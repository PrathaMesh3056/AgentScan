"""Shared bounded chat transport and provenance for known-reference assessments."""

from __future__ import annotations

import copy
import json
from abc import abstractmethod
from typing import Any
from urllib.parse import unquote, urlsplit

from agentscan.attacks.scan.prompt_injection import PromptInjectionModule
from agentscan.core.client import AgentScanClient, _validate_response, consume_target_request
from agentscan.core.connectors.base import set_by_path
from agentscan.core.connectors.http import HttpJsonConnector, RequestTemplateConnector
from agentscan.core.context import ScanContext, active_context, target_redaction_secrets
from agentscan.core.evaluator import LLMJudge
from agentscan.core.models import Finding, Target
from agentscan.core.outcomes import AssessmentInconclusiveError, ModuleUnavailableError
from agentscan.core.provenance import user_message_input
from agentscan.core.trace import recorder
from agentscan.core.trajectory import trajectory_recorder

_HTTP_HEADER_PROVENANCE = "_known_reference_actual_http_headers"


class KnownReferenceChatModule(PromptInjectionModule):
    """Require private evidence and preserve uncertainty at chat boundaries."""

    is_abstract = True
    deterministic_evidence_method = "known_private_reference"

    async def run(self, target: Target) -> list[Finding]:
        if urlsplit(target.url).scheme.startswith("mcp"):
            raise ModuleUnavailableError(
                f"{self.attack_id} requires a chat endpoint; native MCP tool dispatch is unassessed."
            )
        context = active_context.get()
        secrets = target_redaction_secrets(target)
        if context is not None:
            # Direct SDK callers can retain a context from another target. Keep
            # both sets so later transcript export also protects earlier turns.
            context.redaction_secrets = tuple(dict.fromkeys((*context.redaction_secrets, *secrets)))
            return await super().run(target)
        token = active_context.set(
            ScanContext(
                request_budget=target.request_budget,
                redaction_secrets=secrets,
                # Preserve direct callers' recorder settings and access to the
                # redacted exchanges after this temporary context is released.
                recorder=recorder._get(),
                trajectory=trajectory_recorder._get(),
            )
        )
        try:
            return await super().run(target)
        finally:
            active_context.reset(token)

    def _provenance_input(self, variant: dict[str, Any], payload_text: str) -> str:
        if variant.get("channel", "user") != "user":
            raise AssessmentInconclusiveError(
                f"{self.attack_id} supports user-message probes only; indirect ingestion is unassessed."
            )
        supplied = user_message_input(self._current_target, payload_text)
        supplied += "\n" + str(variant.get(_HTTP_HEADER_PROVENANCE, ""))
        target = self._current_target
        if target is not None:
            # Reflected headers/context are supplied data, not private extraction.
            headers: list[Any] = [target.extra_headers, target.auth_header]
            if target.request_template is not None and target.browser is None:
                headers.append(target.request_template.headers)
            endpoint = (
                target.browser.url
                if target.browser is not None
                else target.request_template.url
                if target.request_template is not None
                else target.url
            )
            for _depth in range(3):
                headers.append(endpoint)
                endpoint = unquote(endpoint)
            supplied += "\n" + json.dumps(headers, ensure_ascii=False)
        if len(supplied) > 100_000:
            raise AssessmentInconclusiveError(
                f"{self.attack_id} request exceeds the provenance assessment bound."
            )
        return supplied

    async def _deliver_variant(
        self,
        client: AgentScanClient,
        variant: dict[str, Any],
        payload_text: str | None = None,
    ) -> dict[str, Any]:
        target = self._current_target
        if target is not None and (
            target.browser is not None
            or (target.request_template is None and urlsplit(target.url).scheme in {"ws", "wss"})
        ):
            # HTTP already counts each actual redirect/retry request. Browser
            # and WebSocket connectors need one logical count before delivery.
            consume_target_request()
        response = await super()._deliver_variant(client, variant, payload_text)
        metadata = [response]
        captured_raw = response.get("raw")
        if isinstance(captured_raw, dict):
            metadata.append(captured_raw)
        for container in metadata[:]:
            choices = container.get("choices")
            if isinstance(choices, list):
                metadata.extend(choice for choice in choices if isinstance(choice, dict))
        for container in metadata:
            status = container.get("status_code", 200)
            if container.get("error") or (type(status) is int and (status == 0 or status >= 400)):
                # Captured response mapping can wrap an operational error in
                # raw while lifting its body into an apparently successful reply.
                _validate_response(container)
        for item in metadata:
            if "status_code" in item and type(item["status_code"]) is not int:
                raise AssessmentInconclusiveError(
                    f"{self.attack_id} received unsupported response status metadata."
                )
            if (
                any(key in item and item[key] is not False for key in ("truncated", "incomplete"))
                or any(
                    key in item and item[key] is not True
                    for key in ("complete", "done", "completion_verified")
                )
                or ("finish_reason" in item and item["finish_reason"] != "stop")
            ):
                raise AssessmentInconclusiveError(
                    f"{self.attack_id} received an explicitly incomplete response."
                )
        if (
            target is not None
            and target.browser is None
            and target.request_template is None
            and urlsplit(target.url).scheme in {"ws", "wss"}
        ):
            # The connector reads one frame, not a complete stream. A readable
            # first frame cannot establish a negative without an explicit end
            # marker from the configured target protocol. Choice-level metadata
            # does not establish completion of the whole response.
            envelopes = [response]
            if isinstance(captured_raw, dict):
                envelopes.append(captured_raw)
            if not any(
                any(item.get(key) is True for key in ("complete", "done", "completion_verified"))
                or item.get("finish_reason") == "stop"
                for item in envelopes
            ):
                raise AssessmentInconclusiveError(
                    f"{self.attack_id} requires explicit WebSocket response completion metadata."
                )
        if any(
            isinstance(container.get("raw"), str)
            and any(line.strip().startswith("data:") for line in container["raw"].splitlines())
            for container in metadata
        ):
            # The connector currently discards streaming completion provenance.
            # A marker in untrusted stream text cannot restore that guarantee.
            raise AssessmentInconclusiveError(
                f"{self.attack_id} cannot establish completion of a streamed response."
            )
        return response

    @abstractmethod
    async def _test_variant(
        self,
        client: AgentScanClient,
        variant: dict[str, Any],
        judge: LLMJudge | None = None,
    ) -> Finding | None:
        # Per-call copied metadata avoids shared state between concurrent probes.
        # Discard any YAML-supplied value before collecting actual client headers.
        assessed_variant = {
            key: value for key, value in variant.items() if key != _HTTP_HEADER_PROVENANCE
        }
        if isinstance(client, AgentScanClient) and isinstance(
            client._connector, HttpJsonConnector | RequestTemplateConnector
        ):
            self._reference_match(
                "", self._provenance_input(assessed_variant, self._build_payload(assessed_variant))
            )
            await client._ensure_connected()
            connector = client._connector
            if connector._client is not None:
                endpoint = (
                    connector.template.url
                    if isinstance(connector, RequestTemplateConnector)
                    else connector.target.url
                )
                method = (
                    connector.template.method
                    if isinstance(connector, RequestTemplateConnector)
                    else "POST"
                )
                # Building a request performs no I/O. It includes HTTPX defaults,
                # merged overrides, Host and applicable client cookies.
                payload = self._build_payload(assessed_variant)
                if isinstance(connector, RequestTemplateConnector):
                    body = copy.deepcopy(connector.template.json_body)
                    set_by_path(body, connector.template.message_path, payload)
                else:
                    body = {"message": payload}
                # enrolled_request supplies json=body even for captured GET/HEAD.
                request = connector._client.build_request(method, endpoint, json=body)
                serialized = json.dumps(request.headers.multi_items(), ensure_ascii=False)
                if len(serialized) > 100_000:
                    raise AssessmentInconclusiveError(
                        f"{self.attack_id} request exceeds the provenance assessment bound."
                    )
                assessed_variant[_HTTP_HEADER_PROVENANCE] = serialized
        return await super()._test_variant(client, assessed_variant, judge=None)
