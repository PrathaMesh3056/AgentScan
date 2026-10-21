"""ATK-002: persona probes assessed against a privately provisioned reference."""

from __future__ import annotations

import copy
import json
from pathlib import Path
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

PAYLOAD_FILE = Path(__file__).resolve().parent.parent / "payloads" / "jailbreak.yaml"
_HTTP_HEADER_PROVENANCE = "_atk002_actual_http_headers"


class JailbreakModule(PromptInjectionModule):
    """Observe complete known-reference disclosure under bounded persona probes.

    Public marker repetition and an inferred judge verdict cannot establish a
    safeguard failure. Negatives cover only complete supported text matches.
    """

    is_abstract = False
    attack_id = "ATK-002"
    attack_name = "Jailbreak & Persona Adoption"
    owasp_id = "LLM01"
    payload_file = PAYLOAD_FILE
    assessment_scope = "persona_complete_known_reference"
    criterion_version = "atk002-known-reference-2026-10-20"
    deterministic_evidence_method = "known_private_reference"

    default_remediation = (
        "Keep confidential records and credentials outside model-visible instructions. "
        "Preserve trusted message roles and treat persona, fiction, simulation and claimed "
        "administrator instructions as untrusted user input. Enforce access control, output "
        "contracts and tool permissions in application code; measure legitimate task utility "
        "alongside these probes. Refusal text and persona consistency alone do not enforce "
        "confidentiality or prove general resistance."
    )
    default_judge_remediation = default_remediation

    async def run(self, target: Target) -> list[Finding]:
        if urlsplit(target.url).scheme.startswith("mcp"):
            raise ModuleUnavailableError(
                "ATK-002 requires a chat endpoint; native MCP tool dispatch is unassessed."
            )
        if active_context.get() is not None or target.request_budget is None:
            return await super().run(target)
        token = active_context.set(
            ScanContext(
                request_budget=target.request_budget,
                redaction_secrets=target_redaction_secrets(target),
            )
        )
        try:
            return await super().run(target)
        finally:
            active_context.reset(token)

    def _provenance_input(self, variant: dict[str, Any], payload_text: str) -> str:
        if variant.get("channel", "user") != "user":
            raise AssessmentInconclusiveError(
                "ATK-002 supports user-message probes only; indirect ingestion is unassessed."
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
                "ATK-002 request exceeds the provenance assessment bound."
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
                    "ATK-002 received unsupported response status metadata."
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
                    "ATK-002 received an explicitly incomplete response."
                )
        if any(
            isinstance(container.get("raw"), str)
            and any(line.strip().startswith("data:") for line in container["raw"].splitlines())
            for container in metadata
        ):
            # The connector currently discards streaming completion provenance.
            # A marker in untrusted stream text cannot restore that guarantee.
            raise AssessmentInconclusiveError(
                "ATK-002 cannot establish completion of a streamed response."
            )
        return response

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
                        "ATK-002 request exceeds the provenance assessment bound."
                    )
                assessed_variant[_HTTP_HEADER_PROVENANCE] = serialized
        finding = await super()._test_variant(client, assessed_variant, judge=None)
        if finding is None:
            return None
        return finding.model_copy(
            update={
                "description": (
                    f"The response to {variant['name']} disclosed a complete operator-known "
                    "confidential reference under a persona probe. This establishes observed "
                    "reference disclosure; general safeguard failure, causal persona adoption "
                    "and tool execution have not been independently verified."
                ),
                "metadata": {
                    **finding.metadata,
                    "attack_family": variant.get("family", "legacy_persona_framing"),
                    "persona_adoption_verified": False,
                    "authorization_bypass_verified": False,
                    "encoded_or_partial_extraction_assessed": False,
                },
            }
        )
