"""Optional analysis with deterministic and sensitive-local defaults.

The local Ollama server must be operated with cloud features disabled. We check
local model metadata before sending sensitive messages and never download models.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any
from urllib.parse import urlsplit

import httpx

DEFAULT_TEMPERATURE = 0.0
DEFAULT_MAX_TOKENS = 1024
DEFAULT_TIMEOUT = 60
DEFAULT_RETRIES = 0


class AIClientError(RuntimeError):
    """Offline analysis is disabled, unavailable, or returned invalid data."""


def local_model_name(model: str) -> str:
    if not model.startswith("ollama/"):
        raise AIClientError("External model providers are disabled for sensitive scan data.")
    name = model.removeprefix("ollama/")
    if not re.fullmatch(r"[A-Za-z0-9_.:/-]{1,128}", name) or "cloud" in name.lower():
        raise AIClientError("Choose an installed offline Ollama model.")
    return name


def local_model_url() -> str:
    value = os.environ.get("AGENTSCAN_LOCAL_MODEL_URL", "http://127.0.0.1:11434").rstrip("/")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "::1"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise AIClientError("Local analysis requires a literal loopback HTTP address.")
    _ = parsed.port
    return value


class AIClient:
    """Bounded nonstreaming client for an explicitly selected offline local model."""

    def __init__(
        self,
        model: str,
        temperature: float = DEFAULT_TEMPERATURE,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        timeout: int = DEFAULT_TIMEOUT,
        num_retries: int = DEFAULT_RETRIES,
    ) -> None:
        self.model = model
        self.temperature = temperature
        self.max_tokens = max(1, min(max_tokens, 4096))
        self.timeout = max(1, min(timeout, 120))
        self.num_retries = 0

    async def complete(
        self,
        prompt: str,
        *,
        system: str | None = None,
        temperature: float | None = None,
        seed: int | None = None,
    ) -> str:
        messages = [{"role": "system", "content": system}] if system else []
        messages.append({"role": "user", "content": prompt})
        return await self.chat(messages, temperature=temperature, seed=seed)

    async def chat(
        self,
        messages: list[dict[str, str]],
        *,
        temperature: float | None = None,
        seed: int | None = None,
    ) -> str:
        from agentscan.core.context import active_context
        from agentscan.core.egress import PinnedHTTPTransport, canonical_origin, enrolled_request
        from agentscan.core.models import Target
        from agentscan.core.trace import recorder, redact_sensitive_data

        context = active_context.get()
        if context is not None and context.analysis_mode == "external":
            from agentscan.core.external_analysis import (
                external_chat,
                external_model_name,
                provider_key,
            )

            if context.data_classification != "non_sensitive":
                raise AIClientError("External analysis is blocked for sensitive scans.")
            if context.analysis_requests >= 128:
                raise AIClientError("External analysis request budget exhausted.")
            selected = context.external_model
            try:
                external_model_name(self.model)
                selected = self.model
            except AIClientError:
                pass

            provider, _ = external_model_name(selected)
            key = provider_key(provider, allow_dotenv=context.external_keys_from_dotenv)
            if key not in context.redaction_secrets:
                context.redaction_secrets = (*context.redaction_secrets, key)
            sanitized = [{k: redact_sensitive_data(v) for k, v in m.items()} for m in messages]

            if len(json.dumps(sanitized).encode()) > 65536:
                raise AIClientError("External analysis input exceeds the configured size limit.")
            if any(
                set(m) != {"role", "content"} or m["role"] not in {"system", "user", "assistant"}
                for m in sanitized
            ):
                raise AIClientError("Invalid analysis message format.")
            content = await external_chat(
                selected,
                sanitized,
                temperature=self.temperature if temperature is None else temperature,
                max_tokens=self.max_tokens,
                timeout=self.timeout,
                seed=seed,
            )
            if recorder.enabled:
                recorder.record_llm(selected, sanitized, content)
            return content
        if context is not None and context.analysis_mode != "local":
            raise AIClientError(
                "Model-assisted analysis is disabled; deterministic checks remain available."
            )
        selected_model = context.local_model if context is not None else self.model
        if context is not None and self.model.startswith("ollama/"):
            selected_model = self.model
        name = local_model_name(selected_model)
        base = local_model_url()
        target = Target(
            url=base + "/api/chat",
            timeout=self.timeout,
            allowed_hosts=[urlsplit(base).hostname or "127.0.0.1"],
            allowed_origins=[canonical_origin(base)],
            allowed_networks=["127.0.0.1/32", "::1/128"],
        )
        sanitized = [{k: redact_sensitive_data(v) for k, v in m.items()} for m in messages]
        if len(json.dumps(sanitized).encode()) > 65536:
            raise AIClientError("Local analysis input exceeds the configured size limit.")
        options = {
            "temperature": self.temperature if temperature is None else temperature,
            "num_predict": self.max_tokens,
            "num_ctx": 4096,
        }
        if seed is not None:
            options["seed"] = seed
        try:
            async with httpx.AsyncClient(
                transport=PinnedHTTPTransport(target),
                trust_env=False,
                timeout=self.timeout,
                headers={"Accept-Encoding": "identity"},
            ) as client:
                metadata = await enrolled_request(
                    client, target, "POST", base + "/api/show", {"model": name}, count_target=False
                )
                metadata.raise_for_status()
                info = metadata.json()
                if (
                    not isinstance(info, dict)
                    or not info.get("model_info")
                    or info.get("remote_host")
                    or info.get("remote_model")
                ):
                    raise AIClientError(
                        "The selected model is not verified as installed local weights."
                    )
                response = await enrolled_request(
                    client,
                    target,
                    "POST",
                    target.url,
                    {"model": name, "messages": sanitized, "stream": False, "options": options},
                    count_target=False,
                )
                response.raise_for_status()
                data = response.json()
            if data.get("done") is not True:
                raise AIClientError("Local model response was incomplete.")
            content = self._extract_content(data)
        except AIClientError:
            raise
        except Exception as exc:
            raise AIClientError(f"Offline model analysis failed: {type(exc).__name__}") from None
        if recorder.enabled:
            recorder.record_llm(selected_model, sanitized, content)
        return content

    def validate_environment(self) -> tuple[bool, list[str]]:
        from agentscan.core.context import active_context

        context = active_context.get()
        if context is not None and context.analysis_mode == "external":
            from agentscan.core.external_analysis import (
                external_model_name,
                provider_key,
            )

            try:
                if context.data_classification != "non_sensitive":
                    raise AIClientError("Sensitive external analysis blocked.")
                provider, _ = external_model_name(context.external_model)
                provider_key(provider, allow_dotenv=context.external_keys_from_dotenv)
            except AIClientError:
                return False, [
                    "explicit non-sensitive scan, provider/model and locally configured key"
                ]
            return True, []
        try:
            local_model_name(self.model)
            local_model_url()
        except (AIClientError, ValueError):
            return False, ["installed offline Ollama model; external providers disabled"]
        return True, []

    @staticmethod
    def _extract_content(response: Any) -> str:
        try:
            content = response["message"]["content"]
        except (TypeError, KeyError) as exc:
            raise AIClientError("Malformed local model response.") from exc
        if not isinstance(content, str):
            raise AIClientError("Malformed local model response.")
        return content
