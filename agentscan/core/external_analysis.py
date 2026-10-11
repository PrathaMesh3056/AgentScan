"""Explicit external analysis for client-designated non-sensitive scans only."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

from agentscan.core.ai_client import AIClientError

PROVIDERS = {
    "openai": ("https://api.openai.com/v1/chat/completions", "OPENAI_API_KEY"),
    "anthropic": ("https://api.anthropic.com/v1/messages", "ANTHROPIC_API_KEY"),
    "gemini": (
        "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
        "GEMINI_API_KEY",
    ),
}


def external_model_name(model: str) -> tuple[str, str]:
    provider, separator, name = model.partition("/")
    if (
        provider not in PROVIDERS
        or not separator
        or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name)
    ):
        raise AIClientError("Choose provider/model using openai, anthropic or gemini.")
    return provider, name


def provider_key(provider: str, *, allow_dotenv: bool = True) -> str:
    variable = PROVIDERS[provider][1]
    value = os.environ.get(variable)
    if not value and provider == "gemini":
        value = os.environ.get("GOOGLE_API_KEY")
    if not value and allow_dotenv:
        from dotenv import dotenv_values

        values = dotenv_values(Path.cwd() / ".env", interpolate=False)
        value = values.get(variable) or (
            values.get("GOOGLE_API_KEY") if provider == "gemini" else None
        )
    if not value or not value.strip() or len(value) > 4096 or any(ord(c) < 32 for c in value):
        raise AIClientError(f"Configure {variable} locally before choosing external analysis.")
    return value.strip()


def validate_analysis_selection(mode: str, classification: str, model: str) -> None:
    if mode == "external":
        if classification != "non_sensitive":
            raise AIClientError(
                "External analysis requires explicit non-sensitive scan designation."
            )
        provider, _ = external_model_name(model)
        provider_key(provider)
    elif mode == "local":
        from agentscan.core.ai_client import local_model_name, local_model_url

        local_model_name(model)
        local_model_url()
    elif mode != "deterministic":
        raise AIClientError("Choose deterministic, local or external analysis.")


async def external_chat(
    model: str,
    messages: list[dict[str, str]],
    *,
    temperature: float,
    max_tokens: int,
    timeout: int,
    seed: int | None,
) -> str:
    from agentscan.core.context import active_context
    from agentscan.core.egress import PinnedHTTPTransport, canonical_origin, enrolled_request
    from agentscan.core.models import Target

    context = active_context.get()
    if (
        context is None
        or context.analysis_mode != "external"
        or context.data_classification != "non_sensitive"
    ):
        raise AIClientError("External analysis is blocked for sensitive or undesignated scans.")
    if context.analysis_requests >= 128:
        raise AIClientError("External analysis request budget exhausted.")
    provider, name = external_model_name(model)
    key = provider_key(provider, allow_dotenv=context.external_keys_from_dotenv)
    context.analysis_requests += 1
    endpoint = PROVIDERS[provider][0].format(model=name)
    headers = {"Accept-Encoding": "identity"}
    systems = "\n".join(m["content"] for m in messages if m["role"] == "system")
    conversation = [m for m in messages if m["role"] != "system"]
    body: dict[str, Any]
    if provider == "gemini":
        headers["x-goog-api-key"] = key
        body = {
            "contents": [
                {
                    "role": "model" if m["role"] == "assistant" else "user",
                    "parts": [{"text": m["content"]}],
                }
                for m in conversation
            ],
            "generationConfig": {"temperature": temperature, "maxOutputTokens": max_tokens},
        }
        if systems:
            body["systemInstruction"] = {"parts": [{"text": systems}]}
    elif provider == "anthropic":
        headers.update({"x-api-key": key, "anthropic-version": "2023-06-01"})
        body = {
            "model": name,
            "messages": conversation,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if systems:
            body["system"] = systems
    else:
        headers["Authorization"] = f"Bearer {key}"
        body = {
            "model": name,
            "messages": messages,
            "max_completion_tokens": max_tokens,
            "store": False,
        }
        # Reasoning models may reject temperature/seed. Omit optional controls
        # rather than silently retrying a potentially billable request.
    target = Target(
        url=endpoint,
        timeout=timeout,
        allowed_hosts=[urlsplit(endpoint).hostname or ""],
        allowed_origins=[canonical_origin(endpoint)],
        allowed_networks=[],
        extra_headers=headers,
    )
    try:
        async with httpx.AsyncClient(
            transport=PinnedHTTPTransport(target), trust_env=False, timeout=timeout, headers=headers
        ) as client:
            response = await enrolled_request(
                client, target, "POST", endpoint, body, count_target=False
            )
            response.raise_for_status()
            data = response.json()
        if provider == "gemini":
            candidate = data["candidates"][0]
            if candidate.get("finishReason") != "STOP":
                raise AIClientError("External response was incomplete or blocked.")
            content = "\n".join(
                p["text"]
                for p in candidate["content"]["parts"]
                if isinstance(p.get("text"), str) and not p.get("thought")
            )
        elif provider == "anthropic":
            if data.get("stop_reason") != "end_turn":
                raise AIClientError("External response was incomplete or blocked.")
            content = "\n".join(p["text"] for p in data["content"] if p.get("type") == "text")
        else:
            choice = data["choices"][0]
            if choice.get("finish_reason") != "stop":
                raise AIClientError("External response was incomplete or blocked.")
            content = choice["message"]["content"]
        if not isinstance(content, str) or not content.strip():
            raise AIClientError("External model returned no usable text.")
        return content
    except AIClientError:
        raise
    except Exception as exc:
        raise AIClientError(f"External analysis unavailable: {type(exc).__name__}") from None
