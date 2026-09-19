# agentscan/core/ai_client.py
#
# The single AI model client for AgentScan's AI-driven testing.
# Every module that needs an *attacker* LLM (to generate adaptive payloads) or a
# *judge* LLM (LLM-as-a-Judge evaluation) talks to a model through this wrapper —
# never through a provider SDK directly.
#
# Why litellm:
#   AgentScan must drive OpenAI, Anthropic, Gemini, Ollama, etc. without writing
#   a bespoke client per provider. litellm gives one OpenAI-shaped interface over
#   all of them. Callers pass a model string ("gpt-4o", "claude-3-5-sonnet-latest",
#   "ollama/llama3") and this class handles the rest.
#
# API keys are read by litellm from the environment (OPENAI_API_KEY,
# ANTHROPIC_API_KEY, ...). AgentScan never stores or logs them.

from __future__ import annotations

import contextlib
from typing import Any

from loguru import logger

# ── Defaults ──────────────────────────────────────────────────────────────────

DEFAULT_TEMPERATURE = 0.0  # deterministic by default — attacker/judge want reproducibility
DEFAULT_MAX_TOKENS = 1024
DEFAULT_TIMEOUT = 60
DEFAULT_RETRIES = 2

_litellm_configured = False


class AIClientError(RuntimeError):
    """Raised when an LLM request fails or returns an unusable response."""


def _get_litellm() -> Any:
    """
    Lazy-import and configure litellm once.

    Kept lazy so importing agentscan (or running `scan` without AI modules) does
    not pull in litellm's heavy import graph.
    """
    global _litellm_configured
    try:
        import litellm
    except ImportError as e:
        raise AIClientError(
            "AI-driven testing requires the 'llm' extra: pip install 'agentscan[llm]'"
        ) from e

    if not _litellm_configured:
        # Drop provider-unsupported params instead of erroring (e.g. a model that
        # rejects `temperature`) so one call shape works across every provider.
        litellm.drop_params = True
        litellm.telemetry = False
        # Silence litellm's "Provider List / Give Feedback" console spam.
        litellm.suppress_debug_info = True
        with contextlib.suppress(Exception):
            import logging

            logging.getLogger("LiteLLM").setLevel(logging.ERROR)
        _litellm_configured = True
    return litellm


class AIClient:
    """
    Unified async wrapper around litellm for driving attacker/judge LLMs.

    Model-agnostic — the same instance shape works for any provider:
        client = AIClient(model="gpt-4o")
        reply = await client.complete("Write a jailbreak for X", system="You are a red-teamer.")

    The client is stateless between calls; reuse one instance freely.
    """

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
        self.max_tokens = max_tokens
        self.timeout = timeout
        self.num_retries = num_retries

    async def complete(
        self,
        prompt: str,
        *,
        system: str | None = None,
        temperature: float | None = None,
        seed: int | None = None,
    ) -> str:
        """
        Single-shot completion: optional system prompt + one user message.

        Returns the assistant's text content (never None — empty string if blank).
        """
        messages: list[dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        return await self.chat(messages, temperature=temperature, seed=seed)

    async def chat(
        self,
        messages: list[dict[str, str]],
        *,
        temperature: float | None = None,
        seed: int | None = None,
    ) -> str:
        """
        Multi-turn chat completion.

        Args:
            messages: OpenAI-shaped history — [{"role": "system"|"user"|"assistant",
                      "content": "..."}].

        Returns:
            The assistant's text content.

        Raises:
            AIClientError: on transport failure, auth failure, or a malformed
            response. Callers decide whether to skip the module or abort.
        """
        litellm = _get_litellm()
        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature if temperature is None else temperature,
            "max_tokens": self.max_tokens,
            "timeout": self.timeout,
            "num_retries": self.num_retries,
        }
        if seed is not None:
            kwargs["seed"] = seed
        try:
            response = await litellm.acompletion(**kwargs)
        except Exception as e:  # noqa: BLE001 - normalise every provider error to one type
            logger.error(f"LLM request to {self.model!r} failed: {e}")
            raise AIClientError(f"LLM request to {self.model!r} failed: {e}") from e

        content = self._extract_content(response)
        # Record the full exchange (input prompts + raw output) for --llm-log / --verbose.
        from agentscan.core.trace import recorder

        if recorder.enabled:
            recorder.record_llm(self.model, messages, content)
        return content

    def validate_environment(self) -> tuple[bool, list[str]]:
        """
        Check whether the required API key(s) for this model are present.

        Returns (keys_present, missing_keys) so the CLI can skip AI-driven
        modules with a clear message instead of failing mid-scan.
        """
        litellm = _get_litellm()
        info = litellm.validate_environment(self.model)
        return bool(info.get("keys_in_environment", False)), list(info.get("missing_keys", []))

    @staticmethod
    def _extract_content(response: Any) -> str:
        """Pull the assistant text out of a litellm ModelResponse."""
        try:
            content = response.choices[0].message.content
        except (AttributeError, IndexError, KeyError) as e:
            raise AIClientError(f"Malformed LLM response: {response!r}") from e
        return content or ""
