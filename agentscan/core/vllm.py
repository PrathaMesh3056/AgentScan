# agentscan/core/vllm.py
#
# Client connector for high-throughput local inference engines (vLLM / Ollama / TGI).
# Implements continuous batching, streaming evaluation, and health verification.

from __future__ import annotations

import asyncio
import os

import httpx
from loguru import logger

from agentscan.core.circuit_breaker import AsyncCircuitBreaker


class VLLMClient:
    """
    High-performance client for vLLM or OpenAI-compatible model servers.
    Used in DEEP mode for high-throughput red-teaming and automated grading.
    """

    def __init__(
        self,
        base_url: str | None = None,
        model_name: str | None = None,
        api_key: str | None = None,
        timeout: float = 60.0,
    ):
        url = base_url or os.environ.get("AGENTSCAN_VLLM_URL") or "http://localhost:8000/v1"
        self.base_url = url.rstrip("/")
        self.model_name = model_name or os.environ.get(
            "AGENTSCAN_VLLM_MODEL", "meta-llama/Llama-3-8B-Instruct"
        )
        self.api_key = api_key or os.environ.get("AGENTSCAN_VLLM_API_KEY", "EMPTY")
        self.timeout = timeout
        self.circuit_breaker = AsyncCircuitBreaker(
            name=f"vllm-{self.base_url}",
            failure_threshold=3,
            recovery_timeout=20.0,
        )

    async def is_healthy(self) -> bool:
        """Verify the inference server is up and responsive."""
        health_url = self.base_url.replace("/v1", "") + "/health"
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(health_url)
                return resp.status_code == 200
        except Exception as exc:
            logger.debug(f"vLLM health check failed: {exc}")
            return False

    async def generate(
        self,
        prompt: str,
        system_prompt: str | None = None,
        temperature: float = 0.7,
        max_tokens: int = 512,
    ) -> str:
        """Send a single prompt to vLLM via circuit breaker."""
        messages: list[dict[str, str]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model_name,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        async def _request() -> str:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(
                    f"{self.base_url}/chat/completions",
                    json=payload,
                    headers=headers,
                )
                resp.raise_for_status()
                data = resp.json()
                return str(data["choices"][0]["message"]["content"])

        return str(await self.circuit_breaker.call(_request))

    async def batch_generate(
        self,
        prompts: list[str],
        system_prompt: str | None = None,
        concurrency: int = 20,
    ) -> list[str]:
        """Evaluate a batch of attack prompts concurrently against the model server."""
        semaphore = asyncio.Semaphore(concurrency)

        async def _worker(p: str) -> str:
            async with semaphore:
                try:
                    return await self.generate(p, system_prompt=system_prompt)
                except Exception as exc:
                    logger.error(f"Batch generation item failed: {exc}")
                    return ""

        return await asyncio.gather(*[_worker(p) for p in prompts])
