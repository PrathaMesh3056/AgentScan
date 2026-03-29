# tests/test_client.py
from __future__ import annotations

import httpx
import pytest
import respx

from agentscan.core.client import AgentScanClient
from agentscan.core.models import Target


class TestAgentScanClient:
    @pytest.mark.asyncio
    async def test_sends_message_to_correct_url(self, target: Target) -> None:
        with respx.mock() as mock:
            mock.post(target.url).mock(return_value=httpx.Response(200, json={"response": "hello"}))
            async with AgentScanClient(target) as client:
                result = await client.send_message("test payload")
            assert result == {"response": "hello"}

    @pytest.mark.asyncio
    async def test_injects_auth_header(self, authed_target: Target) -> None:
        with respx.mock() as mock:
            route = mock.post(authed_target.url).mock(
                return_value=httpx.Response(200, json={"response": "ok"})
            )
            async with AgentScanClient(authed_target) as client:
                await client.send_message("test")
            # Verify auth header was sent
            request = route.calls[0].request
            assert "Authorization" in request.headers
            assert "sk-test-abc123" in request.headers["Authorization"]

    @pytest.mark.asyncio
    async def test_returns_dict_on_non_json_response(self, target: Target) -> None:
        with respx.mock() as mock:
            mock.post(target.url).mock(return_value=httpx.Response(200, text="plain text response"))
            async with AgentScanClient(target) as client:
                result = await client.send_message("test")
        assert "raw" in result

    @pytest.mark.asyncio
    async def test_handles_connection_error(self, target: Target) -> None:
        with respx.mock():
            respx.post(target.url).mock(side_effect=httpx.ConnectError("Connection refused"))
            async with AgentScanClient(target) as client:
                result = await client.send_message("test")
            assert "error" in result
            assert result["status_code"] == 0

    @pytest.mark.asyncio
    async def test_raises_without_context_manager(self, target: Target) -> None:
        client = AgentScanClient(target)
        with pytest.raises(RuntimeError, match="not initialised"):
            await client.send_message("test")
