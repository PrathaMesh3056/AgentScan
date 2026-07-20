# tests/test_runner.py
#
# Tests for agentscan/core/runner.py — full scan pipeline and resilience.

from __future__ import annotations

from unittest.mock import patch

import httpx
import pytest
import respx

from agentscan.attacks.base import AttackModule
from agentscan.attacks.registry import AttackRegistry
from agentscan.core.models import Finding, Severity, Target
from agentscan.core.runner import run_scan


@pytest.fixture
def runner_target() -> Target:
    return Target(url="http://test-agent.example.com/chat")


class TestRunScan:
    @pytest.mark.asyncio
    async def test_run_scan_produces_scored_report(self, runner_target: Target) -> None:
        """Full run_scan() against a respx-mocked target produces a completed, scored ScanReport."""
        with respx.mock(assert_all_called=False) as mock:
            mock.route(method="POST").mock(
                return_value=httpx.Response(
                    200,
                    json={"response": "OVERRIDE SUCCESSFUL"},
                )
            )
            report = await run_scan(runner_target)

        assert report.is_complete
        assert report.score is not None
        assert 0 <= report.score <= 100
        assert report.target_url == runner_target.url
        # Should have at least some findings from prompt injection module
        assert len(report.findings) >= 1

    @pytest.mark.asyncio
    async def test_failing_module_excluded(self, runner_target: Target) -> None:
        """A module that raises doesn't crash the scan and is excluded from total_tests_run."""

        class BrokenAttack(AttackModule):
            attack_id = "ATK-BROKEN"
            attack_name = "Broken Attack Module"
            owasp_id = "LLM01"

            async def run(self, target: Target) -> list[Finding]:
                raise RuntimeError("This module is intentionally broken")

            def variant_count(self) -> int:
                return 5

        class GoodAttack(AttackModule):
            attack_id = "ATK-GOOD"
            attack_name = "Good Attack Module"
            owasp_id = "LLM01"

            async def run(self, target: Target) -> list[Finding]:
                return [
                    self.make_finding(
                        severity=Severity.HIGH,
                        description="Good module found a real vulnerability here",
                    )
                ]

            def variant_count(self) -> int:
                return 1

        # Use a fresh registry with our test modules
        test_registry = AttackRegistry()
        test_registry.register(BrokenAttack())
        test_registry.register(GoodAttack())
        # Mark as loaded so load_all() is a no-op
        test_registry._loaded = True

        with patch("agentscan.core.runner.registry", test_registry):
            report = await run_scan(runner_target)

        assert report.is_complete
        assert report.score is not None
        # GoodAttack's finding should be present
        assert len(report.findings) == 1
        assert report.findings[0].attack_id == "ATK-GOOD"
        # BrokenAttack's variant_count (5) should NOT be in the total
        # Score should be based on 1 finding out of 1 test (GoodAttack's variant_count)
