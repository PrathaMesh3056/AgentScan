# tests/test_base.py
#
# Tests for agentscan/attacks/base.py — ABC enforcement,
# make_finding() with/without metadata, variant_count() default.

from __future__ import annotations

import pytest

from agentscan.attacks.base import AttackModule
from agentscan.core.models import Finding, Severity, Target

# ── Concrete subclass for testing ─────────────────────────────────────────────


class ConcreteAttack(AttackModule):
    """Minimal valid subclass for testing base class behaviour."""

    attack_id = "ATK-TEST"
    attack_name = "Test Attack Module"
    owasp_id = "LLM01"

    async def run(self, target: Target) -> list[Finding]:
        return []


# ── Tests ─────────────────────────────────────────────────────────────────────


class TestAttackModuleABC:
    def test_abc_enforcement_missing_run(self) -> None:
        """Subclass without run() cannot be instantiated — ABC raises TypeError."""

        class IncompleteAttack(AttackModule):
            attack_id = "ATK-INCOMPLETE"
            attack_name = "Incomplete Attack"
            owasp_id = "LLM01"
            # deliberately missing run()

        with pytest.raises(TypeError):
            IncompleteAttack()  # type: ignore[abstract]


class TestMakeFinding:
    def test_make_finding_without_metadata(self) -> None:
        """make_finding() without metadata produces Finding with empty metadata dict."""
        module = ConcreteAttack()
        finding = module.make_finding(
            severity=Severity.HIGH,
            description="A valid test description for this finding",
        )
        assert finding.attack_id == "ATK-TEST"
        assert finding.severity == Severity.HIGH
        assert finding.metadata == {}

    def test_make_finding_with_metadata(self) -> None:
        """make_finding() with metadata passes it through to the Finding."""
        module = ConcreteAttack()
        meta: dict[str, object] = {"yaml_variant_id": "PI-003", "detection_method": "contains"}
        finding = module.make_finding(
            severity=Severity.MEDIUM,
            description="A valid test description for this finding",
            metadata=meta,
        )
        assert finding.metadata == meta
        assert finding.metadata["yaml_variant_id"] == "PI-003"


class TestVariantCount:
    def test_variant_count_default(self) -> None:
        """Default variant_count() returns 1."""
        module = ConcreteAttack()
        assert module.variant_count() == 1
