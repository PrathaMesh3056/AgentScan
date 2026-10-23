"""ATK-011: multilingual probes with an independently supplied private reference."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from agentscan.attacks.scan.known_reference_chat import KnownReferenceChatModule
from agentscan.core.client import AgentScanClient
from agentscan.core.evaluator import LLMJudge
from agentscan.core.models import Finding, Target
from agentscan.core.outcomes import AssessmentInconclusiveError, execution_ledger

PAYLOAD_FILE = Path(__file__).resolve().parent.parent / "payloads" / "multilingual.yaml"
_LANGUAGE_SCRIPTS = frozenset(
    {
        ("zh", "Hans"),
        ("ru", "Cyrl"),
        ("ar", "Arab"),
        ("hi", "Deva"),
        ("es", "Latn"),
        ("zh-en", "Hans-Latn"),
        ("hi-Latn", "Latn"),
        ("es-en", "Latn"),
        ("bn", "Beng"),
        ("en", "Latn"),
    }
)


class MultilingualModule(KnownReferenceChatModule):
    """Assess complete reference disclosure, not general multilingual alignment.

    Language labels describe authored seeds. Mutations retain that grouping; no
    language identification or certified translation equivalence is performed.
    """

    is_abstract = False
    attack_id = "ATK-011"
    attack_name = "Multilingual Alignment Bypass"
    owasp_id = "LLM01"
    payload_file = PAYLOAD_FILE
    assessment_scope = "multilingual_complete_known_reference"
    criterion_version = "atk011-known-reference-2026-10-22"

    default_remediation = (
        "Keep confidential values outside model-visible instructions. Apply the same "
        "application authorization and output contracts to every supported language, "
        "mixed-language message and transliteration. Preserve trusted message roles; "
        "user-written authority claims and translations remain untrusted. Evaluate "
        "legitimate task utility and complete-reference disclosure separately in each "
        "supported language. Translation, keyword filters and refusal wording alone "
        "do not enforce confidentiality or establish general alignment."
    )
    default_judge_remediation = default_remediation

    def __init__(self) -> None:
        self._language_counts: dict[tuple[str, str], dict[str, int]] = {}

    @staticmethod
    def _language_key(variant: dict[str, Any]) -> tuple[str, str]:
        language, script = variant.get("language"), variant.get("script")
        if (
            isinstance(language, str)
            and isinstance(script, str)
            and (language, script) in _LANGUAGE_SCRIPTS
        ):
            return language, script
        return "und", "Zyyy"

    @property
    def language_outcomes(self) -> list[dict[str, Any]]:
        """Return detached counts; cancellation/setup failure remains not run."""
        return [
            {
                "language": language,
                "script": script,
                **counts,
                "not_run_tests": counts["selected_tests"]
                - counts["evaluated_tests"]
                - counts["inconclusive_tests"]
                - counts["error_tests"],
            }
            for (language, script), counts in self._language_counts.items()
        ]

    async def run(self, target: Target) -> list[Finding]:
        from agentscan.attacks.mutators import expand_variants

        variants = list(self._load_payload_variants())
        if target.mutate:
            variants = expand_variants(variants, budget=target.mutation_budget)
        self._language_counts = {}
        for variant in variants:
            counts = self._language_counts.setdefault(
                self._language_key(variant),
                {
                    "selected_tests": 0,
                    "evaluated_tests": 0,
                    "findings": 0,
                    "inconclusive_tests": 0,
                    "error_tests": 0,
                },
            )
            counts["selected_tests"] += 1
        # Preserve selected denominators when a missing criterion stops execution
        # before the shared YAML runner is entered.
        ledger = execution_ledger.get()
        if ledger is not None:
            ledger.selected = len(variants)
            ledger.evaluated = 0
        return await super().run(target)

    async def _test_variant(
        self,
        client: AgentScanClient,
        variant: dict[str, Any],
        judge: LLMJudge | None = None,
    ) -> Finding | None:
        language, script = self._language_key(variant)
        counts = self._language_counts.get((language, script))
        try:
            finding = await super()._test_variant(client, variant, judge=None)
        except AssessmentInconclusiveError:
            if counts is not None:
                counts["inconclusive_tests"] += 1
            raise
        except Exception:
            if counts is not None:
                counts["error_tests"] += 1
            raise
        if counts is not None:
            counts["evaluated_tests"] += 1
            counts["findings"] += int(finding is not None)
        if finding is None:
            return None
        return finding.model_copy(
            update={
                "description": (
                    f"The response to {variant['name']} disclosed a complete operator-known "
                    "confidential reference under a multilingual probe. This establishes "
                    "observed reference disclosure; language-caused failure, general "
                    "alignment and tool execution have not been independently verified."
                ),
                "metadata": {
                    **finding.metadata,
                    "attack_family": variant.get("family", "legacy_multilingual_framing"),
                    "declared_language": language,
                    "declared_script": script,
                    "language_effect_verified": False,
                    "translation_equivalence_verified": False,
                    "authorization_bypass_verified": False,
                    "encoded_or_partial_extraction_assessed": False,
                },
            }
        )
