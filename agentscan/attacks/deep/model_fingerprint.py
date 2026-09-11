# agentscan/attacks/deep/model_fingerprint.py
#
# DEEP wrapper around neural.fingerprint (gated on --deep).

from __future__ import annotations

import asyncio

from loguru import logger

from agentscan.attacks.base import AttackModule
from agentscan.core.models import Finding, ScanMode, Severity, Target
from agentscan.neural.fingerprint import run_fingerprint


class ModelFingerprintModule(AttackModule):
    """Activation signature of the local reference model over a fixed probe set."""

    attack_id = "ATK-026"
    attack_name = "Model Activation Fingerprint"
    owasp_id = "LLM10"
    supported_modes = [ScanMode.DEEP]

    async def run(self, target: Target) -> list[Finding]:
        del target
        return await asyncio.to_thread(self._probe)

    def _probe(self) -> list[Finding]:
        result = run_fingerprint()
        if result is None:
            logger.info("ATK-026 skipped: DEEP reference model unavailable.")
            return []
        digest = result["digest"]
        expected = result["expected"]
        if expected and not result["matched"]:
            return [
                self.make_finding(
                    severity=Severity.HIGH,
                    description=(
                        "Local reference-model activation fingerprint does not match the "
                        "expected hash. Weights may have been substituted or fine-tuned "
                        "without review (LLM10)."
                    ),
                    evidence=f"digest={digest} expected={expected}",
                    remediation=(
                        "Restore the pinned open-weight checkpoint and compare hashes "
                        "before enabling DEEP corroboration in CI."
                    ),
                    metadata=result,
                )
            ]
        return [
            self.make_finding(
                severity=Severity.INFO,
                description=(
                    "Recorded an activation fingerprint of the local DEEP reference model "
                    "over a fixed probe set for supply-chain comparison."
                ),
                evidence=f"digest={digest} layer={result['layer_index']}",
                remediation=(
                    "Pin this digest via AGENTSCAN_MODEL_FINGERPRINT to detect future "
                    "weight substitution."
                ),
                metadata=result,
            )
        ]
