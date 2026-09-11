# agentscan/attacks/deep/attention_probe.py
#
# DEEP wrapper around neural.attention_analyzer (gated on --deep).

from __future__ import annotations

import asyncio

from loguru import logger

from agentscan.attacks.base import AttackModule
from agentscan.core.models import Finding, ScanMode, Severity, Target
from agentscan.neural.attention_analyzer import run_attention_analysis


class AttentionAnalyzerModule(AttackModule):
    """Flags attention diversion (entropy collapse / sink concentration) vs benign prompts."""

    attack_id = "ATK-025"
    attack_name = "Attention Diversion Analyzer"
    owasp_id = "LLM10"
    supported_modes = [ScanMode.DEEP]

    def variant_count(self) -> int:
        return 3

    async def run(self, target: Target) -> list[Finding]:
        del target
        return await asyncio.to_thread(self._probe)

    def _probe(self) -> list[Finding]:
        rows = run_attention_analysis()
        if rows is None:
            logger.info("ATK-025 skipped: DEEP reference model unavailable.")
            return []
        findings: list[Finding] = []
        for row in rows:
            if not row.get("diverted"):
                continue
            findings.append(
                self.make_finding(
                    severity=Severity.MEDIUM,
                    description=(
                        "Probe prompt diverted middle-layer attention away from the benign "
                        "baseline (entropy collapse and/or attention-sink concentration), "
                        "indicating instruction-overriding focus (LLM10)."
                    ),
                    evidence=(
                        f"entropy {row['probe_entropy']} vs benign {row['benign_entropy']} "
                        f"(drop {row['entropy_drop']}); sink {row['probe_sink']} vs "
                        f"benign {row['benign_sink']} (rise {row['sink_rise']})"
                    ),
                    remediation=(
                        "Harden alignment and inspect attention sinks on adversarial prefixes; "
                        "do not treat textual refusal as proof the model ignored the probe."
                    ),
                    payload_used=str(row.get("prompt", "")),
                    metadata=row,
                )
            )
        return findings
