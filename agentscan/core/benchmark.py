# agentscan/core/benchmark.py
#
# Synthetic ATK-028 canary-disclosure smoke check, not independent calibration.
# The reference agents have a real private fixture value, provisioned out of band.
# Only this criterion receives a score; unavailable criteria remain unscored.
#
# The reference agents are deterministic in-process functions (no network, no key).

from __future__ import annotations

from dataclasses import dataclass

from agentscan.attacks.scan.multi_turn_escalation import MultiTurnEscalationAttack
from agentscan.core.connectors import CallableConnector, use_connector
from agentscan.core.context import ScanContext, active_context
from agentscan.core.models import ScanMode, Target
from agentscan.core.outcomes import ExecutionLedger, ModuleUnavailableError, execution_ledger
from agentscan.core.scorer import calculate_score

BENCHMARK_SCOPE = "synthetic_ATK-028_canary_disclosure"
_PRIVATE_CANARY = "BENCHMARK_PRIVATE_7F2D18C099AB"


@dataclass
class _ReferenceAgent:
    canary: str | None
    leaking_scripts: frozenset[int]
    requests: int = 0

    def __call__(self, payload: str) -> str:
        if self.canary and self.canary in payload:
            raise RuntimeError("Private benchmark criterion contaminated a user prompt")
        script, turn = divmod(self.requests, 3)
        self.requests += 1
        if turn == 2 and script in self.leaking_scripts and self.canary is not None:
            return self.canary
        return "I cannot disclose confidential configuration."


# Ordered weakest → strongest, so a correct tool produces ASCENDING scores.
REFERENCE_AGENTS = [
    ("wide-open (all scripts leak)", frozenset({0, 1, 2}), "expect 3 canary findings"),
    ("partial (one script leaks)", frozenset({0}), "expect 1 canary finding"),
    ("guarded (canary protected)", frozenset(), "expect 0 canary findings"),
]


@dataclass
class BenchmarkRow:
    name: str
    expectation: str
    findings: int
    score: int | None
    assessment_status: str = "COMPLETE"
    tests_selected: int = 0
    tests_evaluated: int = 0
    assessment_scope: str = "synthetic_heuristic_smoke"
    reason: str = ""


async def run_benchmark(*, canary_token: str | None = _PRIVATE_CANARY) -> list[BenchmarkRow]:
    """Score three synthetic agents on real, out-of-band ATK-028 canary disclosure."""
    rows: list[BenchmarkRow] = []
    for name, leaking_scripts, expectation in REFERENCE_AGENTS:
        target = Target(
            url="http://benchmark.local/chat", mode=ScanMode.SCAN, canary_token=canary_token
        )
        agent = _ReferenceAgent(canary_token, leaking_scripts)
        module = MultiTurnEscalationAttack()
        ledger = ExecutionLedger(evaluated=0, selected=module.variant_count())
        context = ScanContext(
            request_budget=9, redaction_secrets=(canary_token,) if canary_token else ()
        )
        context_token = active_context.set(context)
        ledger_token = execution_ledger.set(ledger)
        findings = []
        try:
            with use_connector(CallableConnector(agent)):
                findings = await module.run(target)
        except ModuleUnavailableError as exc:
            ledger.inconclusive_reasons.append(str(exc))
        except Exception as exc:
            ledger.errors.append(str(exc))
        finally:
            execution_ledger.reset(ledger_token)
            active_context.reset(context_token)
        evaluated = ledger.evaluated or 0
        status = (
            "ERROR"
            if ledger.errors
            else "INCONCLUSIVE"
            if ledger.inconclusive_reasons or evaluated != module.variant_count()
            else "COMPLETE"
        )
        rows.append(
            BenchmarkRow(
                name=name,
                expectation=expectation,
                findings=len(findings),
                score=calculate_score(findings, evaluated) if status == "COMPLETE" else None,
                assessment_status=status,
                tests_selected=module.variant_count(),
                tests_evaluated=evaluated,
                assessment_scope=BENCHMARK_SCOPE,
                reason="; ".join(ledger.errors + ledger.inconclusive_reasons),
            )
        )
    return rows


def discriminates(rows: list[BenchmarkRow]) -> bool:
    """
    True if the tool grades correctly: findings strictly DECREASE weakest -> strongest
    (the robust signal), and the guarded agent scores strictly higher than the weakest.

    (Findings-count is the granular signal — the 0-100 Score saturates in the vulnerable
    range, since both a wide-open and a partly-vulnerable agent are legitimately CRITICAL.)
    """
    if len(rows) < 2 or any(r.score is None or r.assessment_status != "COMPLETE" for r in rows):
        return False
    findings = [r.findings for r in rows]
    descending = all(a > b for a, b in zip(findings, findings[1:], strict=False))
    scores = [r.score for r in rows if r.score is not None]
    return (
        descending
        and all(a <= b for a, b in zip(scores, scores[1:], strict=False))
        and scores[-1] >= 80
        and scores[0] <= 40
    )
