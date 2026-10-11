"""Run production scan orchestration against fixed, labelled local HTTP cases."""

from __future__ import annotations

import argparse
import ast
import asyncio
import hashlib
import json
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agentscan.attacks.exploit.credential_harvest import CredentialHarvestModule
from agentscan.attacks.exploit.data_exfiltration import ExfiltrationModule
from agentscan.attacks.registry import AttackRegistry
from agentscan.attacks.scan.excessive_agency import ExcessiveAgencyModule
from agentscan.attacks.scan.multi_turn_escalation import MultiTurnEscalationAttack
from agentscan.attacks.scan.pii_exfiltration import PiiExfiltrationModule
from agentscan.attacks.scan.prompt_injection import PromptInjectionModule
from agentscan.attacks.scan.runner import YamlScanRunner
from agentscan.attacks.scan.system_prompt_leak import SystemPromptLeakModule
from agentscan.core import runner
from agentscan.core.models import Framework, Target
from benchmarks.evaluation.fixture import AUTH_TOKEN, provisioned_canary, serve, system_prompt
from benchmarks.evaluation.metrics import confusion_matrix

ROOT = Path(__file__).resolve().parents[2]
CORPUS = Path(__file__).with_name("cases.json")
MODULES = {
    "ATK-001": PromptInjectionModule,
    "ATK-003": PiiExfiltrationModule,
    "ATK-012": SystemPromptLeakModule,
    "ATK-013": ExcessiveAgencyModule,
    "ATK-014": ExfiltrationModule,
    "ATK-018": CredentialHarvestModule,
    "ATK-028": MultiTurnEscalationAttack,
}


def load_cases(path: Path = CORPUS) -> list[dict[str, Any]]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("schema_version") != 1 or document.get("synthetic_only") is not True:
        raise ValueError("Unsupported or non-synthetic corpus.")
    cases = document["cases"]
    seen: set[str] = set()
    for case in cases:
        if case["id"] in seen or case["module"] not in MODULES:
            raise ValueError("Duplicate case ID or unsupported module.")
        seen.add(case["id"])
        if (
            case["split"] not in {"tuning", "holdout", "operational"}
            or type(case["label"]) is not bool
        ):
            raise ValueError("Invalid fixed split or ground-truth label.")
    return cases


def file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def production_sources() -> dict[str, str]:
    return {
        str(path.relative_to(ROOT)).replace("\\", "/"): file_hash(path)
        for path in sorted((ROOT / "agentscan").rglob("*"))
        if path.is_file() and path.suffix in {".py", ".yaml", ".j2"}
    }


def source_digest(hashes: dict[str, str]) -> str:
    return hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest()


def module_inventory() -> list[dict[str, Any]]:
    inventory = []
    for path in sorted((ROOT / "agentscan" / "attacks").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in tree.body:
            if not isinstance(node, ast.ClassDef):
                continue
            fields = {
                target.id: item.value.value
                for item in node.body
                if isinstance(item, ast.Assign) and isinstance(item.value, ast.Constant)
                for target in item.targets
                if isinstance(target, ast.Name)
            }
            if fields.get("attack_id"):
                inventory.append(
                    {
                        "module_id": fields["attack_id"],
                        "name": fields.get("attack_name", node.name),
                        "source": str(path.relative_to(ROOT)).replace("\\", "/"),
                        "labelled_evaluation": "representative selected variants"
                        if fields["attack_id"] in MODULES
                        else "untested",
                    }
                )
    return inventory


def make_module(case: dict[str, Any]):
    module = MODULES[case["module"]]()
    if isinstance(module, YamlScanRunner):
        selected = [
            variant
            for variant in module._load_payload_variants()
            if variant["id"] == case["variant"]
        ]
        if len(selected) != 1:
            raise ValueError(f"Unknown or duplicate production variant: {case['variant']}")
        # Select a real production variant without altering its detector or payload.
        # Selection is an evaluation harness operation; no source files are patched.
        module._load_payload_variants = lambda: tuple(selected)  # type: ignore[method-assign]
    return module


@contextmanager
def selected_registry(module: Any):
    registry = AttackRegistry()
    registry.register(module)
    registry._loaded = True
    original = runner.registry
    runner.registry = registry
    try:
        yield
    finally:
        runner.registry = original


def make_target(case: dict[str, Any], origin: str) -> Target:
    auth = case.get("auth", "valid")
    headers = (
        "Bearer " + AUTH_TOKEN
        if auth == "valid"
        else "Bearer deliberately-invalid"
        if auth == "wrong"
        else None
    )
    module = MODULES[case["module"]]()
    known_prompt = (
        f'FEATURE_TOKEN = "{provisioned_canary(case["id"])}"'
        if case["module"] == "ATK-018"
        else system_prompt(case["id"])
    )
    return Target(
        url=f"{origin}/cases/{case['id']}/chat",
        framework=Framework.UNKNOWN,
        mode=module.supported_modes[0],
        system_prompt=known_prompt if case["module"] in {"ATK-012", "ATK-014", "ATK-018"} else None,
        canary_token=provisioned_canary(case["id"])
        if case["module"] == "ATK-028"
        or case.get("known_canary")
        or (case["module"] == "ATK-001" and case["split"] == "operational")
        else None,
        auth_header=headers,
        concurrency=1,
        request_budget=15,
        timeout=5,
        analysis_mode="deterministic",
        data_classification="sensitive",
        allowed_hosts=["127.0.0.1"],
        allowed_origins=[origin],
        allowed_networks=["127.0.0.0/8"],
        retry_state_changing_requests=False,
    )


def oracle_positive(case: dict[str, Any], receipts: list[dict[str, Any]]) -> bool:
    canary = provisioned_canary(case["id"])
    normalized = canary.replace("_", "").casefold()
    for receipt in receipts:
        state = receipt["state"]
        response = receipt["response"]["response"]
        compact = "".join(char for char in response if char not in " _-\r\n\t").casefold()
        if normalized in compact or "synthetic-worker@private.invalid" in response:
            return True
        if not state["policy_enabled"] or not state["records"]:
            return True
    return False


async def evaluate_cases(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    results = []
    with serve(cases) as (agent, origin):
        for case in cases:
            target = make_target(case, origin)
            with selected_registry(make_module(case)):
                report = await runner.run_scan(target)
            receipts = agent.receipts[case["id"]]
            # A confirmed finding remains positive under partial coverage.
            # Missing criteria and transport failures without a finding are
            # unknown; neither may become a clean negative.
            prediction = (
                True
                if report.findings
                else False
                if report.status == "COMPLETE" and report.tests_run > 0
                else None
            )
            if receipts and any(receipt["canary_in_request"] for receipt in receipts):
                raise AssertionError(f"Private canary contaminated user input: {case['id']}")
            observed = oracle_positive(case, receipts) if receipts else None
            if observed is not None and observed is not case["label"]:
                raise AssertionError(f"Fixture state contradicts declared label: {case['id']}")
            results.append(
                {
                    "case_id": case["id"],
                    "module": case["module"],
                    "variant": case["variant"],
                    "split": case["split"],
                    "label": case["label"],
                    "prediction": prediction,
                    "oracle_observed": observed,
                    "rationale": case["rationale"],
                    "assessment_configuration": {
                        "known_reference_declared": target.canary_token is not None,
                        "reference_for_operational_control": case["module"] == "ATK-001"
                        and case["split"] == "operational",
                    },
                    "assessment_status": report.status,
                    "requests_observed": len(receipts),
                    "tests_selected": report.tests_selected,
                    "tests_evaluated": report.tests_run,
                    "finding_count": len(report.findings),
                    "module_outcomes": report.module_outcomes,
                    "module_errors": report.module_errors,
                    "findings": [finding.model_dump(mode="json") for finding in report.findings],
                    "synthetic_http_receipts": receipts,
                    "evidence_level": "fixture state and local HTTP observations",
                }
            )
    return results


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    holdout = [row for row in rows if row["split"] == "holdout"]
    return {
        "tuning": confusion_matrix([row for row in rows if row["split"] == "tuning"]),
        "holdout": confusion_matrix(holdout),
        "operational": confusion_matrix([row for row in rows if row["split"] == "operational"]),
        "per_module_holdout": {
            module: confusion_matrix([row for row in holdout if row["module"] == module])
            for module in MODULES
        },
    }


def render_report(document: dict[str, Any]) -> str:
    holdout = document["metrics"]["holdout"]

    def metric(value: dict[str, Any]) -> str:
        percentage = "undefined" if value["value"] is None else f"{100 * value['value']:.1f}%"
        return f"{value['numerator']}/{value['denominator']} ({percentage})"

    lines = [
        "# AgentScan synthetic local evaluation",
        "",
        "This is a reproducible in-house synthetic challenge set. It is not an independent production accuracy estimate or a certification.",
        "",
        f"Generated: {document['generated_at']}.",
        f"Dataset SHA-256: `{document['dataset_sha256']}`.",
        f"Production source SHA-256: `{document['production_source_sha256']}`.",
        f"Sources stable during execution: {document['sources_stable_during_run']}.",
        "",
        f"Held-out cases: {holdout['total']}; TP {holdout['tp']}, FP {holdout['fp']}, TN {holdout['tn']}, FN {holdout['fn']}, unknown {holdout['unknown']}.",
        f"Precision: {metric(holdout['precision'])}. Recall: {metric(holdout['recall'])}. False-positive rate: {metric(holdout['false_positive_rate'])}.",
        f"End-to-end recall (unknown positives remain misses): {metric(holdout['end_to_end_recall'])}. Evaluation coverage: {metric(holdout['evaluation_coverage'])}. Positive coverage: {metric(holdout['positive_coverage'])}. Negative coverage: {metric(holdout['negative_coverage'])}.",
        "",
        "Unknown predictions remain separate. Precision/recall/FPR use evaluated cases only; evaluation coverage reports every attempted case. A case is one scenario even when a module sends multiple requests.",
        "",
        "| Module | TP | FP | TN | FN | Unknown | Precision | Recall | FPR |",
        "|---|---:|---:|---:|---:|---:|---|---|---|",
    ]
    for module, values in document["metrics"]["per_module_holdout"].items():
        lines.append(
            f"| {module} | {values['tp']} | {values['fp']} | {values['tn']} | {values['fn']} | {values['unknown']} | {metric(values['precision'])} | {metric(values['recall'])} | {metric(values['false_positive_rate'])} |"
        )
    lines.extend(
        [
            "",
            "## Missed findings and false alarms",
            "",
            "Labels below were declared before execution. They were not adjusted to match detector outputs.",
            "",
        ]
    )
    for row in document["cases"]:
        if (
            row["split"] == "holdout"
            and row["prediction"] is not None
            and row["prediction"] is not row["label"]
        ):
            kind = "false negative" if row["label"] else "false positive"
            lines.append(f"- **{row['case_id']} ({row['module']}, {kind}):** {row['rationale']}")
    lines.extend(["", "## Operational controls", ""])
    operational = document["metrics"]["operational"]
    lines.append(
        f"{operational['unknown']}/{operational['total']} controls are unknown. These authentication/HTTP/response failures must not count as clean negative assessments."
    )
    for row in document["cases"]:
        if row["split"] == "operational":
            lines.append(
                f"- {row['case_id']}: {row['assessment_status']}; evaluated {row['tests_evaluated']}/{row['tests_selected']}; prediction {row['prediction']}."
            )
    lines.extend(
        ["", "## Coverage and limits", "", "| Module | Labelled evaluation |", "|---|---|"]
    )
    for module in document["module_coverage"]:
        lines.append(
            f"| {module['module_id']} — {module['name']} | {module['labelled_evaluation']} |"
        )
    lines.extend(
        [
            "",
            "Only selected production variants in seven modules were evaluated. The remaining modules and other variants have no measured accuracy here.",
            "The real production HTTP facade, scan ledger, scoring and detectors ran without mocking response delivery. Tools mutated a bounded in-memory record list only; no real tool or arbitrary process was executed.",
            "Canary values were provisioned out of band and absent from every scanner user request. Ground truth comes from private fixture state/receipts, not the detector's regular expression.",
            "No provider calls, embedding downloads, judge models, real GPU, MCP server or real agent framework were used. Semantic judgments, language variation and representative customer prevalence are unmeasured.",
            "The inspected holdout is now an exposed diagnostic set. Any detector tuning based on these results needs a new independently authored holdout before claiming generalization.",
            "Production score is a finding summary, not a calibrated probability of safety. A zero score or zero findings cannot replace measured coverage and failure checks.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "internal_docs/diagrams/evaluation")
    parser.add_argument("--corpus", type=Path, default=CORPUS)
    args = parser.parse_args()
    if (args.output / "results.json").exists():
        parser.error(
            "A saved evaluation already exists; choose a new --output directory to preserve its provenance."
        )
    sources = production_sources()
    rows = asyncio.run(evaluate_cases(load_cases(args.corpus)))
    after = production_sources()
    document = {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "synthetic_only": True,
        "dataset_sha256": file_hash(args.corpus),
        "dataset_path": str(args.corpus),
        "dataset_declaration": {
            key: value
            for key, value in json.loads(args.corpus.read_text(encoding="utf-8")).items()
            if key != "cases"
        },
        "label_policy_sha256": file_hash(CORPUS.with_name("LABEL_POLICY.md")),
        "production_source_sha256": source_digest(sources),
        "production_source_hashes": sources,
        "sources_stable_during_run": sources == after,
        "evaluation_source_hashes": {
            path.name: file_hash(path) for path in sorted(CORPUS.parent.glob("*")) if path.is_file()
        },
        "metrics": summarize(rows),
        "module_coverage": module_inventory(),
        "cases": rows,
    }
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "results.json").write_text(
        json.dumps(document, indent=2) + "\n", encoding="utf-8"
    )
    (args.output / "REPORT.md").write_text(render_report(document), encoding="utf-8")
    print(
        json.dumps(
            {
                "output": str(args.output),
                "metrics": document["metrics"],
                "dataset_sha256": document["dataset_sha256"],
                "sources_stable_during_run": document["sources_stable_during_run"],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
