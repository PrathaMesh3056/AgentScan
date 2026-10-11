"""Exercise dashboard request/auth/status/export paths using real local HTTP IO."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from agentscan.ui.app import create_app
from agentscan.ui.state import state
from benchmarks.evaluation.fixture import AUTH_TOKEN, provisioned_canary, serve
from benchmarks.evaluation.run import ROOT, load_cases, make_module, selected_registry


def evaluate_dashboard(project_root: Path) -> list[dict[str, Any]]:
    cases = [case for case in load_cases() if case["id"] in {"PI-T-01", "PII-H-01", "OPS-01"}]
    previous_state = dict(state.__dict__)
    results = []
    try:
        with serve(cases) as (agent, origin):
            for case in cases:
                state.active_scan = None
                state.scan_status = {"status": "idle"}
                state.report = None
                state.sentinel_task = None
                with (
                    selected_registry(make_module(case)),
                    TestClient(
                        create_app(project_root=project_root, token="evaluation-dashboard-token"),
                        base_url="http://127.0.0.1:8765",
                        headers={"Authorization": "Bearer evaluation-dashboard-token"},
                    ) as client,
                ):
                    response = client.post(
                        "/api/scan",
                        json={
                            "target_url": f"{origin}/cases/{case['id']}/chat",
                            "auth_header": "Bearer " + AUTH_TOKEN
                            if case["auth"] == "valid"
                            else "",
                            "analysis_mode": "deterministic",
                            "concurrency": 1,
                            # This is an execution/export check, not a historical
                            # label rerun. ATK-001 requires an out-of-band criterion
                            # before it can reach the target/authentication boundary.
                            "canary_token": provisioned_canary(case["id"])
                            if case["module"] == "ATK-001"
                            else None,
                        },
                    )
                    if response.status_code != 200:
                        raise AssertionError(
                            "Dashboard rejected a valid local evaluation submission."
                        )
                    deadline = time.monotonic() + 8
                    while time.monotonic() < deadline:
                        status = client.get("/api/scan/status").json()
                        if status["status"] != "running":
                            break
                        time.sleep(0.01)
                    else:
                        raise AssertionError(
                            "Dashboard evaluation did not complete within its bound."
                        )
                    report = client.get("/api/report/download", params={"format": "json"}).json()
                    exports = {}
                    for format_name in ("json", "sarif", "html"):
                        exported = client.get(
                            "/api/report/download", params={"format": format_name}
                        )
                        if exported.status_code != 200:
                            raise AssertionError("Dashboard report export failed.")
                        if format_name == "json":
                            assessment = exported.json()
                        elif format_name == "sarif":
                            sarif_run = exported.json()["runs"][0]
                            assessment = sarif_run["properties"]["agentscanAssessment"]
                            if sarif_run["invocations"][0]["executionSuccessful"] is not (
                                report["status"] == "COMPLETE"
                            ):
                                raise AssertionError(
                                    "SARIF completion flag concealed partial coverage."
                                )
                        else:
                            if f"Status: <strong>{report['status']}</strong>" not in exported.text:
                                raise AssertionError("HTML export concealed assessment status.")
                            if report["score"] is None and (
                                "N/A" not in exported.text
                                or "An unavailable target score cannot establish safety."
                                not in exported.text
                            ):
                                raise AssertionError("HTML export concealed the unavailable score.")
                            assessment = report
                        for key in ("status", "score", "tests_selected", "tests_run"):
                            if assessment[key] != report[key]:
                                raise AssertionError(
                                    "Export changed assessment status, score or coverage."
                                )
                        exports[format_name] = {
                            "status": exported.status_code,
                            "content_type": exported.headers["content-type"],
                            "content_disposition": exported.headers.get("content-disposition", ""),
                            "bytes": len(exported.content),
                            "assessment_status": report["status"],
                            "score_available": report["score"] is not None,
                            "coverage_verified": True,
                        }
                    expected = (
                        "inconclusive"
                        if case["id"] == "PII-H-01"
                        else "completed"
                        if case["auth"] == "valid"
                        else "failed"
                    )
                    if status["status"] != expected:
                        raise AssertionError(
                            "Dashboard failed to distinguish authentication failure from a clean scan."
                        )
                    if expected == "failed" and (
                        report["score"] is not None or report["tests_run"]
                    ):
                        raise AssertionError(
                            "Authentication failure was presented with a score/evaluated test."
                        )
                    if expected == "inconclusive" and (
                        report["score"] is not None or report["status"] != "INCONCLUSIVE"
                    ):
                        raise AssertionError(
                            "Missing private reference was presented as a scored completed assessment."
                        )
                    results.append(
                        {
                            "case_id": case["id"],
                            "submission_http_status": response.status_code,
                            "dashboard_status": status,
                            "report_status": report["status"],
                            "exports": exports,
                            "target_http_receipts": agent.receipts[case["id"]],
                            "assessment_configuration": {
                                "known_reference_declared": case["module"] == "ATK-001",
                                "purpose": "execution_status_and_export_contract",
                            },
                            "scope": "actual dashboard API plus selected production module and local authenticated HTTP target; no browser automation",
                        }
                    )
    finally:
        state.__dict__.update(previous_state)
    return results


def main() -> None:
    import tempfile

    output = ROOT / "internal_docs/diagrams/evaluation"
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="evaluation-dashboard-", dir=ROOT / ".test-tmp"
    ) as directory:
        results = evaluate_dashboard(Path(directory))
    (output / "dashboard-api-results.json").write_text(
        json.dumps({"synthetic_only": True, "cases": results}, indent=2) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "checks": len(results),
                "status": "passed",
                "output": str(output / "dashboard-api-results.json"),
            }
        )
    )


if __name__ == "__main__":
    main()
