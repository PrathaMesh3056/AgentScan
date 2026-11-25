# tests/test_reporting/test_audit_coverage_model.py
#
# Regression tests for QA-036: a static audit must expose which modules ran,
# which were not selected, and which errored, in the serialized report.

from __future__ import annotations

import json

import pytest

from agentscan.identity.models import IdentityReport
from agentscan.reporting.audit_coverage import (
    AUDIT_MODULE_KEYS,
    DEFAULT_AUDIT_MODULES,
    assessment_label,
    assessment_status,
    build_coverage,
    normalize_selection,
    scope_complete,
)


def _record(module: str, status: str = "COMPLETE", checks: int = 1) -> dict:
    return {
        "module": module,
        "status": status,
        "source": "test-double",
        "checks_run": checks,
        "inputs_selected": 1,
        "limitations": [],
    }


def test_coverage_keeps_skipped_modules_visible() -> None:
    entries = build_coverage(["scan_config"], [_record("config")])

    assert entries[0]["module"] == "config"
    assert entries[0]["status"] == "COMPLETE"
    skipped = [entry for entry in entries if entry["status"] == "SKIPPED"]
    assert {entry["module_key"] for entry in skipped} == set(AUDIT_MODULE_KEYS) - {"scan_config"}
    assert assessment_status(entries) == "COMPLETE"
    assert scope_complete(["scan_config"]) is False
    assert assessment_label(["scan_config"]) == "Supply-Chain Static Audit"


def test_coverage_records_error_without_hiding_other_modules() -> None:
    entries = build_coverage(
        ["scan_config", "scan_identity"],
        [_record("identity", "NOT_ASSESSED", 0)],
        {"scan_config": "RuntimeError: synthetic scanner failure"},
    )

    error = entries[0]
    assert error["module"] == "config"
    assert error["status"] == "ERROR"
    assert "synthetic scanner failure" in error["limitations"][0]
    assert any(entry["module"] == "identity" for entry in entries)
    assert assessment_status(entries) == "INCONCLUSIVE"


def test_missing_record_becomes_not_assessed_not_complete() -> None:
    entries = build_coverage(["scan_secrets"], [])

    assert entries[0]["status"] == "NOT_ASSESSED"
    assert assessment_status(entries) == "INCONCLUSIVE"


def test_empty_selection_is_not_assessed() -> None:
    assert assessment_status([]) == "NOT_ASSESSED"


def test_mixed_and_single_family_labels_are_explicit() -> None:
    assert assessment_label(["scan_config", "scan_identity"]) == (
        "Mixed Static Audit (Supply-Chain + Identity)"
    )
    assert assessment_label(DEFAULT_AUDIT_MODULES) == (
        "Mixed Static Audit (Supply-Chain + Identity)"
    )
    assert assessment_label(["scan_semgrep"]) == "Code Rules Static Audit"
    assert assessment_label(["scan_identity"]) == "Identity & RBAC Entitlement Audit"


def test_full_selection_is_the_only_complete_scope() -> None:
    assert scope_complete(AUDIT_MODULE_KEYS) is True
    assert scope_complete(DEFAULT_AUDIT_MODULES) is False


def test_unknown_module_is_rejected() -> None:
    with pytest.raises(ValueError, match="Unknown audit module"):
        normalize_selection(["scan_config", "scan_everything"])


def test_report_json_preserves_coverage_status_and_module_errors() -> None:
    entries = build_coverage(
        ["scan_config", "scan_secrets"],
        [_record("config"), _record("secrets", "INCONCLUSIVE", 2)],
        {"scan_secrets": "OSError: synthetic read failure"},
    )
    report = IdentityReport(
        audit_id="qa-036",
        path_audited="fixture",
        findings=[],
        identity_score=None,
        audit_coverage=entries,
        status="INCONCLUSIVE",
        assessment_label="Supply-Chain Static Audit",
        scope_complete=False,
        module_errors=[
            {
                "module": "scan_secrets",
                "module_name": "hardcoded secrets",
                "error": "OSError: synthetic read failure",
            }
        ],
    )

    payload = json.loads(report.model_dump_json())
    statuses = {(entry["module"], entry["status"]) for entry in payload["audit_coverage"]}

    assert payload["assessment_label"] == "Supply-Chain Static Audit"
    assert payload["scope_complete"] is False
    assert payload["status"] == "INCONCLUSIVE"
    assert payload["module_errors"][0]["module"] == "scan_secrets"
    assert ("config", "COMPLETE") in statuses
    assert ("secrets", "INCONCLUSIVE") in statuses
    assert ("secrets", "ERROR") in statuses
    assert sum(1 for entry in payload["audit_coverage"] if entry["status"] == "SKIPPED") == (
        len(AUDIT_MODULE_KEYS) - 2
    )
    assert report.modules_skipped
    assert report.score_label == "Audit Score"
