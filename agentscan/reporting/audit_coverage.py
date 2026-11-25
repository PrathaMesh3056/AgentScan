"""Explicit coverage and status model for static audits (QA-036).

One static audit run is described by one coverage entry per catalog module.
Each entry says whether the module ran (COMPLETE / INCONCLUSIVE /
NOT_ASSESSED), was not selected (SKIPPED) or raised (ERROR). CLI, MCP and
dashboard build the report from this module so the same run cannot be
described as a full audit on one surface and a partial one on another.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

STATUS_COMPLETE = "COMPLETE"
STATUS_INCONCLUSIVE = "INCONCLUSIVE"
STATUS_NOT_ASSESSED = "NOT_ASSESSED"
STATUS_SKIPPED = "SKIPPED"
STATUS_ERROR = "ERROR"

RAN_STATUSES = frozenset({STATUS_COMPLETE, STATUS_INCONCLUSIVE, STATUS_NOT_ASSESSED})
COVERAGE_STATUSES = frozenset({*RAN_STATUSES, STATUS_SKIPPED, STATUS_ERROR})

FAMILY_SUPPLY_CHAIN = "supply_chain"
FAMILY_IDENTITY = "identity"
FAMILY_CODE_RULES = "code_rules"


@dataclass(frozen=True)
class AuditModule:
    """One selectable static-audit module.

    coverage_names are the module values the underlying scanner writes into
    its coverage records (Semgrep can emit two records for one module).
    """

    key: str
    coverage_names: tuple[str, ...]
    family: str
    label: str


AUDIT_MODULES: tuple[AuditModule, ...] = (
    AuditModule("scan_deps", ("dependencies",), FAMILY_SUPPLY_CHAIN, "dependency CVEs"),
    AuditModule("scan_config", ("config",), FAMILY_SUPPLY_CHAIN, "configuration"),
    AuditModule("scan_secrets", ("secrets",), FAMILY_SUPPLY_CHAIN, "hardcoded secrets"),
    AuditModule("scan_typo", ("typosquats",), FAMILY_SUPPLY_CHAIN, "typosquatted packages"),
    AuditModule("scan_mcp", ("mcp",), FAMILY_SUPPLY_CHAIN, "MCP configuration"),
    AuditModule("scan_identity", ("identity",), FAMILY_IDENTITY, "identity & RBAC"),
    AuditModule("scan_frameworks", ("frameworks",), FAMILY_SUPPLY_CHAIN, "agent frameworks"),
    AuditModule("scan_semgrep", ("semgrep", "native_rules"), FAMILY_CODE_RULES, "code rules"),
)

AUDIT_MODULE_KEYS: tuple[str, ...] = tuple(module.key for module in AUDIT_MODULES)
DEFAULT_AUDIT_MODULES: tuple[str, ...] = tuple(
    module.key for module in AUDIT_MODULES if module.key != "scan_semgrep"
)

_MODULES_BY_KEY = {module.key: module for module in AUDIT_MODULES}
_KEY_BY_COVERAGE_NAME = {
    name: module.key for module in AUDIT_MODULES for name in module.coverage_names
}

_FAMILY_ORDER = (FAMILY_SUPPLY_CHAIN, FAMILY_IDENTITY, FAMILY_CODE_RULES)
_FAMILY_TITLES = {
    FAMILY_SUPPLY_CHAIN: "Supply-Chain",
    FAMILY_IDENTITY: "Identity",
    FAMILY_CODE_RULES: "Code Rules",
}


def module_for(key: str) -> AuditModule:
    """Return the catalog entry for key, or raise a clear error."""
    try:
        return _MODULES_BY_KEY[key]
    except KeyError:
        raise ValueError(f"Unknown audit module: {key}") from None


def normalize_selection(selected: Iterable[str] | None) -> list[str]:
    """Return selected module keys in catalog order, validating unknown keys."""
    if selected is None:
        return list(DEFAULT_AUDIT_MODULES)
    requested = set(selected)
    unknown = sorted(requested.difference(AUDIT_MODULE_KEYS))
    if unknown:
        raise ValueError("Unknown audit module(s): " + ", ".join(unknown))
    return [key for key in AUDIT_MODULE_KEYS if key in requested]


def _entry(
    module: AuditModule,
    status: str,
    *,
    checks_run: int,
    source: str,
    limitations: Sequence[str],
) -> dict[str, Any]:
    if status not in COVERAGE_STATUSES:
        raise ValueError(f"Unknown coverage status: {status}")
    return {
        "module": module.coverage_names[0],
        "module_key": module.key,
        "label": module.label,
        "status": status,
        "source": source,
        "checks_run": checks_run,
        "inputs_selected": 0,
        "limitations": list(limitations),
    }


def build_coverage(
    selected: Iterable[str],
    records: Iterable[Mapping[str, Any]],
    errors: Mapping[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Return one explicit entry per selected and unselected catalog module.

    The scanner-produced records are preserved verbatim. Selected modules with
    no record must not disappear from the report: they become ERROR (when the
    runner captured an exception) or NOT_ASSESSED (no record was produced).
    Modules that were not selected are kept as SKIPPED entries so a partial
    run can never read as a full audit.
    """
    selection = normalize_selection(selected)
    selected_set = set(selection)
    errors = errors or {}
    record_list = [dict(record) for record in records]
    matched: set[int] = set()
    entries: list[dict[str, Any]] = []

    by_module: dict[str, list[tuple[int, dict[str, Any]]]] = {}
    for index, record in enumerate(record_list):
        key = _KEY_BY_COVERAGE_NAME.get(str(record.get("module", "")))
        if key is not None:
            by_module.setdefault(key, []).append((index, record))

    for key in selection:
        module = module_for(key)
        if key in errors:
            entries.append(
                _entry(
                    module,
                    STATUS_ERROR,
                    checks_run=0,
                    source="module_error",
                    limitations=[errors[key]],
                )
            )
        for index, record in by_module.get(key, ()):
            matched.add(index)
            entries.append(record)
        if key not in errors and key not in by_module:
            entries.append(
                _entry(
                    module,
                    STATUS_NOT_ASSESSED,
                    checks_run=0,
                    source="no_coverage_record",
                    limitations=["The module returned no coverage record."],
                )
            )

    for index, record in enumerate(record_list):
        if index not in matched:
            # Never drop a scanner record just because the catalog does not know it.
            entries.append(record)

    for key in AUDIT_MODULE_KEYS:
        if key in selected_set:
            continue
        module = module_for(key)
        entries.append(
            _entry(
                module,
                STATUS_SKIPPED,
                checks_run=0,
                source="not_selected",
                limitations=["Not selected for this run; this module was not assessed."],
            )
        )
    return entries


def coverage_counts(entries: Iterable[Mapping[str, Any]]) -> dict[str, int]:
    """Count coverage entries by state (a module can contribute more than one)."""
    counts = {"ran": 0, "skipped": 0, "errored": 0, "total": 0}
    for entry in entries:
        counts["total"] += 1
        status = entry.get("status")
        if status == STATUS_SKIPPED:
            counts["skipped"] += 1
        elif status == STATUS_ERROR:
            counts["errored"] += 1
        elif status in RAN_STATUSES:
            counts["ran"] += 1
    return counts


def assessment_status(entries: Iterable[Mapping[str, Any]]) -> str:
    """Return the assessment completion status for a coverage list.

    COMPLETE requires every selected module to be complete and at least one
    check to have run. Any errored, inconclusive or not-assessed selected
    module makes the assessment INCONCLUSIVE rather than clean.
    """
    selected_entries = [entry for entry in entries if entry.get("status") != STATUS_SKIPPED]
    if not selected_entries:
        return STATUS_NOT_ASSESSED
    if any(entry.get("status") != STATUS_COMPLETE for entry in selected_entries):
        return STATUS_INCONCLUSIVE
    checks_run = sum(int(entry.get("checks_run", 0) or 0) for entry in selected_entries)
    return STATUS_COMPLETE if checks_run > 0 else STATUS_INCONCLUSIVE


def scope_complete(selected: Iterable[str]) -> bool:
    """True only when every catalog module was selected for this run."""
    return set(selected) == set(AUDIT_MODULE_KEYS)


def assessment_label(selected: Iterable[str]) -> str:
    """Human label for the assessed mode, including explicit mixed-mode labels."""
    families = {module_for(key).family for key in selected}
    if not families:
        return "Static Audit"
    if families == {FAMILY_IDENTITY}:
        return "Identity & RBAC Entitlement Audit"
    if families == {FAMILY_SUPPLY_CHAIN}:
        return "Supply-Chain Static Audit"
    if families == {FAMILY_CODE_RULES}:
        return "Code Rules Static Audit"
    titles = " + ".join(_FAMILY_TITLES[family] for family in _FAMILY_ORDER if family in families)
    return f"Mixed Static Audit ({titles})"
