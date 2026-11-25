"""Pin the widened static-analysis contract and optional-provider regression."""

from __future__ import annotations

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REQUIRED_SECURITY_RULES = {
    "S113",
    "S301",
    "S307",
    "S324",
    "S501",
    "S602",
    "S608",
    "S701",
    "S704",
}


def project_config():
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def test_ruff_keeps_the_high_signal_security_subset():
    lint = project_config()["tool"]["ruff"]["lint"]
    assert set(lint["select"]) >= REQUIRED_SECURITY_RULES
    assert "S" not in lint["select"]
    ignores = lint["per-file-ignores"]
    assert set(ignores["tests/fixtures/**"]) == {"S301", "S602", "S608"}
    assert ignores["tests/api/test_idempotency.py"] == ["S608"]
    assert ignores["benchmarks/evaluation/atk005_retrieval_target.py"] == ["S608"]


def test_mypy_widens_checks_without_turning_on_strict_mode():
    mypy = project_config()["tool"]["mypy"]
    assert mypy["strict"] is False
    assert mypy["check_untyped_defs"] is True
    assert mypy["no_implicit_optional"] is True
    assert mypy["strict_equality"] is True
    assert mypy["warn_redundant_casts"] is True
    assert mypy["ignore_missing_imports"] is True


def test_ui_calibration_does_not_require_an_optional_provider_sdk():
    source = (ROOT / "tests/test_ui.py").read_text(encoding="utf-8")
    assert 'importorskip("litellm")' not in source
