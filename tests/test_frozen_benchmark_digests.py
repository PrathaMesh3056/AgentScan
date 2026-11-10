"""Guard frozen evaluation inputs against checkout normalization.

The benchmark runners pin the exact bytes of their input files with SHA-256
constants or a hash recorded in the frozen method. Git's ``core.autocrlf``
rewrites LF to CRLF on Windows unless the file is marked ``-text`` in
``.gitattributes``, which silently breaks those digests. This test fails in that
case instead of letting a benchmark run on unverified inputs.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pytest

EVALUATION_DIR = Path(__file__).resolve().parents[1] / "benchmarks" / "evaluation"

# (runner source, digest constant, frozen input)
FROZEN_INPUTS = [
    ("atk002_run.py", "FROZEN_CASES_SHA256", "atk002_cases.json"),
    ("atk005_retrieval_run.py", "FROZEN_MANIFEST_SHA256", "atk005_retrieval_manifest.json"),
    ("atk007_run.py", "FROZEN_SHA256", "atk007_cases.json"),
    ("atk008_run.py", "FROZEN_CASES_SHA256", "atk008_cases_v3.json"),
    ("atk009_run.py", "FROZEN_CASES_SHA256", "atk009_cases.json"),
    ("atk011_run.py", "FROZEN_CASES_SHA256", "atk011_cases.json"),
]

ATK001_MANIFEST = EVALUATION_DIR / "atk001_local" / "manifest.json"
ATK001_METHOD = EVALUATION_DIR / "atk001_local" / "METHOD.md"


def _declared_digest(script: str, constant: str) -> str:
    source = (EVALUATION_DIR / script).read_text(encoding="utf-8")
    match = re.search(rf'{constant}\s*=\s*"([a-f0-9]{{64}})"', source)
    assert match is not None, f"{constant} not found in {script}"
    return match.group(1)


@pytest.mark.parametrize(("script", "constant", "data_file"), FROZEN_INPUTS)
def test_frozen_input_matches_declared_digest(script: str, constant: str, data_file: str) -> None:
    expected = _declared_digest(script, constant)
    actual = hashlib.sha256((EVALUATION_DIR / data_file).read_bytes()).hexdigest()
    assert actual == expected, (
        f"{data_file} does not match {constant} in {script}. "
        "Frozen evaluation inputs must be checked out byte-for-byte; "
        "check .gitattributes and core.autocrlf."
    )


def test_atk001_frozen_manifest_matches_method_hash() -> None:
    method = ATK001_METHOD.read_text(encoding="utf-8")
    match = re.search(r"Manifest SHA256: \*\*([a-f0-9]{64})\*\*", method)
    assert match is not None, "ATK-001 manifest hash not found in METHOD.md"
    actual = hashlib.sha256(ATK001_MANIFEST.read_bytes()).hexdigest()
    assert actual == match.group(1), (
        "atk001_local/manifest.json does not match the hash in METHOD.md. "
        "Frozen evaluation inputs must be checked out byte-for-byte; "
        "check .gitattributes and core.autocrlf."
    )
