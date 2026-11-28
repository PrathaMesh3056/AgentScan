# tests/test_sentinel/test_sentinel_renderer.py
#
# QA-170: run the Sentinel renderer evidence checks under Node.

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
RENDERER_TEST = ROOT / "tests" / "test_sentinel" / "sentinel_renderer_test.mjs"


def test_sentinel_renderer_uses_recorded_evidence() -> None:
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is required for dashboard renderer tests")
    result = subprocess.run(
        [node, str(RENDERER_TEST)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr or result.stdout
