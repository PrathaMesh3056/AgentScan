from __future__ import annotations

import ast
from types import SimpleNamespace

import pytest

from agentscan.remediation.ast_patch import _patch_torch_load


@pytest.mark.parametrize(
    "source",
    [
        "result = torch.load(str(path))\n",
        "label = 'é'; result = torch.load(str(path))  # retain comment\n",
        "result = torch.load(\n    str(path),  # file name\n)\n",
        "result = torch.load(str(path), weights_only=False)\n",
        "result = torch.load(torch.load(str(path)))\n",
    ],
)
def test_torch_patch_attaches_keyword_to_loader_call_and_executes(source: str) -> None:
    calls = []

    def safe_load(*args, weights_only=False):
        calls.append((args, weights_only))
        return "synthetic tensor"

    patched = _patch_torch_load(source)
    ast.parse(patched)
    exec(patched, {"torch": SimpleNamespace(load=safe_load), "path": "weights.bin"})
    assert calls and all(only is True for _, only in calls)
    assert calls[0][0] == ("weights.bin",)
    if "#" in source:
        assert "# retain comment" in patched or "# file name" in patched


def test_torch_dynamic_kwargs_require_manual_review() -> None:
    source = "result = torch.load(str(path), **loader_options)\n"
    assert _patch_torch_load(source) == source
