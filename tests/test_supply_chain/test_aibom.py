# tests/test_supply_chain/test_aibom.py

from __future__ import annotations

import json
from pathlib import Path

from agentscan.supply_chain.aibom import build_cyclonedx_aibom, write_aibom


def test_cyclonedx_aibom_contains_packages_model_and_mcp(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("httpx==0.27.0\n", encoding="utf-8")
    (tmp_path / "demo.mcp.json").write_text(
        json.dumps({"auth": {"type": "token"}, "tools": [{"name": "files.read"}]}),
        encoding="utf-8",
    )
    doc = build_cyclonedx_aibom(str(tmp_path))
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.6"
    names = {c["name"] for c in doc["components"]}
    assert "httpx" in names
    assert "Qwen/Qwen2.5-0.5B-Instruct" in names
    assert "demo.mcp.json" in names
    mcp = next(c for c in doc["components"] if c["name"] == "demo.mcp.json")
    props = {p["name"]: p["value"] for p in mcp["properties"]}
    assert "files.read" in props["agentscan:mcp-tools"]


def test_write_aibom_roundtrip(tmp_path: Path) -> None:
    out = tmp_path / "aibom.cdx.json"
    write_aibom(str(tmp_path), out)
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["bomFormat"] == "CycloneDX"
