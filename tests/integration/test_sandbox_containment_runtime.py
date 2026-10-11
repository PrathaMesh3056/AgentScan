"""Opt-in regression against the local Docker engine and an existing Python image."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from agentscan.sandbox.container import ContainerSandbox


@pytest.mark.slow
@pytest.mark.skipif(
    os.environ.get("AGENTSCAN_RUN_DOCKER_TESTS") != "1",
    reason="Set AGENTSCAN_RUN_DOCKER_TESTS=1 to use disposable Docker resources",
)
def test_real_docker_copied_workspace_and_kernel_controls(tmp_path: Path) -> None:
    sandbox = ContainerSandbox(image="python:3.12-slim")
    assert sandbox.is_available(), "The opted-in Docker engine must be available"
    (tmp_path / "input.txt").write_text("original", encoding="utf-8")
    (tmp_path / ".env").write_text("SYNTHETIC_SECRET=not-copied", encoding="utf-8")
    fixture = """
import json, os
from pathlib import Path
status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines())
try:
    Path('/agentscan-root-write').write_text('denied')
    readonly_root = False
except OSError:
    readonly_root = True
Path('input.txt').write_text('disposable mutation')
Path('receipt.txt').write_text('fixture receipt')
print(json.dumps({
    'uid': os.getuid(),
    'caps': status['CapEff'].strip(),
    'nnp': status['NoNewPrivs'].strip(),
    'seccomp': status['Seccomp'].strip(),
    'interfaces': sorted(p.name for p in Path('/sys/class/net').iterdir()),
    'root_readonly': readonly_root,
    'env_present': Path('.env').exists(),
}))
"""
    run = subprocess.run
    created_ids: list[str] = []
    mounted_workspaces: list[Path] = []

    def observe(argv, **kwargs):
        result = run(argv, **kwargs)
        if argv[:2] == ["docker", "create"] and result.returncode == 0:
            created_ids.append(result.stdout.strip())
            mounted_workspaces.append(
                Path(argv[argv.index("-v") + 1].removesuffix(":/workspace:rw"))
            )
        return result

    with patch("subprocess.run", side_effect=observe):
        result = sandbox.execute_in_sandbox(["python", "-c", fixture], tmp_path, timeout=15)
    assert result.exit_code == 0, result.stderr
    receipt = json.loads(result.stdout)
    assert receipt == {
        "uid": 65534,
        "caps": "0000000000000000",
        "nnp": "1",
        "seccomp": "2",
        "interfaces": ["lo"],
        "root_readonly": True,
        "env_present": False,
    }
    assert (tmp_path / "input.txt").read_text() == "original"
    assert not (tmp_path / "receipt.txt").exists()
    assert {"kind": "C", "path": "/workspace/input.txt"} in result.filesystem_diff
    assert {"kind": "A", "path": "/workspace/receipt.txt"} in result.filesystem_diff
    assert len(created_ids) == 1
    assert all(not workspace.exists() for workspace in mounted_workspaces)
    assert (
        run(["docker", "inspect", created_ids[0]], capture_output=True, timeout=5).returncode != 0
    )
