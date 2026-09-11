# tests/test_remediation/test_ast_patch.py

from pathlib import Path

from agentscan.core.models import Finding, Severity
from agentscan.remediation.ast_patch import plan_ast_patches


def test_ast_patch_torch_load_and_debug(tmp_path: Path) -> None:
    code_file = tmp_path / "model_loader.py"
    code_file.write_text(
        'import torch\n\nDEBUG = True\n\ndef load():\n    return torch.load("weights.pt")\n',
        encoding="utf-8",
    )

    findings = [
        Finding(
            attack_id="SC-011",
            attack_name="Unsafe model deserialisation",
            severity=Severity.CRITICAL,
            owasp_id="LLM05",
            description="Call to torch.load() is missing weights_only=True.",
            evidence="file=model_loader.py, line=6",
            metadata={"file": str(code_file), "line": 6},
        ),
        Finding(
            attack_id="SC-014",
            attack_name="Insecure configuration (DEBUG=True)",
            severity=Severity.HIGH,
            owasp_id="LLM05",
            description="Module-level DEBUG = True found.",
            evidence="file=model_loader.py, line=3",
            metadata={"file": str(code_file), "line": 3},
        ),
    ]

    actions = plan_ast_patches(findings, tmp_path)
    assert len(actions) == 1
    action = actions[0]
    assert action.kind == "ast_patch"
    assert "weights_only=True" in action.after
    assert "DEBUG = False" in action.after


def test_ast_patch_shell_true(tmp_path: Path) -> None:
    code_file = tmp_path / "runner.py"
    code_file.write_text(
        "import subprocess\n\ndef run(cmd):\n    subprocess.Popen(cmd, shell=True)\n",
        encoding="utf-8",
    )

    finding = Finding(
        attack_id="SC-013",
        attack_name="Unconstrained subprocess execution",
        severity=Severity.HIGH,
        owasp_id="LLM05",
        description="subprocess called with shell=True.",
        evidence="file=runner.py, line=4",
        metadata={"file": str(code_file), "line": 4},
    )

    actions = plan_ast_patches([finding], tmp_path)
    assert len(actions) == 1
    assert "shell=False" in actions[0].after
