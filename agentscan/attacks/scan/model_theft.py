# agentscan/attacks/scan/model_theft.py
#
# ATK-025: Model Theft / IP Exfiltration — OWASP LLM10
#
# Probes the target agent for disclosure of model internals:
# architecture, training data, fine-tuning instructions, weight paths.

from __future__ import annotations

from pathlib import Path

from agentscan.attacks.scan.runner import YamlScanRunner
from agentscan.core.models import ScanMode


class ModelTheftModule(YamlScanRunner):
    """SCAN-mode probe for model intellectual property exfiltration (LLM10)."""

    attack_id = "ATK-025"
    attack_name = "Model Theft / IP Exfiltration"
    owasp_id = "LLM10"
    supported_modes = [ScanMode.SCAN, ScanMode.EXPLOIT]

    payload_file: Path = Path(__file__).parent.parent / "payloads" / "model_theft.yaml"

    default_remediation: str = (
        "Restrict the model from disclosing architectural details, training data, "
        "fine-tuning instructions, or weight storage paths. Add output filtering "
        "for memorised training content."
    )
