# tests/attacks/test_deep/test_trojan_and_skip.py

from __future__ import annotations

from unittest.mock import patch

import pytest
import torch

from agentscan.attacks.deep.attention_probe import AttentionAnalyzerModule
from agentscan.attacks.deep.model_fingerprint import ModelFingerprintModule
from agentscan.attacks.deep.trojan_scanner import TrojanScannerModule
from agentscan.core.models import ScanMode, Severity, Target
from agentscan.neural.qwen import try_load_model_and_tokenizer


@pytest.mark.asyncio
async def test_deep_modules_skip_when_model_unavailable() -> None:
    target = Target(url="http://localhost:8000/chat", mode=ScanMode.DEEP)
    with patch(
        "agentscan.attacks.deep.trojan_scanner.try_load_model_and_tokenizer", return_value=None
    ):
        assert await TrojanScannerModule().run(target) == []
    with patch("agentscan.attacks.deep.attention_probe.run_attention_analysis", return_value=None):
        assert await AttentionAnalyzerModule().run(target) == []
    with patch("agentscan.attacks.deep.model_fingerprint.run_fingerprint", return_value=None):
        assert await ModelFingerprintModule().run(target) == []


@pytest.mark.asyncio
async def test_fingerprint_mismatch_is_high() -> None:
    target = Target(url="http://localhost:8000/chat", mode=ScanMode.DEEP)
    fake = {
        "digest": "aaa",
        "expected": "bbb",
        "matched": False,
        "layer_index": 12,
        "probes": ["Hello."],
    }
    with patch("agentscan.attacks.deep.model_fingerprint.run_fingerprint", return_value=fake):
        findings = await ModelFingerprintModule().run(target)
    assert len(findings) == 1
    assert findings[0].attack_id == "ATK-026"
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_trojan_flags_high_kl() -> None:
    target = Target(url="http://localhost:8000/chat", mode=ScanMode.DEEP)

    class _Tok:
        def __call__(self, text: str, return_tensors: str = "pt") -> dict:
            del text, return_tensors
            return {"input_ids": torch.tensor([[1, 2, 3]])}

        def decode(self, ids: torch.Tensor, skip_special_tokens: bool = True) -> str:
            del ids, skip_special_tokens
            return "The capital of France is Paris"

    class _Model:
        def generate(self, **kwargs: object) -> torch.Tensor:
            del kwargs
            return torch.tensor([[1, 2, 3, 4]])

    baseline = torch.tensor([5.0, 0.0, 0.0, 0.0])
    shifted = torch.tensor([0.0, 0.0, 0.0, 5.0])

    def fake_logits(_model: object, _tok: object, prompt: str) -> torch.Tensor:
        return shifted if "TRIGGER" in prompt or prompt.endswith(" cf") else baseline

    with (
        patch(
            "agentscan.attacks.deep.trojan_scanner.try_load_model_and_tokenizer",
            return_value=(_Model(), _Tok()),
        ),
        patch("agentscan.attacks.deep.trojan_scanner.next_token_logits", side_effect=fake_logits),
        patch(
            "agentscan.attacks.deep.trojan_scanner._greedy_continue",
            return_value="Paris",
        ),
    ):
        findings = await TrojanScannerModule().run(target)

    assert findings
    assert all(f.attack_id == "ATK-024" for f in findings)


def test_try_load_returns_none_on_failure() -> None:
    with patch("agentscan.neural.qwen.load_model_and_tokenizer", side_effect=OSError("offline")):
        assert try_load_model_and_tokenizer() is None
