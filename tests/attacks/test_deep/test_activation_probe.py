# tests/attacks/test_deep/test_activation_probe.py
#
# Integration tests for ActivationProbeModule (@pytest.mark.slow).

import pytest

from agentscan.attacks.deep.activation_probe import (
    LAYER_INDEX,
    ActivationProbeModule,
    _extract_layer_activation,
    _load_model_and_tokenizer,
)
from agentscan.core.models import ScanMode, Target
from agentscan.neural.activation_delta import l2_distance


@pytest.mark.slow
@pytest.mark.asyncio
async def test_activation_probe_detects_adversarial_anomaly() -> None:
    module = ActivationProbeModule()
    target = Target(url="http://localhost:8000/chat", mode=ScanMode.DEEP)
    findings = await module.run(target)
    assert len(findings) == 1
    assert findings[0].attack_id == "ATK-023"
    assert findings[0].severity == "HIGH"


@pytest.mark.slow
def test_two_different_benign_prompts_stay_below_threshold() -> None:
    model, tokenizer = _load_model_and_tokenizer()
    prompt1 = "What is the capital of France?"
    prompt2 = "How many continents are there on Earth?"
    prompt3 = "What is the boiling point of water in Celsius?"

    h1 = _extract_layer_activation(model, tokenizer, prompt1, LAYER_INDEX)
    h2 = _extract_layer_activation(model, tokenizer, prompt2, LAYER_INDEX)
    h3 = _extract_layer_activation(model, tokenizer, prompt3, LAYER_INDEX)

    baseline_noise = l2_distance(h1, h2)
    benign_delta = l2_distance(h1, h3)

    assert benign_delta <= 2.0 * baseline_noise
