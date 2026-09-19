# tests/attacks/test_deep/test_activation_probe.py
#
# Integration tests for ActivationProbeModule (@pytest.mark.slow).

import pytest

pytest.importorskip("torch")

from agentscan.attacks.deep.activation_probe import (
    ANOMALY_MULTIPLIER,
    LAYER_INDEX,
    ActivationProbeModule,
    _benign_cosine_floor,
    _benign_noise_floor,
    _extract_layer_activation,
    _load_model_and_tokenizer,
)
from agentscan.attacks.scan.prompt_injection import PromptInjectionModule
from agentscan.core.models import ScanMode, Severity, Target
from agentscan.neural.activation_delta import cosine_similarity, l2_distance


@pytest.mark.slow
@pytest.mark.asyncio
async def test_activation_probe_corroborates_payloads() -> None:
    module = ActivationProbeModule()
    target = Target(url="http://localhost:8000/chat", mode=ScanMode.DEEP)
    findings = await module.run(target)

    # The probe replays real ATK-001 payloads; at least one should clear the floor.
    assert len(findings) >= 1
    variant_ids = {v["id"] for v in PromptInjectionModule._load_payload_variants()}

    ratios = []
    for f in findings:
        assert f.attack_id == "ATK-023"
        assert f.severity in (Severity.HIGH, Severity.MEDIUM)
        # Every finding links back to a real prompt-injection payload.
        assert f.metadata["yaml_variant_id"] in variant_ids
        assert f.metadata["anomaly_ratio"] >= ANOMALY_MULTIPLIER
        # Both magnitude and direction signals are recorded.
        assert "cosine_similarity" in f.metadata
        assert "benign_cosine_floor" in f.metadata
        assert isinstance(f.metadata["directional_anomaly"], bool)
        # A directional anomaly must always carry HIGH severity.
        if f.metadata["directional_anomaly"]:
            assert f.severity == Severity.HIGH
        ratios.append(f.metadata["anomaly_ratio"])

    # Findings are ordered strongest-anomaly-first.
    assert ratios == sorted(ratios, reverse=True)


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


@pytest.mark.slow
def test_noise_floor_is_mean_pairwise_distance() -> None:
    model, tokenizer = _load_model_and_tokenizer()
    prompts = [
        "What is the capital of France?",
        "How many continents are there on Earth?",
        "What is the boiling point of water in Celsius?",
    ]
    acts = [_extract_layer_activation(model, tokenizer, p, LAYER_INDEX) for p in prompts]

    d01 = l2_distance(acts[0], acts[1])
    d02 = l2_distance(acts[0], acts[2])
    d12 = l2_distance(acts[1], acts[2])
    expected = (d01 + d02 + d12) / 3

    assert _benign_noise_floor(acts) == pytest.approx(expected)


@pytest.mark.slow
def test_cosine_floor_is_mean_pairwise_similarity() -> None:
    model, tokenizer = _load_model_and_tokenizer()
    prompts = [
        "What is the capital of France?",
        "How many continents are there on Earth?",
        "What is the boiling point of water in Celsius?",
    ]
    acts = [_extract_layer_activation(model, tokenizer, p, LAYER_INDEX) for p in prompts]

    c01 = cosine_similarity(acts[0], acts[1])
    c02 = cosine_similarity(acts[0], acts[2])
    c12 = cosine_similarity(acts[1], acts[2])
    expected = (c01 + c02 + c12) / 3

    assert _benign_cosine_floor(acts) == pytest.approx(expected)
