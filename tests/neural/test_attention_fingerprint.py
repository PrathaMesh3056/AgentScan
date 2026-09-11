# tests/neural/test_attention_fingerprint.py
#
# Fast unit tests for attention stats, fingerprint hashing, and KL (no HF download).

from __future__ import annotations

import torch

from agentscan.neural.activation_delta import kl_divergence
from agentscan.neural.attention_analyzer import (
    attention_entropy,
    diversion_report,
    sink_concentration,
)
from agentscan.neural.fingerprint import fingerprint_from_activations, tensor_signature


def test_attention_entropy_uniform_higher_than_peaked() -> None:
    uniform = torch.ones(2, 8) / 8
    peaked = torch.zeros(2, 8)
    peaked[:, 0] = 1.0
    assert attention_entropy(uniform) > attention_entropy(peaked)


def test_sink_is_one_for_first_token_mass() -> None:
    peaked = torch.zeros(4, 6)
    peaked[:, 0] = 1.0
    assert abs(sink_concentration(peaked) - 1.0) < 1e-5


def test_diversion_flags_entropy_drop() -> None:
    report = diversion_report(
        benign_entropy=2.0,
        probe_entropy=1.0,
        benign_sink=0.1,
        probe_sink=0.12,
    )
    assert report["diverted"] is True
    assert report["entropy_drop"] == 1.0


def test_fingerprint_stable_for_same_tensor() -> None:
    a = torch.arange(128, dtype=torch.float32)
    b = a.clone()
    assert fingerprint_from_activations([a]) == fingerprint_from_activations([b])
    assert tensor_signature(a) == tensor_signature(b)


def test_fingerprint_changes_when_activation_shifts() -> None:
    a = torch.zeros(64)
    b = torch.ones(64)
    assert fingerprint_from_activations([a]) != fingerprint_from_activations([b])


def test_kl_zero_when_logits_match() -> None:
    logits = torch.tensor([0.2, 0.5, -0.1, 1.3])
    assert abs(kl_divergence(logits, logits)) < 1e-5


def test_kl_positive_when_distributions_differ() -> None:
    p = torch.tensor([5.0, 0.0, 0.0, 0.0])
    q = torch.tensor([0.0, 0.0, 0.0, 5.0])
    assert kl_divergence(p, q) > 1.0
