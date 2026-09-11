# agentscan/neural/fingerprint.py
#
# Activation signature over a fixed probe set. Compared to an expected hash
# when AGENTSCAN_MODEL_FINGERPRINT is set (or Target extra_headers).

from __future__ import annotations

import hashlib
import os
from typing import Any

import torch
from loguru import logger

from agentscan.neural.qwen import (
    LAYER_INDEX,
    extract_layer_activation,
    try_load_model_and_tokenizer,
)

FINGERPRINT_PROBES = (
    "Hello.",
    "What is 2 + 2?",
    "Name a primary color.",
    "The sky is",
)

ENV_EXPECTED_HASH = "AGENTSCAN_MODEL_FINGERPRINT"


def tensor_signature(activation: torch.Tensor, decimals: int = 3) -> bytes:
    """Stable compact signature of a last-token activation vector."""
    flat = activation.flatten().float().cpu()
    n = min(64, int(flat.numel()))
    head = torch.round(flat[:n] * (10**decimals))
    stats = torch.tensor(
        [
            float(flat.mean()),
            float(flat.std(unbiased=False)),
            float(flat.min()),
            float(flat.max()),
        ]
    )
    stats_r = torch.round(stats * (10**decimals))
    return head.numpy().tobytes() + stats_r.numpy().tobytes()


def fingerprint_from_activations(activations: list[torch.Tensor]) -> str:
    """SHA-256 hex digest of concatenated tensor signatures."""
    blob = b"".join(tensor_signature(a) for a in activations)
    return hashlib.sha256(blob).hexdigest()


def compute_model_fingerprint(model: Any, tokenizer: Any, layer_idx: int = LAYER_INDEX) -> str:
    acts = [
        extract_layer_activation(model, tokenizer, prompt, layer_idx)
        for prompt in FINGERPRINT_PROBES
    ]
    return fingerprint_from_activations(acts)


def expected_fingerprint() -> str | None:
    value = os.environ.get(ENV_EXPECTED_HASH, "").strip()
    return value or None


def run_fingerprint() -> dict[str, Any] | None:
    """
    Compute the local model fingerprint.
    Returns None if the model cannot be loaded.
    """
    loaded = try_load_model_and_tokenizer()
    if loaded is None:
        return None
    model, tokenizer = loaded
    try:
        digest = compute_model_fingerprint(model, tokenizer)
    except Exception as e:  # noqa: BLE001
        logger.warning(f"Model fingerprint failed: {e}")
        return None
    expected = expected_fingerprint()
    return {
        "digest": digest,
        "expected": expected,
        "matched": expected is None or expected.lower() == digest.lower(),
        "layer_index": LAYER_INDEX,
        "probes": list(FINGERPRINT_PROBES),
    }
