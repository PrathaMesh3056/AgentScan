# agentscan/neural/qwen.py
#
# Shared lazy loader for the local DEEP-mode reference model.
# Never sends weights to a remote API. Failures return None so DEEP modules skip.

from __future__ import annotations

from functools import lru_cache
from typing import Any

from loguru import logger

from agentscan.neural.execution import serialized_reference_call
from agentscan.neural.hooks import ActivationCapture

MODEL_NAME = "Qwen/Qwen2.5-0.5B-Instruct"
MODEL_REVISION = "7ae557604adf67be50417f59c2c2f167def9a775"
LAYER_INDEX = 12  # Qwen2.5-0.5B has 24 hidden layers (24 // 2 = 12)


@serialized_reference_call
@lru_cache(maxsize=1)
def load_model_and_tokenizer() -> tuple[Any, Any]:
    """Load Qwen 0.5B once per process. Raises if transformers/weights are unavailable."""
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(
        MODEL_NAME, revision=MODEL_REVISION, trust_remote_code=False
    )
    model = AutoModelForCausalLM.from_pretrained(
        MODEL_NAME,
        attn_implementation="eager",
        torch_dtype=torch.float32,
        revision=MODEL_REVISION,
        trust_remote_code=False,
        use_safetensors=True,
    )
    model.eval()
    return model, tokenizer


def try_load_model_and_tokenizer() -> tuple[Any, Any] | None:
    """Return (model, tokenizer) or None when the local model cannot be loaded."""
    try:
        return load_model_and_tokenizer()
    except Exception as e:  # noqa: BLE001 - missing GPU/weights/transformers must skip DEEP
        logger.warning(f"DEEP reference model unavailable; skipping neural probes: {e}")
        return None


@serialized_reference_call
def extract_layer_activation(model: Any, tokenizer: Any, prompt: str, layer_idx: int) -> Any:
    """Last-token hidden state at layer_idx via ActivationCapture."""
    import torch

    inputs = tokenizer(prompt, return_tensors="pt")
    target_layer = model.model.layers[layer_idx]
    with torch.no_grad(), ActivationCapture(target_layer) as cap:
        model(**inputs)
    if cap.captured is None:
        raise RuntimeError(f"Failed to capture activation at layer {layer_idx}")
    return cap.captured[:, -1, :]


@serialized_reference_call
def next_token_logits(model: Any, tokenizer: Any, prompt: str) -> Any:
    """Logits for the next token given prompt (no generation)."""
    import torch

    inputs = tokenizer(prompt, return_tensors="pt")
    with torch.no_grad():
        out = model(**inputs)
    return out.logits[0, -1, :]
