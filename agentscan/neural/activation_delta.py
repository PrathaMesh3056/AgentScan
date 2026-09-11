# agentscan/neural/activation_delta.py
#
# Distance and similarity metrics for activation tensors.

from __future__ import annotations

import torch


def l2_distance(a: torch.Tensor, b: torch.Tensor) -> float:
    """
    Computes the L2 distance between two activation tensors.
    Flattens tensors to 1D before computing norm to handle multi-dimensional activation states.
    """
    a_flat = a.flatten()
    b_flat = b.flatten()
    return float(torch.norm(a_flat - b_flat).item())


def cosine_similarity(a: torch.Tensor, b: torch.Tensor) -> float:
    """
    Computes cosine similarity between two activation tensors.
    """
    a_flat = a.flatten()
    b_flat = b.flatten()
    return float(torch.nn.functional.cosine_similarity(a_flat, b_flat, dim=0).item())


def kl_divergence(p_logits: torch.Tensor, q_logits: torch.Tensor) -> float:
    """KL(softmax(p) || softmax(q)) between two logit vectors."""
    log_p = torch.nn.functional.log_softmax(p_logits.flatten().float(), dim=0)
    log_q = torch.nn.functional.log_softmax(q_logits.flatten().float(), dim=0)
    p = log_p.exp()
    return float((p * (log_p - log_q)).sum().item())
