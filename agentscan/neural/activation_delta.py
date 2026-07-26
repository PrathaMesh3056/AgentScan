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
