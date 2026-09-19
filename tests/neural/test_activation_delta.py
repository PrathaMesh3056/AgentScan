# tests/neural/test_activation_delta.py
#
# Unit tests for activation tensor metrics (l2_distance, cosine_similarity).

import pytest

pytest.importorskip("torch")
import torch

from agentscan.neural.activation_delta import cosine_similarity, l2_distance


def test_l2_distance_identical_tensors_returns_zero() -> None:
    a = torch.tensor([1.0, 2.5, -3.0])
    b = torch.tensor([1.0, 2.5, -3.0])
    assert l2_distance(a, b) == 0.0


def test_l2_distance_known_tensors_matches_expected() -> None:
    a = torch.tensor([1.0, 2.0, 3.0])
    b = torch.tensor([4.0, 6.0, 3.0])
    # Difference vector is [-3.0, -4.0, 0.0], sqrt(9 + 16 + 0) = 5.0
    assert l2_distance(a, b) == pytest.approx(5.0, abs=1e-6)


def test_cosine_similarity_identical_tensors_returns_one() -> None:
    a = torch.tensor([1.0, 2.0, 3.0])
    b = torch.tensor([1.0, 2.0, 3.0])
    assert cosine_similarity(a, b) == pytest.approx(1.0, abs=1e-6)
