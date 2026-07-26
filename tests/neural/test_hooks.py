# tests/neural/test_hooks.py
#
# Unit tests for ActivationCapture context manager using a synthetic PyTorch layer.

import torch
import torch.nn as nn

from agentscan.neural.hooks import ActivationCapture


def test_hook_captures_correct_output_tensor() -> None:
    layer = nn.Linear(4, 2)
    x = torch.tensor([[1.0, 2.0, 3.0, 4.0]])

    with ActivationCapture(layer) as cap:
        expected_output = layer(x)

    assert cap.captured is not None
    assert torch.equal(cap.captured, expected_output)


def test_hook_removed_after_context_exit() -> None:
    layer = nn.Linear(4, 2)
    assert len(layer._forward_hooks) == 0

    with ActivationCapture(layer):
        assert len(layer._forward_hooks) == 1

    assert len(layer._forward_hooks) == 0


def test_repeated_use_does_not_accumulate_hooks() -> None:
    layer = nn.Linear(4, 2)
    x = torch.tensor([[1.0, 2.0, 3.0, 4.0]])

    with ActivationCapture(layer) as cap1:
        _ = layer(x)

    with ActivationCapture(layer) as cap2:
        _ = layer(x)

    assert len(layer._forward_hooks) == 0
    assert cap1.captured is not None
    assert cap2.captured is not None
