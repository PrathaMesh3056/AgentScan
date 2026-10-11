# agentscan/neural/hooks.py
#
# Context manager for capturing activation tensors from neural network modules.

from __future__ import annotations

from threading import get_ident
from typing import Any

import torch


class ActivationCapture:
    """
    Context manager for capturing activation output tensors of a PyTorch module.

    Usage:
        with ActivationCapture(module) as cap:
            output = model(**inputs)
        captured_tensor = cap.captured
    """

    def __init__(self, module: torch.nn.Module) -> None:
        self.module = module
        self.captured: torch.Tensor | None = None
        self._handle: torch.utils.hooks.RemovableHandle | None = None
        self._owner_thread: int | None = None

    def _hook(self, module: torch.nn.Module, input: tuple[Any, ...], output: Any) -> None:
        if get_ident() != self._owner_thread:
            return
        tensor = output[0] if isinstance(output, tuple) else output
        if isinstance(tensor, torch.Tensor):
            self.captured = tensor.detach()

    def __enter__(self) -> ActivationCapture:
        self._owner_thread = get_ident()
        self._handle = self.module.register_forward_hook(self._hook)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        if self._handle is not None:
            self._handle.remove()
            self._handle = None
        self._owner_thread = None
