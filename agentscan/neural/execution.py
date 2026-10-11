"""Serialize shared reference-model loading and inference across worker threads."""

from __future__ import annotations

from collections.abc import Callable
from functools import wraps
from threading import RLock
from typing import Any

reference_model_lock = RLock()


def serialized_reference_call(func: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(func)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        with reference_model_lock:
            return func(*args, **kwargs)

    return wrapped
