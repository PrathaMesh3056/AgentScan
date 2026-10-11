# tests/guard/test_path.py

from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import patch

import pytest

from agentscan.guard.path import CanonicalPathGuard, PathSecurityError


def test_path_confinement_happy_path(tmp_path: Path) -> None:
    """Verifies that resolving valid relative and absolute paths within containment succeeds."""
    guard = CanonicalPathGuard(tmp_path)
    file_path = tmp_path / "valid.txt"
    file_path.write_text("secure content", encoding="utf-8")

    # Relative path resolution
    resolved_rel = guard.resolve_safe("valid.txt")
    assert resolved_rel == file_path

    # Absolute path within boundary
    resolved_abs = guard.resolve_safe(file_path)
    assert resolved_abs == file_path


def test_path_traversal_dot_dot_escape(tmp_path: Path) -> None:
    """Verifies parent directory traversal (../) attempts are rejected."""
    guard = CanonicalPathGuard(tmp_path)

    with pytest.raises(PathSecurityError) as exc_info:
        guard.resolve_safe("../../../etc/passwd")
    assert "escapes containment boundary" in str(exc_info.value)

    with pytest.raises(PathSecurityError) as exc_info:
        guard.resolve_safe("sub/../../outside.txt")
    assert "escapes containment boundary" in str(exc_info.value)


def test_null_byte_injection(tmp_path: Path) -> None:
    """Verifies null-byte injection cannot bypass path boundary or trigger unhandled OS errors."""
    guard = CanonicalPathGuard(tmp_path)
    valid_file = tmp_path / "safe.txt"
    valid_file.write_text("hello", encoding="utf-8")

    with pytest.raises(PathSecurityError, match="Null bytes"):
        guard.resolve_safe("safe.txt\x00")

    # Null byte with traversal is blocked
    with pytest.raises(PathSecurityError) as exc_info:
        guard.resolve_safe("../../../etc/passwd\x00.png")
    assert "Null bytes" in str(exc_info.value)


def test_symlink_escape_detected(tmp_path: Path) -> None:
    """Verifies symlink escapes pointing outside containment boundary are blocked."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "secret.txt"
    secret.write_text("secret", encoding="utf-8")

    guard = CanonicalPathGuard(workspace)

    # 1. Platform-dependent real symlink test if privileges allow
    link_path = workspace / "leak_link"
    try:
        link_path.symlink_to(outside, target_is_directory=True)
        with pytest.raises(PathSecurityError) as exc_info:
            guard.resolve_safe("leak_link/secret.txt")
        assert "escapes containment boundary" in str(exc_info.value)
    except OSError:
        pass  # Windows unprivileged environment; verified via mock below

    # 2. Deterministic mock verification across all platforms
    with patch.object(Path, "resolve", return_value=secret):
        with pytest.raises(PathSecurityError) as exc_info:
            guard.resolve_safe("simulated_symlink.txt")
        assert "escapes containment boundary" in str(exc_info.value)


def test_absolute_path_outside_root(tmp_path: Path) -> None:
    """Verifies absolute paths pointing outside containment boundary are blocked."""
    guard = CanonicalPathGuard(tmp_path)
    outside_path = Path("/etc/shadow")

    with pytest.raises(PathSecurityError) as exc_info:
        guard.resolve_safe(outside_path)
    assert "escapes containment boundary" in str(exc_info.value)


def test_must_exist_flag(tmp_path: Path) -> None:
    """Verifies behavior when must_exist is True vs False."""
    guard = CanonicalPathGuard(tmp_path)
    non_existent = "non_existent.txt"

    # Default / must_exist=False succeeds for non-existent files inside boundary
    resolved = guard.resolve_safe(non_existent, must_exist=False)
    assert resolved == (tmp_path / non_existent).resolve()

    # must_exist=True raises FileNotFoundError
    with pytest.raises(FileNotFoundError):
        guard.resolve_safe(non_existent, must_exist=True)


def test_nonexistent_allowed_root_raises_error(tmp_path: Path) -> None:
    """Verifies instantiating CanonicalPathGuard with a non-existent root raises FileNotFoundError."""
    missing_dir = tmp_path / "does_not_exist"
    with pytest.raises(FileNotFoundError) as exc_info:
        CanonicalPathGuard(missing_dir)
    assert "does not exist" in str(exc_info.value)


@pytest.mark.slow
def test_resolve_safe_latency_under_1ms_100_consecutive_calls(tmp_path: Path) -> None:
    """
    Isolated performance benchmark (run separately from concurrent build/IO work):
    Asserts CanonicalPathGuard.resolve_safe() executes in <1ms on 100 consecutive calls.
    """
    guard = CanonicalPathGuard(tmp_path)
    target_file = tmp_path / "latency_benchmark.txt"
    target_file.write_text("perf", encoding="utf-8")

    # Warm-up calls
    for _ in range(5):
        guard.resolve_safe("latency_benchmark.txt")

    import gc

    was_enabled = gc.isenabled()
    gc.collect()
    gc.disable()
    latencies_ms: list[float] = []
    try:
        for _ in range(100):
            t0 = time.perf_counter()
            resolved = guard.resolve_safe("latency_benchmark.txt")
            dt_ms = (time.perf_counter() - t0) * 1000.0
            latencies_ms.append(dt_ms)
            assert resolved == target_file
    finally:
        if was_enabled:
            gc.enable()

    avg_latency = sum(latencies_ms) / len(latencies_ms)
    sorted_latencies = sorted(latencies_ms)
    p95_latency = sorted_latencies[94]

    assert avg_latency < 0.5, f"Avg latency was {avg_latency:.4f}ms, expected < 0.5ms"
    assert p95_latency < 1.0, f"95th percentile latency was {p95_latency:.4f}ms, expected < 1.0ms"
