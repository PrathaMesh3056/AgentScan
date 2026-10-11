# tests/sandbox/test_selector.py

from __future__ import annotations

import io
from unittest.mock import patch

import pytest

from agentscan.sandbox.bwrap import BubblewrapSandbox
from agentscan.sandbox.container import ContainerSandbox
from agentscan.sandbox.gvisor import GVisorSandboxEngine
from agentscan.sandbox.selector import (
    SandboxUnavailableError,
    reset_tier_announcement,
    select_sandbox,
)
from agentscan.sandbox.subprocess_audit import SubprocessAuditSandbox


def test_selector_with_gvisor_available() -> None:
    """Verifies priority 1: gVisor is selected when available."""
    reset_tier_announcement()
    with patch.object(GVisorSandboxEngine, "is_available", return_value=True):
        selected = select_sandbox()
        assert isinstance(selected, GVisorSandboxEngine)
        assert selected.tier_name == "gvisor"


def test_selector_with_docker_available_when_gvisor_absent() -> None:
    """Verifies priority 2: Docker is selected when gVisor is unavailable."""
    reset_tier_announcement()
    with (
        patch.object(GVisorSandboxEngine, "is_available", return_value=False),
        patch.object(ContainerSandbox, "is_available", return_value=True),
    ):
        selected = select_sandbox()
        assert isinstance(selected, ContainerSandbox)
        assert selected.tier_name == "docker"


def test_selector_with_bwrap_available_when_docker_absent() -> None:
    """Verifies priority 3: Bubblewrap is selected when Docker and gVisor are unavailable."""
    reset_tier_announcement()
    with (
        patch.object(GVisorSandboxEngine, "is_available", return_value=False),
        patch.object(ContainerSandbox, "is_available", return_value=False),
        patch.object(BubblewrapSandbox, "is_available", return_value=True),
    ):
        selected = select_sandbox()
        assert isinstance(selected, BubblewrapSandbox)
        assert selected.tier_name == "bwrap"


def test_selector_falls_through_to_subprocess_audit() -> None:
    """Verifies fallback priority 4: SubprocessAuditSandbox selected when no isolation tier is available."""
    reset_tier_announcement()
    with (
        patch.object(GVisorSandboxEngine, "is_available", return_value=False),
        patch.object(ContainerSandbox, "is_available", return_value=False),
        patch.object(BubblewrapSandbox, "is_available", return_value=False),
    ):
        with pytest.raises(SandboxUnavailableError):
            select_sandbox()
        selected = select_sandbox(allow_host_execution=True)
        assert isinstance(selected, SubprocessAuditSandbox)
        assert selected.tier_name == "subprocess"


def test_selector_prints_to_stderr_on_first_call_only() -> None:
    """Verifies stderr announcement prints selected tier once and is not repeated."""
    reset_tier_announcement()
    stderr_capture = io.StringIO()

    with (
        patch("sys.stderr", stderr_capture),
        patch.object(ContainerSandbox, "is_available", return_value=True),
        patch.object(GVisorSandboxEngine, "is_available", return_value=False),
    ):
        select_sandbox()
        output_first = stderr_capture.getvalue()
        assert "[agentscan] Selected sandbox tier: docker" in output_first

        # Second call should not append duplicate announcement
        select_sandbox()
        output_second = stderr_capture.getvalue()
        assert output_second == output_first


def test_selector_preferred_tier_override() -> None:
    """Verifies explicit preferred_tier is honored if functional."""
    reset_tier_announcement()
    with pytest.raises(SandboxUnavailableError):
        select_sandbox(preferred_tier="subprocess")
    selected = select_sandbox(preferred_tier="subprocess", allow_host_execution=True)
    assert isinstance(selected, SubprocessAuditSandbox)
