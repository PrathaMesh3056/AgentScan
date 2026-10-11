# agentscan/sandbox/selector.py
#
# Tiered sandbox selector implementing the Option A4 architecture.

from __future__ import annotations

import sys

from agentscan.sandbox.base import SandboxBase
from agentscan.sandbox.bwrap import BubblewrapSandbox
from agentscan.sandbox.container import ContainerSandbox
from agentscan.sandbox.gvisor import GVisorSandboxEngine
from agentscan.sandbox.subprocess_audit import SubprocessAuditSandbox

_PRINTED_TIER_ANNOUNCEMENT: bool = False


class SandboxUnavailableError(RuntimeError):
    """The requested execution isolation is unavailable; no host fallback is allowed."""


def reset_tier_announcement() -> None:
    """Reset the announcement state for testing."""
    global _PRINTED_TIER_ANNOUNCEMENT
    _PRINTED_TIER_ANNOUNCEMENT = False


def select_sandbox(
    preferred_tier: str | None = None, *, allow_host_execution: bool = False
) -> SandboxBase:
    """
    Select the highest available sandbox isolation tier on the current host.

    Tier Priority
    -------------
    1. gVisor ('gvisor') : Linux + runsc runtime available in Docker.
    2. Docker ('docker') : Docker daemon accessible.
    3. Bubblewrap ('bwrap') : Linux unprivileged bwrap binary.
    4. Subprocess ('subprocess') : Audit-only fallback mode.

    Parameters
    ----------
    preferred_tier : str | None
        Optional explicit tier to request ("gvisor" | "docker" | "bwrap" | "subprocess").

    Returns
    -------
    SandboxBase
        The instantiated sandbox provider.
    """
    global _PRINTED_TIER_ANNOUNCEMENT

    selected: SandboxBase | None = None

    if preferred_tier:
        candidate_map: dict[str, type[SandboxBase]] = {
            "gvisor": GVisorSandboxEngine,
            "docker": ContainerSandbox,
            "bwrap": BubblewrapSandbox,
            "subprocess": SubprocessAuditSandbox,
        }
        cls = candidate_map.get(preferred_tier.lower())
        if cls is None:
            raise SandboxUnavailableError(f"Unknown sandbox tier: {preferred_tier}")
        if cls is SubprocessAuditSandbox:
            if not allow_host_execution:
                raise SandboxUnavailableError("Host subprocess execution requires explicit opt-in")
            selected = SubprocessAuditSandbox(allow_host_execution=True)
        else:
            candidate = cls()
            if not candidate.is_available():
                raise SandboxUnavailableError(
                    f"Requested sandbox tier is unavailable: {preferred_tier}"
                )
            selected = candidate

    if selected is None:
        gvisor = GVisorSandboxEngine()
        docker = ContainerSandbox()
        bwrap = BubblewrapSandbox()
        if gvisor.is_available():
            selected = gvisor
        elif docker.is_available():
            selected = docker
        elif bwrap.is_available():
            selected = bwrap
        elif allow_host_execution:
            selected = SubprocessAuditSandbox(allow_host_execution=True)
        else:
            raise SandboxUnavailableError(
                "No isolation backend is available; host execution is disabled"
            )

    if not _PRINTED_TIER_ANNOUNCEMENT:
        sys.stderr.write(f"[agentscan] Selected sandbox tier: {selected.tier_name}\n")
        sys.stderr.flush()
        _PRINTED_TIER_ANNOUNCEMENT = True

    return selected
