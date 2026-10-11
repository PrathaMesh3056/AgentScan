# agentscan/sandbox/__init__.py
#
# Tiered sandbox isolation engines and exploit verification telemetry.

from __future__ import annotations

from agentscan.sandbox.base import SandboxBase, SandboxResult
from agentscan.sandbox.bwrap import BubblewrapSandbox
from agentscan.sandbox.container import ContainerSandbox
from agentscan.sandbox.gvisor import GVisorSandboxEngine
from agentscan.sandbox.selector import (
    SandboxUnavailableError,
    reset_tier_announcement,
    select_sandbox,
)
from agentscan.sandbox.subprocess_audit import SubprocessAuditSandbox

__all__ = [
    "BubblewrapSandbox",
    "ContainerSandbox",
    "GVisorSandboxEngine",
    "SandboxBase",
    "SandboxResult",
    "SandboxUnavailableError",
    "SubprocessAuditSandbox",
    "reset_tier_announcement",
    "select_sandbox",
]
