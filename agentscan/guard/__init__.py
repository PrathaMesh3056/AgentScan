# agentscan/guard/__init__.py
#
# Capability firewall and cryptographic protection primitives.

from __future__ import annotations

from agentscan.guard.command import CommandSecurityError, PosixCommandGuard
from agentscan.guard.crypto import CryptographicEngine
from agentscan.guard.firewall import CapabilityGuard, protect_tool
from agentscan.guard.mcp_proxy import MCPCapabilityProxy
from agentscan.guard.path import CanonicalPathGuard, PathSecurityError

__all__ = [
    "CanonicalPathGuard",
    "CapabilityGuard",
    "CommandSecurityError",
    "CryptographicEngine",
    "MCPCapabilityProxy",
    "PathSecurityError",
    "PosixCommandGuard",
    "protect_tool",
]
