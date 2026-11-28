# agentscan/remediation/__init__.py
#
# Phase 1 `agentscan fix` — plan and apply safe, local remediations.
# Finding IDs stay SC-/ID-/ATK- (no FIX-* prefix).

from agentscan.remediation.engine import RemediationEngine, plan_and_apply
from agentscan.remediation.models import FixAction, FixPlan
from agentscan.remediation.patch_generator import (
    generate_github_pr_payload,
    generate_unified_patch,
)
from agentscan.remediation.redaction import redact
from agentscan.remediation.webhook_receiver import app as heal_app
from agentscan.remediation.webhook_receiver import run_heal_server

__all__ = [
    "FixAction",
    "FixPlan",
    "RemediationEngine",
    "generate_github_pr_payload",
    "generate_unified_patch",
    "heal_app",
    "plan_and_apply",
    "redact",
    "run_heal_server",
]
