# agentscan/remediation/models.py

from __future__ import annotations

from pydantic import BaseModel, Field


class FixAction(BaseModel):
    """One planned file change produced by `agentscan fix`."""

    path: str = Field(..., description="Filesystem path of the file to change.")
    kind: str = Field(
        ...,
        description="pin_bump | ast_patch | identity_shrink | guardrails",
    )
    finding_id: str = Field(
        ...,
        description="Source finding attack_id (SC- / ID- / ATK-). No FIX-* prefix.",
    )
    before: str = Field(default="", description="File contents before the change.")
    after: str = Field(default="", description="File contents after the change.")
    applied: bool = Field(default=False, description="True only after a successful --apply write.")


class FixPlan(BaseModel):
    """A collection of FixAction changes planned by the remediation engine."""

    actions: list[FixAction] = Field(
        default_factory=list,
        description="All planned remediation actions.",
    )

    @property
    def total_actions(self) -> int:
        return len(self.actions)

    @property
    def applied_count(self) -> int:
        return sum(1 for a in self.actions if a.applied)

    @property
    def paths_affected(self) -> list[str]:
        seen: set[str] = set()
        paths: list[str] = []
        for a in self.actions:
            if a.path not in seen:
                seen.add(a.path)
                paths.append(a.path)
        return paths

    def apply(self) -> int:
        """Write all pending FixAction diffs to disk. Returns count of applied fixes."""
        from pathlib import Path

        applied = 0
        for action in self.actions:
            if not action.applied:
                target_path = Path(action.path)
                target_path.parent.mkdir(parents=True, exist_ok=True)
                target_path.write_text(action.after, encoding="utf-8")
                action.applied = True
                applied += 1
        return applied
