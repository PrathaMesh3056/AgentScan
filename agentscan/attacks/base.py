# agentscan/attacks/base.py
#
# The contract every attack module must sign.
# Now imports from core/models.py — the single source of truth.

from __future__ import annotations

from abc import ABC, abstractmethod

from agentscan.core.models import Finding, ScanMode, Severity, Target


class AttackModule(ABC):
    """
    Abstract base class for every AgentScan attack module.

    To create a new attack module:
    1. Subclass AttackModule
    2. Set attack_id, attack_name, owasp_id as class attributes
    3. Implement async run(target) -> List[Finding]
    4. Drop the file in agentscan/attacks/scan/, exploit/, or deep/
    5. The registry picks it up automatically — no other changes needed

    Example:
        class MyAttack(AttackModule):
            attack_id   = "ATK-099"
            attack_name = "My New Attack"
            owasp_id    = "LLM01"

            async def run(self, target: Target) -> List[Finding]:
                # fire HTTP requests, check responses
                return [self.make_finding(...)]
    """

    attack_id: str
    attack_name: str
    owasp_id: str

    # Which ScanModes this module runs in.
    # Default: SCAN only. Override in subclass to add EXPLOIT or DEEP.
    supported_modes: list[ScanMode] = [ScanMode.SCAN]

    def __init_subclass__(cls, **kwargs: object) -> None:
        """
        Runs when Python reads any subclass definition.
        Enforces required class attributes before any instance is created.
        """
        super().__init_subclass__(**kwargs)

        # Skip check for abstract intermediary classes
        if getattr(cls, "__abstractmethods__", None):
            return

        required = ["attack_id", "attack_name", "owasp_id"]
        for attr in required:
            if not hasattr(cls, attr):
                raise TypeError(
                    f"{cls.__name__} is missing required class attribute "
                    f"'{attr}'. Every AttackModule must define: {required}"
                )

    @abstractmethod
    async def run(self, target: Target) -> list[Finding]:
        """
        Execute this attack against target.

        Args:
            target: The LLM endpoint to scan.

        Returns:
            List of Findings. Empty list = target passed this attack.

        Must be async. Never use blocking I/O inside run().
        """
        ...

    def is_applicable(self, target: Target) -> bool:
        """
        Return True if this module should run against this target.

        Default: checks if target.mode is in supported_modes.
        Override to add framework-specific or other conditions.
        """
        return target.mode in self.supported_modes

    def make_finding(
        self,
        severity: Severity,
        description: str,
        evidence: str = "",
        remediation: str = "",
        payload_used: str | None = None,
        turn_number: int | None = None,
    ) -> Finding:
        """
        Convenience factory so subclasses don't repeat boilerplate.
        Automatically uses this module's attack_id, attack_name, owasp_id.
        """
        return Finding(
            attack_id=self.attack_id,
            attack_name=self.attack_name,
            severity=severity,
            owasp_id=self.owasp_id,
            description=description,
            evidence=evidence,
            remediation=remediation,
            payload_used=payload_used,
            turn_number=turn_number,
        )

    def make_pass(self, description: str = "") -> Finding:
        """
        Shortcut for creating a PASS finding.
        Call this when the target correctly resists the attack.
        """
        return self.make_finding(
            severity=Severity.PASS,
            description=description or f"{self.attack_name}: target passed.",
        )

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__} "
            f"id={self.attack_id} "
            f"owasp={self.owasp_id} "
            f"modes={[m.value for m in self.supported_modes]}>"
        )
