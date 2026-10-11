# agentscan/swarm/budget.py
#
# Bounded swarm controller enforcing round limits, token ceilings, and exploit early-exit.

from __future__ import annotations

from typing import Any

DEFAULT_MAX_ROUNDS: int = 3
DEFAULT_MAX_TOKENS_PER_TURN: int = 256
DEFAULT_TOKEN_MULTIPLIER: int = 10


class BoundedSwarmController:
    """
    Enforces operational boundaries and TAP-style branch pruning for red-team swarms.

    Halts execution when the round budget expires, when total token consumption
    hits the ceiling, or immediately when an exploit has been confirmed.
    """

    def __init__(
        self,
        max_rounds: int = DEFAULT_MAX_ROUNDS,
        max_tokens_per_turn: int = DEFAULT_MAX_TOKENS_PER_TURN,
        token_ceiling: int | None = None,
    ) -> None:
        """
        Initialize the bounded swarm controller.

        Parameters
        ----------
        max_rounds : int
            Maximum number of sequential multi-agent execution rounds.
        max_tokens_per_turn : int
            Expected token budget per agent turn.
        token_ceiling : int | None
            Total token consumption limit across all turns before halting.
        """
        self.max_rounds: int = max_rounds
        self.max_tokens_per_turn: int = max_tokens_per_turn
        self.token_ceiling: int = (
            token_ceiling
            if token_ceiling is not None
            else (max_rounds * max_tokens_per_turn * DEFAULT_TOKEN_MULTIPLIER)
        )
        self.rounds_used: int = 0
        self.tokens_consumed: int = 0
        self.stop_reason: str = "active"

    def should_continue(self, current_round: int, exploit_confirmed: bool) -> bool:
        """
        Determine whether the swarm should proceed with the current round.

        Parameters
        ----------
        current_round : int
            The current 1-indexed round number.
        exploit_confirmed : bool
            Whether a confirmed vulnerability has been established.

        Returns
        -------
        bool
            True if execution is permitted to continue; False otherwise.
        """
        if exploit_confirmed:
            self.stop_reason = "exploit_confirmed"
            return False

        if current_round > self.max_rounds:
            self.stop_reason = "max_rounds_reached"
            return False

        if self.tokens_consumed >= self.token_ceiling:
            self.stop_reason = "token_ceiling_reached"
            return False

        self.rounds_used = max(self.rounds_used, current_round)
        return True

    def record_turn(self, tokens_used: int) -> None:
        """
        Record token consumption for an individual agent turn.

        Parameters
        ----------
        tokens_used : int
            Number of tokens consumed in the turn.
        """
        self.tokens_consumed += max(0, tokens_used)
        if self.tokens_consumed >= self.token_ceiling and self.stop_reason == "active":
            self.stop_reason = "token_ceiling_reached"

    def summary(self) -> dict[str, Any]:
        """
        Generate execution telemetry and stopping summary.

        Returns
        -------
        dict[str, Any]
            Dict containing rounds_used, tokens_consumed, and stop_reason.
        """
        return {
            "rounds_used": self.rounds_used,
            "tokens_consumed": self.tokens_consumed,
            "stop_reason": self.stop_reason if self.stop_reason != "active" else "completed",
        }
