# agentscan/core/canary.py
#
# Out-of-band Canary Token Generator & Tracking Engine.
# Generates unique callback URLs embedded in attack payloads to catch blind exfiltration and SSRF.

from __future__ import annotations

import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

from loguru import logger


@dataclass
class CanaryToken:
    token_id: str
    scan_id: str
    attack_id: str
    created_at: float = field(default_factory=time.time)
    triggered: bool = False
    triggered_at: float | None = None
    trigger_metadata: dict[str, Any] = field(default_factory=dict)


class CanaryManager:
    """
    Manages active canaries for in-flight scans.
    When a target agent inadvertently reaches out to the callback URL,
    the canary is marked as triggered and converted into a CRITICAL finding.
    """

    def __init__(self, callback_base_url: str | None = None):
        base_url = (
            callback_base_url or os.environ.get("AGENTSCAN_CANARY_URL") or "http://localhost:8080"
        )
        self.callback_base_url = base_url.rstrip("/")
        self._tokens: dict[str, CanaryToken] = {}

    def create_canary(self, scan_id: str, attack_id: str) -> tuple[str, str]:
        """
        Generate a new canary token.
        Returns:
            (canary_token_id, canary_callback_url)
        """
        token_id = secrets.token_hex(16)
        token = CanaryToken(token_id=token_id, scan_id=scan_id, attack_id=attack_id)
        self._tokens[token_id] = token
        url = f"{self.callback_base_url}/canary/callback/{token_id}"
        return token_id, url

    def record_hit(self, token_id: str, metadata: dict[str, Any]) -> CanaryToken | None:
        """Triggered when an incoming HTTP callback hits the server."""
        token = self._tokens.get(token_id)
        if not token:
            logger.warning(f"Canary callback received for unknown or expired token: {token_id}")
            return None

        token.triggered = True
        token.triggered_at = time.time()
        token.trigger_metadata = metadata
        logger.critical(
            f"CANARY TRIGGERED! Scan: {token.scan_id}, Attack: {token.attack_id}, Token: {token_id}. "
            f"Blind exfiltration / SSRF confirmed!"
        )
        return token

    def check_token(self, token_id: str) -> bool:
        """Check if a specific canary was triggered."""
        token = self._tokens.get(token_id)
        return token.triggered if token else False


# Global singleton instance for the worker / API process
canary_manager = CanaryManager()
