"""Encrypt queued target credentials and retain bounded redacted report evidence."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet

from agentscan.core.trace import redact_sensitive_data


def data_cipher() -> Fernet:
    path = os.environ.get("AGENTSCAN_DATA_KEY_FILE", "")
    if not path:
        raise RuntimeError("Configure AGENTSCAN_DATA_KEY_FILE with a persistent Fernet key file.")
    try:
        return Fernet(Path(path).read_bytes().strip())
    except (OSError, ValueError) as exc:
        raise RuntimeError("The configured service data key is unavailable or invalid.") from exc


def encrypt_target(target: dict[str, Any]) -> dict[str, str]:
    return {"ciphertext": data_cipher().encrypt(json.dumps(target).encode()).decode()}


def decrypt_target(envelope: dict[str, Any] | None) -> dict[str, Any]:
    if not envelope or not isinstance(envelope.get("ciphertext"), str):
        raise ValueError("A durable encrypted target request is required.")
    value = json.loads(data_cipher().decrypt(envelope["ciphertext"].encode()))
    if not isinstance(value, dict):
        raise ValueError("Invalid encrypted target request.")
    return value


def sanitize_report(value: Any, secrets: tuple[str, ...] = (), key: str = "") -> Any:
    """Service reports retain metadata and digests, never raw traffic or tool arguments.

    This is a retention policy, not a claim that regexes identify every secret.
    Local CLI reports retain evidence under the operator's filesystem policy.
    """
    if key.lower() == "trajectory":
        # Preserve the report schema while omitting raw requests and replies.
        return []
    if key.lower() == "target_url" and isinstance(value, str):
        from urllib.parse import urlsplit

        return urlsplit(value)._replace(query="", fragment="").geturl()
    if key.lower() in {
        "evidence",
        "payload",
        "payload_used",
        "system_prompt",
        "response",
        "request",
        "raw",
        "content",
        "messages",
        "headers",
        "arguments",
    }:
        encoded = json.dumps(value, sort_keys=True, default=str).encode()
        return f"[REDACTED: sha256={hashlib.sha256(encoded).hexdigest()}; bytes={len(encoded)}]"
    if isinstance(value, dict):
        return {str(k): sanitize_report(v, secrets, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize_report(v, secrets) for v in value]
    if isinstance(value, str):
        text = value
        for secret in sorted(set(secrets), key=len, reverse=True):
            if secret:
                text = text.replace(secret, "[REDACTED]")
        return redact_sensitive_data(text)
    return value
