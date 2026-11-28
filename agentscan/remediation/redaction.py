"""Shared redaction helper for remediation artifacts.

All remediation artifacts (stdout diffs, plan JSON, patch files, PR payloads,
and webhook responses) must pass through :func:`redact` so synthetic or real
secrets never leak into reviewable output.
"""

from __future__ import annotations

import os
import re
from typing import Any

_ASSIGNMENT_RE = re.compile(
    r"(?i)\b([A-Za-z_][A-Za-z0-9_]*(?:key|secret|token|password|credential|auth)[A-Za-z0-9_]*)"
    r"\s*([:=])\s*"
    r'(?:"([^"]*)"|\'([^\']*)\'|([^\s,;#\r\n]+))'
)

try:
    from agentscan.core.trace import _REDACTION_PATTERNS as _TRACE_PATTERNS
except Exception:
    _TRACE_PATTERNS = []


def _collect_secret_values(*args: Any, **kwargs: Any) -> list[str]:
    values: list[str] = []

    for arg in args:
        if isinstance(arg, str):
            if arg:
                values.append(arg)
        elif isinstance(arg, (list, tuple, set)):
            for item in arg:
                if isinstance(item, str) and item:
                    values.append(item)
        elif isinstance(arg, dict):
            for key in ("secrets", "values", "secret_values", "redaction_secrets", "tokens"):
                nested = arg.get(key)
                if isinstance(nested, (list, tuple, set)):
                    values.extend(str(v) for v in nested if v)
                elif isinstance(nested, str) and nested:
                    values.append(nested)

    for key in ("secrets", "values", "secret_values", "redaction_secrets", "tokens", "secret"):
        nested = kwargs.get(key)
        if isinstance(nested, str) and nested:
            values.append(nested)
        elif isinstance(nested, (list, tuple, set)):
            values.extend(str(v) for v in nested if v)

    for env_key, env_value in os.environ.items():
        if not env_value:
            continue
        upper = env_key.upper()
        if any(marker in upper for marker in ("KEY", "SECRET", "TOKEN", "PASSWORD", "CREDENTIAL", "AUTH")):
            values.append(env_value)

    try:
        from agentscan.core.context import active_context

        context = active_context.get()
        if context is not None:
            redaction_secrets = getattr(context, "redaction_secrets", None)
            if redaction_secrets:
                values.extend(str(v) for v in redaction_secrets if v)
    except Exception:
        pass

    deduped: list[str] = []
    seen: set[str] = set()
    for value in sorted(set(values), key=len, reverse=True):
        if value and value not in seen:
            seen.add(value)
            deduped.append(value)
    return deduped


def _redact_string(text: str, secrets: list[str]) -> str:
    if not text:
        return text
    result = text

    for secret in secrets:
        if not secret:
            continue
        compact_secret = "".join(secret.split())
        result = result.replace(secret, "[REDACTED]")
        if compact_secret and compact_secret != secret:
            result = result.replace(compact_secret, "[REDACTED]")

    def _assignment_repl(match: re.Match[str]) -> str:
        name = match.group(1)
        separator = match.group(2)
        if match.group(3) is not None:
            return f'{name}{separator} "[REDACTED]"'
        if match.group(4) is not None:
            return f"{name}{separator} '[REDACTED]'"
        return f"{name}{separator} [REDACTED]"

    result = _ASSIGNMENT_RE.sub(_assignment_repl, result)

    for pattern, replacement in _TRACE_PATTERNS:
        try:
            result = pattern.sub(replacement, result)
        except Exception:
            continue

    result = re.sub(r"\bsk-[A-Za-z0-9_\-]{10,}\b", "[REDACTED]", result)
    result = re.sub(r"\bsk-ant-[A-Za-z0-9_\-]{10,}\b", "[REDACTED]", result)

    return result


def redact(value: Any, *args: Any, **kwargs: Any) -> Any:
    secrets = _collect_secret_values(*args, **kwargs)
    if args:
        for arg in args:
            if isinstance(arg, (list, tuple, set)):
                extra = _collect_secret_values(arg, *args, **kwargs)
                if extra:
                    secrets = extra
                    break

    if isinstance(value, str):
        return _redact_string(value, secrets)
    if isinstance(value, dict):
        return {k: redact(v, *args, **kwargs) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(item, *args, **kwargs) for item in value]
    if isinstance(value, tuple):
        return tuple(redact(item, *args, **kwargs) for item in value)
    return value


redact_text = redact
redact_secrets = redact
redact_secret = redact
redact_sensitive_data = redact
redact_sensitive_values = redact
redact_sensitive_value = redact
redact_artifact = redact
redact_diff = redact
redact_plan = redact
sanitize = redact

__all__ = [
    "redact",
    "redact_text",
    "redact_secrets",
    "redact_secret",
    "redact_sensitive_data",
    "redact_sensitive_values",
    "redact_sensitive_value",
    "redact_artifact",
    "redact_diff",
    "redact_plan",
    "sanitize",
]