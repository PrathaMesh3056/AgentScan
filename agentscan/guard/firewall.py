# agentscan/guard/firewall.py
#
# In-flight tool capability firewall and @protect_tool decorator.

from __future__ import annotations

import asyncio
import functools
import inspect
import json
import re
import urllib.parse
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, cast, overload

from pydantic import BaseModel, ValidationError

from agentscan.guard.command import SHELL_INJECTION_PATTERN
from agentscan.guard.path import CanonicalPathGuard, PathSecurityError

PATH_KEY_PATTERN = re.compile(
    r"(path|file|dir|directory|uri|location|src|dest|destination|target)",
    re.IGNORECASE,
)


class CapabilityGuard:
    """
    In-flight tool parameter firewall for agent tool functions.

    Composes CanonicalPathGuard, shell metacharacter checking, Pydantic schema
    validation, and domain allowlists. Returns structured JSON error strings
    rather than raising exceptions so the LLM agent can re-plan cleanly.
    """

    def __init__(
        self,
        allowed_root: str | Path | None = None,
        allowed_domains: Sequence[str] | None = None,
        disallow_shell_metachars: bool = True,
    ) -> None:
        """
        Initialize the CapabilityGuard.

        Parameters
        ----------
        allowed_root : str | Path | None
            Base directory for filesystem confinement. If None, filesystem checks are skipped.
        allowed_domains : Sequence[str] | None
            List of permitted external network domains. If None or empty, all domains allowed.
        disallow_shell_metachars : bool
            Whether to inspect and block shell metacharacters in string parameters.
        """
        self.allowed_root: Path | None = (
            Path(allowed_root).resolve() if allowed_root is not None else None
        )
        self.path_guard: CanonicalPathGuard | None = (
            CanonicalPathGuard(self.allowed_root) if self.allowed_root is not None else None
        )
        self.allowed_domains: set[str] = {
            domain.lower().rstrip(".") for domain in allowed_domains or []
        }
        self._domain_policy_configured = allowed_domains is not None
        self.disallow_shell_metachars: bool = disallow_shell_metachars
        self._shell_regex = SHELL_INJECTION_PATTERN

    def inspect_parameters(
        self,
        bound_args: dict[str, Any],
        schema_model: type[BaseModel] | None = None,
    ) -> str | None:
        """
        Inspects parameter dictionary against all security policies.

        Parameters
        ----------
        bound_args : dict[str, Any]
            Mapped argument dictionary for the tool invocation.
        schema_model : type[BaseModel] | None
            Optional Pydantic model for schema validation.

        Returns
        -------
        str | None
            Structured JSON error string if a violation is detected; None if clean.
        """
        # 1. Pydantic schema validation
        if schema_model is not None:
            try:
                validated = schema_model.model_validate(bound_args)
                # Execute exactly the values that Pydantic validated and normalized.
                bound_args.update(
                    {name: getattr(validated, name) for name in type(validated).model_fields}
                )
            except ValidationError as err:
                return json.dumps(
                    {
                        "error": "SecurityPolicyViolation",
                        "type": "schema_validation_error",
                        "details": str(err),
                        "instruction_for_agent": (
                            "Invalid tool arguments. Please fix parameters according to "
                            "the schema and re-plan."
                        ),
                    }
                )

        try:
            arguments = self._walk_arguments(bound_args)
        except ValueError as error:
            return json.dumps(
                {
                    "error": "SecurityPolicyViolation",
                    "type": "argument_structure_error",
                    "details": str(error),
                }
            )
        for key, val in arguments:
            violation = self._inspect_single_argument(key, val)
            if violation is not None:
                return violation

        bound_args.update(self._normalize_paths(bound_args))

        return None

    def _normalize_paths(self, value: Any, key: str = "") -> Any:
        if isinstance(value, BaseModel):
            return value.model_copy(
                update={
                    name: self._normalize_paths(getattr(value, name), f"{key}.{name}")
                    for name in type(value).model_fields
                }
            )
        if isinstance(value, dict):
            return {
                name: self._normalize_paths(item, f"{key}.{name}" if key else str(name))
                for name, item in value.items()
            }
        if isinstance(value, (list, tuple)):
            normalized = [
                self._normalize_paths(item, f"{key}.{index}") for index, item in enumerate(value)
            ]
            return tuple(normalized) if isinstance(value, tuple) else normalized
        if isinstance(value, (str, Path)) and self.path_guard is not None:
            text = str(value)
            if self._is_path_like(key, text) and not self._is_url_or_domain(key, text):
                resolved = self.path_guard.resolve_safe(value)
                return resolved if isinstance(value, Path) else str(resolved)
        return value

    def _walk_arguments(self, arguments: Any) -> list[tuple[str, Any]]:
        """Inspect nested schema/list parameters with bounded depth and node count."""
        result: list[tuple[str, Any]] = []
        active: set[int] = set()
        nodes = 0

        def walk(value: Any, key: str, depth: int) -> None:
            nonlocal nodes
            nodes += 1
            if depth > 32 or nodes > 10000:
                raise ValueError("Tool arguments exceed supported nesting or size")
            if isinstance(value, BaseModel):
                value = {name: getattr(value, name) for name in type(value).model_fields}
            if isinstance(value, (dict, list, tuple)):
                if id(value) in active:
                    raise ValueError("Cyclic tool arguments are not permitted")
                active.add(id(value))
                items = value.items() if isinstance(value, dict) else enumerate(value)
                for child, item in items:
                    walk(item, f"{key}.{child}" if key else str(child), depth + 1)
                active.remove(id(value))
            else:
                result.append((key, value))

        walk(arguments, "", 0)
        return result

    def _inspect_single_argument(self, key: str, val: Any) -> str | None:
        """Inspects an individual parameter for path escape, shell metacharacters, or bad domain."""
        if isinstance(val, (str, Path)):
            str_val = str(val)

            # Shell metacharacter inspection
            if self.disallow_shell_metachars and self._shell_regex.search(str_val):
                return json.dumps(
                    {
                        "error": "SecurityPolicyViolation",
                        "type": "shell_injection_error",
                        "parameter": key,
                        "value": str_val,
                        "details": f"Disallowed shell metacharacters detected in parameter '{key}'.",
                        "instruction_for_agent": (
                            "Shell metacharacters (;, |, &, $, `, <, >) are blocked. "
                            "Use direct, parameterized inputs."
                        ),
                    }
                )

            # Domain allowlist check
            network_value = self._is_url_or_domain(key, str_val)
            if self._domain_policy_configured and network_value:
                domain = self._extract_domain(str_val)
                if not domain or domain.lower().rstrip(".") not in self.allowed_domains:
                    return json.dumps(
                        {
                            "error": "SecurityPolicyViolation",
                            "type": "unauthorized_domain",
                            "parameter": key,
                            "value": str_val,
                            "details": f"Domain '{domain}' is not in the allowed domains list.",
                            "instruction_for_agent": (
                                f"Network access is restricted to: {sorted(self.allowed_domains)}. "
                                "Please re-plan using an approved endpoint."
                            ),
                        }
                    )

            # Path confinement check
            if (
                self.path_guard is not None
                and not network_value
                and self._is_path_like(key, str_val)
            ):
                try:
                    self.path_guard.resolve_safe(val)
                except PathSecurityError as err:
                    return json.dumps(
                        {
                            "error": "SecurityPolicyViolation",
                            "type": "path_confinement_error",
                            "parameter": key,
                            "value": str_val,
                            "details": str(err),
                            "instruction_for_agent": (
                                f"Access outside allowed workspace root '{self.allowed_root}' is denied. "
                                "Please re-plan within the workspace."
                            ),
                        }
                    )

        return None

    def _is_path_like(self, key: str, val: str) -> bool:
        """Determines if a key/value pair represents a filesystem path."""
        if PATH_KEY_PATTERN.search(key):
            return True
        return val.startswith(("/", "\\", "./", ".\\", "../", "..\\")) or bool(
            re.match(r"^[a-zA-Z]:[/\\]", val)
        )

    def _is_url_or_domain(self, key: str, val: str) -> bool:
        """Determines if a key/value pair represents a URL or network endpoint."""
        lower_key = key.lower()
        return (
            "url" in lower_key
            or "uri" in lower_key
            or "domain" in lower_key
            or "endpoint" in lower_key
            or val.startswith(("http://", "https://", "ws://", "wss://"))
        )

    def _extract_domain(self, val: str) -> str | None:
        """Extracts the hostname or domain component from a URL or raw domain string."""
        if "://" in val:
            try:
                parsed = urllib.parse.urlparse(val)
                if (
                    parsed.scheme not in ("http", "https", "ws", "wss")
                    or parsed.username
                    or parsed.password
                ):
                    return None
                return parsed.hostname
            except ValueError:
                return None
        return val.split("/")[0].split(":")[0]

    @overload
    def protect_tool[F: Callable[..., Any]](self, func: F) -> F: ...

    @overload
    def protect_tool[F: Callable[..., Any]](
        self, func: None = None, *, schema_model: type[BaseModel] | None = None
    ) -> Callable[[F], F]: ...

    def protect_tool[F: Callable[..., Any]](
        self,
        func: F | None = None,
        *,
        schema_model: type[BaseModel] | None = None,
    ) -> F | Callable[[F], F]:
        """
        Decorator wrapping tool functions with in-flight verification.

        Supports both sync and async functions, returning a structured JSON error
        string upon security policy violation to allow LLM re-planning.
        """

        def decorator(target_func: F) -> F:
            sig = inspect.signature(target_func)

            if asyncio.iscoroutinefunction(target_func):

                @functools.wraps(target_func)
                async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                    bound = sig.bind(*args, **kwargs)
                    bound.apply_defaults()
                    err = self.inspect_parameters(bound.arguments, schema_model=schema_model)
                    if err is not None:
                        return err
                    return await target_func(*bound.args, **bound.kwargs)

                return cast(F, async_wrapper)

            @functools.wraps(target_func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                bound = sig.bind(*args, **kwargs)
                bound.apply_defaults()
                err = self.inspect_parameters(bound.arguments, schema_model=schema_model)
                if err is not None:
                    return err
                return target_func(*bound.args, **bound.kwargs)

            return cast(F, sync_wrapper)

        if func is not None:
            return decorator(func)
        return decorator


_DEFAULT_GUARD = CapabilityGuard()


@overload
def protect_tool[F: Callable[..., Any]](func: F) -> F: ...


@overload
def protect_tool[F: Callable[..., Any]](
    func: None = None, *, schema_model: type[BaseModel] | None = None
) -> Callable[[F], F]: ...


def protect_tool[F: Callable[..., Any]](
    func: F | None = None,
    *,
    schema_model: type[BaseModel] | None = None,
) -> F | Callable[[F], F]:
    """Module-level decorator using default CapabilityGuard."""
    if func is not None:
        return _DEFAULT_GUARD.protect_tool(func)
    return _DEFAULT_GUARD.protect_tool(None, schema_model=schema_model)
