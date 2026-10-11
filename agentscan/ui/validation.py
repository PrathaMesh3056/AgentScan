"""Strict dashboard field validation with safe, actionable error messages.

Never include rejected input or Pydantic's ``input``/``ctx`` values in a response.
Defaults apply to omitted fields; explicitly empty fields must be corrected.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlsplit

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError


def validation_error_response(errors: dict[str, str], status: int = 400) -> JSONResponse:
    return JSONResponse(
        {
            "error": "Correct the highlighted fields: " + ", ".join(errors) + ".",
            "field_errors": errors,
        },
        status_code=status,
    )


def model_field_errors(error: ValidationError) -> dict[str, str]:
    """Translate model locations without exposing input, secret values or exception context."""
    errors: dict[str, str] = {}
    for item in error.errors(include_url=False, include_context=False, include_input=False):
        field = ".".join(str(part) for part in item["loc"]) or "analysis_mode"
        errors[field] = "Choose a valid value for this field."
    return errors


class Fields:
    """Collect all field errors before an operation is allowed to start."""

    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = payload
        self.errors: dict[str, str] = {}

    def value(self, key: str, default: Any = None, aliases: tuple[str, ...] = ()) -> Any:
        for name in (key, *aliases):
            if name in self.payload:
                return self.payload[name]
        return default

    def text(
        self,
        key: str,
        *,
        default: str | None = None,
        required: bool = False,
        max_length: int = 65536,
        aliases: tuple[str, ...] = (),
    ) -> str | None:
        value = self.value(key, default, aliases)
        if value is None:
            if required:
                self.errors[key] = "This field is required."
            return None
        if not isinstance(value, str):
            self.errors[key] = "Enter text for this field."
            return None
        value = value.strip()
        if not value:
            if required:
                self.errors[key] = "This field is required."
            return None
        if len(value) > max_length or "\x00" in value:
            self.errors[key] = (
                f"Use text of at most {max_length} characters without null characters."
            )
            return None
        return value

    def header(self, key: str) -> str | None:
        raw = self.value(key)
        if isinstance(raw, str) and any(ord(char) < 32 or ord(char) > 126 for char in raw):
            self.errors[key] = (
                "Use a target authentication header without control characters or non-ASCII text."
            )
            return None
        value = self.text(key, max_length=4096)
        if value is None:
            return None
        if ":" in value:
            name, _, content = value.partition(":")
            if (
                not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name.strip())
                or not content.strip()
            ):
                self.errors[key] = (
                    "Use a valid header name followed by a nonempty value, for example Authorization: Bearer token."
                )
                return None
        return value

    def choice(self, key: str, choices: tuple[str, ...], *, default: str) -> str:
        value = self.value(key, default)
        if not isinstance(value, str) or value not in choices:
            self.errors[key] = "Choose one of the available options."
            return default
        return value

    def integer(
        self,
        key: str,
        minimum: int,
        maximum: int,
        *,
        default: int | None = None,
        aliases: tuple[str, ...] = (),
    ) -> int | None:
        value = self.value(key, default, aliases)
        if (
            value is None
            and default is None
            and not any(name in self.payload for name in (key, *aliases))
        ):
            return None
        if type(value) is not int or not minimum <= value <= maximum:
            self.errors[key] = f"Enter a whole number between {minimum} and {maximum}."
            return default
        return value

    def boolean(self, key: str, *, default: bool = False) -> bool:
        value = self.value(key, default)
        if type(value) is not bool:
            self.errors[key] = "Choose a checked or unchecked value."
            return default
        return value

    def object(self, key: str, *, required: bool = False) -> dict[str, Any]:
        value = self.value(key, {} if not required else None)
        if not isinstance(value, dict) or (required and not value):
            self.errors[key] = "Enter a JSON object" + (
                " with the required data." if required else "."
            )
            return {}
        if isinstance(value, dict):
            try:
                if (
                    len(json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8"))
                    > 65536
                ):
                    self.errors[key] = "Use a JSON object smaller than 64 KB."
                    return {}
            except (ValueError, TypeError):
                self.errors[key] = "Use a valid JSON object with finite numeric values."
                return {}
        return value

    def url(
        self,
        key: str,
        *,
        required: bool = True,
        schemes: tuple[str, ...] = ("http", "https"),
        aliases: tuple[str, ...] = (),
    ) -> str | None:
        value = self.text(key, required=required, max_length=4096, aliases=aliases)
        if value is None:
            return None
        if any(char.isspace() or ord(char) < 32 for char in value) or "\\" in value:
            self.errors[key] = "Enter a URL without spaces, control characters or backslashes."
            return None
        normalized = value if "://" in value else "http://" + value
        try:
            parsed = urlsplit(normalized)
            port = parsed.port
            if (
                parsed.scheme.lower() not in schemes
                or not parsed.hostname
                or parsed.hostname.startswith(".")
                or (port is not None and port == 0)
            ):
                raise ValueError
            if parsed.username is not None or parsed.password is not None:
                self.errors[key] = (
                    "Use a URL without credentials; configure target authentication separately."
                )
                return None
            if parsed.fragment:
                self.errors[key] = "Remove the URL fragment; enter the actual service endpoint."
                return None
        except ValueError:
            self.errors[key] = "Enter a valid endpoint using " + ", ".join(schemes) + "."
            return None
        return normalized

    def analysis(self, *, model_alias: str | None = None) -> dict[str, str]:
        mode = self.choice(
            "analysis_mode", ("deterministic", "local", "external"), default="deterministic"
        )
        classification = self.choice(
            "data_classification", ("sensitive", "non_sensitive"), default="sensitive"
        )
        # Inactive analysis controls are hidden and must not block a valid submission.
        local = "ollama/llama3.2"
        external = ""
        if mode == "local":
            local = (
                self.text(
                    "local_model", default=model_alias or local, required=True, max_length=136
                )
                or ""
            )
            if (
                not re.fullmatch(r"ollama/[A-Za-z0-9_.:/-]{1,128}", local)
                or "cloud" in local.lower()
            ):
                self.errors["local_model"] = (
                    "Enter an installed offline model as ollama/model-name."
                )
        elif mode == "external":
            external = (
                self.text(
                    "external_model", default=model_alias or "", required=True, max_length=140
                )
                or ""
            )
            if classification != "non_sensitive":
                self.errors["data_classification"] = (
                    "External analysis requires an explicit non-sensitive designation."
                )
            if not re.fullmatch(r"(?:openai|anthropic|gemini)/[A-Za-z0-9._-]{1,128}", external):
                self.errors["external_model"] = "Enter a supported provider/model ID."
        return {
            "analysis_mode": mode,
            "data_classification": classification,
            "local_model": local or "ollama/llama3.2",
            "external_model": external or "",
        }

    def response(self) -> JSONResponse | None:
        return validation_error_response(self.errors) if self.errors else None


def directory_field(request: Request, value: str | None, field: str = "path") -> JSONResponse | str:
    """Check a scoped existing directory only after lexical fields have passed."""
    from agentscan.ui.security import project_path

    try:
        path = project_path(request, value or "")
    except HTTPException as error:
        return validation_error_response(
            {field: "Choose a path within the configured project."}, error.status_code
        )
    except (ValueError, OSError):
        return validation_error_response({field: "Choose a valid project directory."})
    if not path.is_dir():
        return validation_error_response({field: "Choose an existing project directory."})
    return str(path)
