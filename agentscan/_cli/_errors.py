# agentscan/_cli/_errors.py
#
# Small, shared CLI input-error helpers. These turn expected operator mistakes
# (missing files, malformed YAML/JSON, wrong field types, absent optional
# dependencies) into bounded Typer usage errors that name the input.

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer
from pydantic import ValidationError


def read_text_file(path: Path, *, role: str) -> str:
    """Read operator text as UTF-8, accepting a leading UTF-8 BOM."""
    try:
        return path.read_text(encoding="utf-8-sig")
    except FileNotFoundError:
        raise typer.BadParameter(f"{role} not found: {path}") from None
    except IsADirectoryError:
        raise typer.BadParameter(f"{role} is a directory, not a file: {path}") from None
    except UnicodeDecodeError:
        raise typer.BadParameter(f"{role} is not valid UTF-8 text: {path}") from None
    except OSError as exc:
        detail = exc.strerror or type(exc).__name__
        raise typer.BadParameter(f"{role} could not be read: {path} ({detail})") from None


def load_json_file(
    path: Path,
    *,
    role: str,
    expected: type[Any] | None = None,
) -> Any:
    """Load a JSON file with path/line/column context and optional shape check."""
    text = read_text_file(path, role=role)
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise typer.BadParameter(
            f"{role} is not valid JSON: {path} (line {exc.lineno}, column {exc.colno}: {exc.msg})"
        ) from None

    if expected is dict and not isinstance(data, dict):
        raise typer.BadParameter(f"{role} must contain a JSON object: {path}")
    if expected is list and not isinstance(data, list):
        raise typer.BadParameter(f"{role} must contain a JSON array: {path}")
    return data


def validation_field_error(exc: ValidationError, *, prefix: str = "") -> tuple[str, str]:
    """Return the first Pydantic error as (dotted field, message)."""
    errors = exc.errors()
    if not errors:
        return prefix or "<root>", "invalid value"
    first = errors[0]
    location = ".".join(str(part) for part in first.get("loc", ()))
    field = ".".join(part for part in (prefix, location) if part) or "<root>"
    return field, str(first.get("msg", "invalid value"))


def integer_field(value: Any, *, field: str, source: str) -> int:
    """Coerce an operator-supplied integer field, naming the field on failure."""
    if isinstance(value, bool):
        raise typer.BadParameter(f"Field '{field}' in {source} must be an integer.")
    try:
        return int(value)
    except (TypeError, ValueError):
        raise typer.BadParameter(
            f"Field '{field}' in {source} must be an integer, got {value!r}."
        ) from None


def path_field(value: Any, *, field: str, source: str) -> Path:
    """Coerce an operator-supplied path field, naming the field on failure."""
    if isinstance(value, Path):
        return value
    if isinstance(value, str) and value.strip():
        return Path(value)
    raise typer.BadParameter(f"Field '{field}' in {source} must be a non-empty file path.")


def text_field(value: Any, *, field: str, source: str) -> str:
    """Require a scalar string field, naming the field on failure."""
    if isinstance(value, str):
        return value
    raise typer.BadParameter(f"Field '{field}' in {source} must be a string.")


def yaml_error_detail(exc: Exception) -> str:
    """Compact YAML problem plus 1-based line/column when available."""
    text = str(exc).strip()
    problem = getattr(exc, "problem", None) or (text.splitlines()[0] if text else "invalid YAML")
    mark = getattr(exc, "problem_mark", None)
    if mark is not None:
        return f"line {mark.line + 1}, column {mark.column + 1}: {problem}"
    return str(problem)
