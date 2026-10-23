"""Validate bounded ATK-011 coverage before presenting language comparisons."""

from __future__ import annotations

from typing import Any

MULTILINGUAL_SCOPE = "multilingual_complete_known_reference"
LANGUAGE_SCRIPTS = {
    "en": "Latn",
    "zh": "Hans",
    "ru": "Cyrl",
    "ar": "Arab",
    "hi": "Deva",
    "es": "Latn",
    "zh-en": "Hans-Latn",
    "hi-Latn": "Latn",
    "es-en": "Latn",
    "bn": "Beng",
    "und": "Zyyy",
}
_COUNTS = (
    "selected_tests",
    "evaluated_tests",
    "findings",
    "inconclusive_tests",
    "error_tests",
    "not_run_tests",
)


def language_coverage(outcome: Any) -> list[dict[str, Any]] | None:
    """Return only consistent public counters; unavailable is distinct from zero."""
    if (
        not isinstance(outcome, dict)
        or outcome.get("module_id") != "ATK-011"
        or outcome.get("assessment_scope") != MULTILINGUAL_SCOPE
    ):
        return None
    rows = outcome.get("language_outcomes")
    if not isinstance(rows, list) or not 1 <= len(rows) <= len(LANGUAGE_SCRIPTS):
        return None
    totals = [outcome.get("selected_tests"), outcome.get("executed_tests")]
    if any(type(value) is not int or not 0 <= value <= 1_000_000 for value in totals):
        return None
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            return None
        language = row.get("language")
        if (
            not isinstance(language, str)
            or language not in LANGUAGE_SCRIPTS
            or language in seen
            or row.get("script") != LANGUAGE_SCRIPTS[language]
        ):
            return None
        values: dict[str, int] = {}
        for key in _COUNTS:
            value = row.get(key)
            if type(value) is not int or not 0 <= value <= 1_000_000:
                return None
            values[key] = value
        if (
            values["selected_tests"]
            != sum(
                values[key]
                for key in ("evaluated_tests", "inconclusive_tests", "error_tests", "not_run_tests")
            )
            or values["findings"] > values["evaluated_tests"]
        ):
            return None
        seen.add(language)
        result.append({"language": language, "script": LANGUAGE_SCRIPTS[language], **values})
    if (
        sum(row["selected_tests"] for row in result) != totals[0]
        or sum(row["evaluated_tests"] for row in result) != totals[1]
    ):
        return None
    return result
