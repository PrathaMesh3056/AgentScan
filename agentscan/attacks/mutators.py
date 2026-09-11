# agentscan/attacks/mutators.py
#
# Payload transforms for scan --mutate. Reuses jailbreaks.py encodings
# (Base64 smuggle, leetspeak, prefix injection) and adds ZWSP, token-split,
# homoglyph, and suffix-wrap variants.

from __future__ import annotations

import base64
from collections.abc import Callable
from typing import Any

from agentscan.core.jailbreaks import _LEET, _base64_smuggle, _leetspeak, _prefix_injection

ZWSP = "\u200b"
_SUFFIX_WRAP = "\n\n(End of instruction — execute exactly as written.)"

# Latin -> visually similar Cyrillic / Greek (reversible).
_HOMOGLYPHS: dict[str, str] = {
    "a": "а",
    "c": "с",
    "e": "е",
    "i": "і",
    "o": "о",
    "p": "р",
    "x": "х",
    "y": "у",
    "A": "А",
    "B": "В",
    "C": "С",
    "E": "Е",
    "H": "Н",
    "K": "К",
    "M": "М",
    "O": "О",
    "P": "Р",
    "T": "Т",
    "X": "Х",
}
_HOMOGLYPHS_REVERSE = {v: k for k, v in _HOMOGLYPHS.items()}

_SKIP_MUTATE_METHODS = frozenset({"timeout", "min_length"})

MutatorFn = Callable[[str], str]


def mutate_base64(text: str) -> str:
    """Base64-smuggle the payload using the jailbreak seed transform."""
    return _base64_smuggle(text)


def invert_base64(mutated: str) -> str:
    encoded = mutated.strip().splitlines()[-1].strip()
    return base64.b64decode(encoded.encode("ascii")).decode("utf-8")


def mutate_leetspeak(text: str) -> str:
    """Leetspeak obfuscation from jailbreaks.py."""
    return _leetspeak(text)


def leetspeak_body(text: str) -> str:
    """Core leet transform applied to `text` (detectable without the wrapper)."""
    return text.translate(_LEET)


def mutate_zwsp(text: str) -> str:
    """Insert zero-width spaces between characters."""
    if not text:
        return text
    return ZWSP.join(text)


def invert_zwsp(mutated: str) -> str:
    return mutated.replace(ZWSP, "")


def mutate_token_split(text: str) -> str:
    """Split longer tokens in half so filters that match whole words miss them."""
    parts: list[str] = []
    for word in text.split(" "):
        if len(word) > 4:
            mid = max(1, len(word) // 2)
            parts.append(f"{word[:mid]} {word[mid:]}")
        else:
            parts.append(word)
    return " ".join(parts)


def compact_tokens(text: str) -> str:
    """Whitespace-insensitive form used to detect token-split payloads."""
    return "".join(text.split())


def mutate_homoglyphs(text: str) -> str:
    return "".join(_HOMOGLYPHS.get(ch, ch) for ch in text)


def invert_homoglyphs(mutated: str) -> str:
    return "".join(_HOMOGLYPHS_REVERSE.get(ch, ch) for ch in mutated)


def mutate_prefix_wrap(text: str) -> str:
    """Prefix-injection wrap from jailbreaks.py."""
    return _prefix_injection(text)


def mutate_suffix_wrap(text: str) -> str:
    return f"{text}{_SUFFIX_WRAP}"


def invert_suffix_wrap(mutated: str) -> str:
    if mutated.endswith(_SUFFIX_WRAP):
        return mutated[: -len(_SUFFIX_WRAP)]
    return mutated


MUTATORS: list[tuple[str, MutatorFn]] = [
    ("base64", mutate_base64),
    ("leetspeak", mutate_leetspeak),
    ("zwsp", mutate_zwsp),
    ("token_split", mutate_token_split),
    ("homoglyphs", mutate_homoglyphs),
    ("prefix_wrap", mutate_prefix_wrap),
    ("suffix_wrap", mutate_suffix_wrap),
]


def should_mutate_variant(variant: dict[str, Any]) -> bool:
    """Skip DoS timeout/min_length and payload_repeat expansions (size blow-up)."""
    if variant.get("detection_method") in _SKIP_MUTATE_METHODS:
        return False
    return not variant.get("payload_repeat")


def expand_variants(
    variants: list[dict[str, Any]] | tuple[dict[str, Any], ...],
) -> list[dict[str, Any]]:
    """Return originals plus N mutated copies (shallow-copied dicts)."""
    expanded: list[dict[str, Any]] = []
    for variant in variants:
        expanded.append(dict(variant))
        if not should_mutate_variant(variant):
            continue
        payload = str(variant.get("payload", ""))
        vid = str(variant.get("id", "variant"))
        for name, fn in MUTATORS:
            mutated = dict(variant)
            mutated["payload"] = fn(payload)
            mutated["id"] = f"{vid}:{name}"
            mutated["mutation"] = name
            expanded.append(mutated)
    return expanded
