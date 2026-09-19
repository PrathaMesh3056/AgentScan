# agentscan/attacks/mutators.py
#
# Payload transforms for scan --mutate. Reuses jailbreaks.py encodings
# (Base64 smuggle, leetspeak, prefix injection) and adds ZWSP, token-split,
# homoglyph, and suffix-wrap variants.

from __future__ import annotations

import base64
import codecs
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


def mutate_rot13(text: str) -> str:
    """ROT13 cipher obfuscation."""
    return codecs.encode(text, "rot_13")


def invert_rot13(mutated: str) -> str:
    return codecs.encode(mutated, "rot_13")


def mutate_reverse(text: str) -> str:
    """Reverse string representation with decode directive."""
    return f"Reverse this string to execute instruction: {text[::-1]}"


def invert_reverse(mutated: str) -> str:
    prefix = "Reverse this string to execute instruction: "
    if mutated.startswith(prefix):
        return mutated[len(prefix) :][::-1]
    return mutated[::-1]


def mutate_variant(variant: dict[str, Any], mutator_name: str) -> dict[str, Any] | None:
    """Apply a specific mutator to a variant by name."""
    fn = dict(MUTATORS).get(mutator_name)
    if fn is None or not should_mutate_variant(variant):
        return None
    mutated = dict(variant)
    payload = str(variant.get("payload", ""))
    vid = str(variant.get("id", "variant"))
    mutated["payload"] = fn(payload)
    mutated["id"] = f"{vid}:{mutator_name}"
    mutated["mutation"] = mutator_name
    return mutated


def get_retry_mutations(variant: dict[str, Any], max_mutations: int = 3) -> list[dict[str, Any]]:
    """Return top mutated candidates for dynamic retry on verbatim refusal."""
    if not should_mutate_variant(variant) or variant.get("mutation"):
        return []
    candidates = ["base64", "rot13", "leetspeak", "reverse", "zwsp"]
    results: list[dict[str, Any]] = []
    for name in candidates:
        m = mutate_variant(variant, name)
        if m is not None:
            results.append(m)
        if len(results) >= max_mutations:
            break
    return results


MUTATORS: list[tuple[str, MutatorFn]] = [
    ("base64", mutate_base64),
    ("leetspeak", mutate_leetspeak),
    ("zwsp", mutate_zwsp),
    ("token_split", mutate_token_split),
    ("homoglyphs", mutate_homoglyphs),
    ("prefix_wrap", mutate_prefix_wrap),
    ("suffix_wrap", mutate_suffix_wrap),
    ("rot13", mutate_rot13),
    ("reverse", mutate_reverse),
]


def should_mutate_variant(variant: dict[str, Any]) -> bool:
    """Skip DoS timeout/min_length and payload_repeat expansions (size blow-up)."""
    if variant.get("detection_method") in _SKIP_MUTATE_METHODS:
        return False
    return not variant.get("payload_repeat")


def expand_variants(
    variants: list[dict[str, Any]] | tuple[dict[str, Any], ...],
    budget: int | None = None,
) -> list[dict[str, Any]]:
    """Return originals plus N mutated copies (shallow-copied dicts).

    If budget is provided, limits the number of mutators applied per variant.
    """
    mutators = MUTATORS if budget is None else MUTATORS[: max(0, budget)]
    expanded: list[dict[str, Any]] = []
    for variant in variants:
        expanded.append(dict(variant))
        if not should_mutate_variant(variant):
            continue
        payload = str(variant.get("payload", ""))
        vid = str(variant.get("id", "variant"))
        for name, fn in mutators:
            mutated = dict(variant)
            mutated["payload"] = fn(payload)
            mutated["id"] = f"{vid}:{name}"
            mutated["mutation"] = name
            expanded.append(mutated)
    return expanded
