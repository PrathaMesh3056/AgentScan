"""Bounded public-input inspection for known-reference disclosure assessments."""

from __future__ import annotations

import copy
import json
import math
from typing import TYPE_CHECKING, Any

from agentscan.core.connectors.base import set_by_path
from agentscan.core.outcomes import AssessmentInconclusiveError

if TYPE_CHECKING:
    from agentscan.core.models import Target


def user_message_input(target: Target | None, payload_text: str) -> str:
    """Collect text supplied in the actual user-message request body.

    Mirror captured HTTP message replacement without modifying the profile.
    Browser selection takes precedence over a captured request. This inspection
    cannot establish what a remote server puts into the model's hidden context.
    """
    if target is None or target.browser or target.request_template is None:
        return payload_text
    template = target.request_template
    body = copy.deepcopy(template.json_body)
    set_by_path(body, template.message_path, payload_text)
    fragments: list[str] = []
    pending: list[Any] = [body]
    size = 0
    nodes = 0
    while pending:
        item = pending.pop()
        nodes += 1
        if nodes > 4096:
            raise AssessmentInconclusiveError(
                "Captured request exceeds the provenance assessment bound."
            )
        if isinstance(item, str):
            size += len(item) + 1
            if size > 100_000:
                raise AssessmentInconclusiveError(
                    "Captured request exceeds the provenance assessment bound."
                )
            fragments.append(item)
        elif isinstance(item, dict):
            pending.extend(item.keys())
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
        elif isinstance(item, int | float) or item is None:
            # JSON numbers are supplied data too. An integral float may be
            # rendered in decimal by the target even if JSON used exponent
            # notation; neither spelling establishes a private disclosure.
            pending.append(json.dumps(item))
            if isinstance(item, float) and math.isfinite(item) and item.is_integer():
                pending.append(format(item, ".0f"))
    return "\n".join(fragments)
