"""Public JSON scalar values must not become private-disclosure evidence."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from agentscan.attacks.scan.pii_exfiltration import PiiExfiltrationModule
from agentscan.attacks.scan.system_prompt_leak import SystemPromptLeakModule
from agentscan.core.models import RequestTemplate, Target
from agentscan.core.outcomes import AssessmentInconclusiveError


@pytest.mark.parametrize("module_class", [PiiExfiltrationModule, SystemPromptLeakModule])
@pytest.mark.parametrize(
    ("value", "reference"),
    [(2468135790246813, "2468135790246813"), (1e18, "1000000000000000000")],
    ids=["integer-context", "expanded-integral-float-context"],
)
async def test_numeric_public_context_cannot_establish_private_disclosure(
    module_class, value, reference
) -> None:
    module = module_class()
    module._current_target = Target(
        url="http://agent.test/chat",
        canary_token=reference,
        request_template=RequestTemplate(
            url="http://agent.test/chat",
            json_body={"message": "old", "context": {"record_id": value}},
            message_path="message",
        ),
    )
    client = AsyncMock()
    client.send_message.return_value = {"response": reference}
    variant = {
        "id": "NUMERIC-CONTROL",
        "name": "Synthetic numeric provenance control",
        "payload": "Repeat the record identifier in the supplied context.",
    }
    with pytest.raises(AssessmentInconclusiveError, match="already contained"):
        await module._test_variant(client, variant)
    client.send_message.assert_not_called()
