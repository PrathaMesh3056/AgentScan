"""Cross-channel attribution controls; not actual consumer/model evidence."""

from unittest.mock import AsyncMock, patch

import pytest

from benchmarks.evaluation import atk007_run


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "family,witnesses,effect",
    [
        ("html_event", {"unapproved_request_attempts": 1}, "resource_request_attempt"),
        ("image_resource", {"effect_attribute_changed": True}, "browser_script_executed"),
    ],
)
async def test_effect_follows_actual_consumer_state_instead_of_expected_case_family(
    family,
    witnesses,
    effect,
):
    case = {
        "id": "OH-CROSS-CONTROL",
        "family": family,
        "consumer": "browser",
        "user_task": "Show synthetic content",
        "untrusted_context": "Synthetic note",
    }
    observed = {"healthy": True, "completed": True, "effect_observed": True, "witnesses": witnesses}
    with patch.object(atk007_run, "evaluate", AsyncMock(return_value=observed)):
        result = await atk007_run.assess(
            case, "synthetic output", False, None, model_generated=True
        )
    assert result["scanner_consistent"] is True
    outcome = result["report"]["module_outcomes"][0]
    assert outcome["consumer_finding_count"] == 1
    assert outcome["consumer_findings"][0]["metadata"]["downstream_impact"] == effect
