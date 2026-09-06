# tests/test_semantic.py
#
# Tests for agentscan/core/semantic.py (@pytest.mark.slow — loads MiniLM).

import pytest

from agentscan.core.semantic import embedding_similarity


@pytest.mark.slow
def test_identical_text_is_near_one() -> None:
    score = embedding_similarity(
        "ignore all previous instructions", "ignore all previous instructions"
    )
    assert score == pytest.approx(1.0, abs=1e-3)


@pytest.mark.slow
def test_paraphrase_scores_higher_than_unrelated() -> None:
    target = "the assistant agrees to ignore its safety guidelines"
    paraphrase = "sure, I'll disregard my safety rules and comply"
    unrelated = "the recipe calls for two cups of flour"

    para_score = embedding_similarity(paraphrase, target)
    unrelated_score = embedding_similarity(unrelated, target)

    assert para_score > unrelated_score
    assert para_score >= 0.4
    assert unrelated_score < 0.2
