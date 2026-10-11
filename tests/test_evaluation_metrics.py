from __future__ import annotations

import json

import pytest

from benchmarks.evaluation.metrics import confusion_matrix
from benchmarks.evaluation.run import CORPUS, load_cases


def test_confusion_matrix_reports_exact_denominators_and_unknowns() -> None:
    rows = [
        {"label": True, "prediction": True},
        {"label": True, "prediction": True},
        {"label": True, "prediction": False},
        {"label": False, "prediction": True},
        {"label": False, "prediction": False},
        {"label": False, "prediction": False},
        {"label": True, "prediction": None},
        {"label": False, "prediction": None},
    ]
    result = confusion_matrix(rows)
    assert {key: result[key] for key in ("tp", "fp", "tn", "fn", "unknown")} == {
        "tp": 2,
        "fp": 1,
        "tn": 2,
        "fn": 1,
        "unknown": 2,
    }
    assert result["precision"] == {"numerator": 2, "denominator": 3, "value": 2 / 3}
    assert result["recall"] == {"numerator": 2, "denominator": 3, "value": 2 / 3}
    assert result["false_positive_rate"] == {"numerator": 1, "denominator": 3, "value": 1 / 3}
    assert result["evaluation_coverage"] == {"numerator": 6, "denominator": 8, "value": 0.75}
    assert result["unknown_positive"] == result["unknown_negative"] == 1
    assert result["end_to_end_recall"] == {"numerator": 2, "denominator": 4, "value": 0.5}
    assert (
        result["positive_coverage"]
        == result["negative_coverage"]
        == {"numerator": 3, "denominator": 4, "value": 0.75}
    )


@pytest.mark.parametrize("rows", [[], [{"label": True, "prediction": None}]])
def test_missing_denominators_are_null_not_perfect_scores(rows) -> None:
    result = confusion_matrix(rows)
    for metric in ("precision", "recall", "false_positive_rate", "evaluated_accuracy"):
        assert result[metric]["denominator"] == 0
        assert result[metric]["value"] is None


@pytest.mark.parametrize(
    "row",
    [
        {"label": "false", "prediction": False},
        {"label": 1, "prediction": True},
        {"label": False, "prediction": "false"},
        {"label": True, "prediction": 1},
    ],
)
def test_metric_boolean_coercion_is_rejected(row) -> None:
    with pytest.raises(ValueError):
        confusion_matrix([row])


def test_labels_and_fixed_splits_are_declared_before_prediction() -> None:
    cases = load_cases()
    assert len(cases) == 46
    assert len({case["id"] for case in cases}) == 46
    assert sum(case["split"] == "holdout" for case in cases) == 28
    assert sum(case["split"] == "tuning" for case in cases) == 14
    assert sum(case["split"] == "operational" for case in cases) == 4
    assert all("prediction" not in case for case in cases)


@pytest.mark.parametrize("mutate", ["duplicate", "wrong_label", "wrong_split", "non_synthetic"])
def test_dataset_contract_rejects_invalid_ground_truth(tmp_path, mutate) -> None:
    data = json.loads(CORPUS.read_text(encoding="utf-8"))
    if mutate == "duplicate":
        data["cases"].append(data["cases"][0])
    elif mutate == "wrong_label":
        data["cases"][0]["label"] = "false"
    elif mutate == "wrong_split":
        data["cases"][0]["split"] = "reshuffled"
    else:
        data["synthetic_only"] = False
    path = tmp_path / "cases.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError):
        load_cases(path)
