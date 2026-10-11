"""Exact case-level denominators, with operationally unknown cases separated."""

from __future__ import annotations

from collections import Counter
from typing import Any


def confusion_matrix(rows: list[dict[str, Any]]) -> dict[str, Any]:
    counts = Counter({key: 0 for key in ("tp", "fp", "tn", "fn", "unknown")})
    unknown_positive = unknown_negative = 0
    for row in rows:
        label = row["label"]
        if type(label) is not bool:
            raise ValueError("Ground-truth labels must be real booleans.")
        prediction = row["prediction"]
        if prediction is None:
            counts["unknown"] += 1
            unknown_positive += int(label)
            unknown_negative += int(not label)
        elif type(prediction) is not bool:
            raise ValueError("Predictions must be boolean or None for unknown.")
        else:
            counts[
                "tp" if label and prediction else "fn" if label else "fp" if prediction else "tn"
            ] += 1
    tp, fp, tn, fn = (counts[key] for key in ("tp", "fp", "tn", "fn"))
    known = tp + fp + tn + fn

    def ratio(numerator: int, denominator: int) -> dict[str, Any]:
        return {
            "numerator": numerator,
            "denominator": denominator,
            "value": numerator / denominator if denominator else None,
        }

    return {
        **dict(counts),
        "total": len(rows),
        "evaluated": known,
        "unknown_positive": unknown_positive,
        "unknown_negative": unknown_negative,
        "precision": ratio(tp, tp + fp),
        "recall": ratio(tp, tp + fn),
        "false_positive_rate": ratio(fp, fp + tn),
        "evaluated_accuracy": ratio(tp + tn, known),
        "evaluation_coverage": ratio(known, len(rows)),
        "positive_coverage": ratio(tp + fn, tp + fn + unknown_positive),
        "negative_coverage": ratio(fp + tn, fp + tn + unknown_negative),
        "end_to_end_recall": ratio(tp, tp + fn + unknown_positive),
        "unknown_rate": ratio(counts["unknown"], len(rows)),
    }
