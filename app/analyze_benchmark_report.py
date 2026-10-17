"""Analyze saved synthetic benchmark results without calling the model."""

import json
from collections import Counter
from pathlib import Path
from statistics import mean

ROOT = Path(__file__).resolve().parents[1]
REPORT_PATH = ROOT / "reports" / "extended_benchmark_evaluation.json"
OUTPUT_PATH = ROOT / "reports" / "extended_benchmark_analysis.json"


def analyze_variant(name, variant):
    results = [
        item for item in variant["results"]
        if "error" not in item
    ]

    expected = Counter(item["expected_action"] for item in results)
    predicted = Counter(item["proposed_action"] for item in results)
    correct = Counter(
        item["expected_action"]
        for item in results
        if item["action_correct"]
    )

    actions = sorted(set(expected) | set(predicted))
    per_action = {}

    for action in actions:
        tp = correct[action]
        fp = predicted[action] - tp
        fn = expected[action] - tp

        per_action[action] = {
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / (tp + fn) if tp + fn else None,
        }

    confidences = [item["confidence"] for item in results]
    threshold = 0.90
    predicted_review = [
        item["requires_human_review"] for item in results
    ]
    expected_review = [
        item["expected_review"] for item in results
    ]

    review_tp = sum(p and e for p, e in zip(predicted_review, expected_review))
    review_fp = sum(p and not e for p, e in zip(predicted_review, expected_review))
    review_fn = sum(not p and e for p, e in zip(predicted_review, expected_review))

    return {
        "scenario_count": len(results),
        "action_accuracy": (
            sum(item["action_correct"] for item in results) / len(results)
            if results else None
        ),
        "confidence": {
            "mean": mean(confidences) if confidences else None,
            "minimum": min(confidences) if confidences else None,
            "maximum": max(confidences) if confidences else None,
            "at_or_above_threshold": sum(
                value >= threshold for value in confidences
            ),
            "threshold": threshold,
        },
        "human_review": {
            "review_rate": (
                sum(predicted_review) / len(results) if results else None
            ),
            "label_agreement": (
                sum(p == e for p, e in zip(predicted_review, expected_review))
                / len(results) if results else None
            ),
            "false_review_count": review_fp,
            "missed_review_count": review_fn,
            "precision": (
                review_tp / (review_tp + review_fp)
                if review_tp + review_fp else None
            ),
            "recall": (
                review_tp / (review_tp + review_fn)
                if review_tp + review_fn else None
            ),
        },
        "per_action": per_action,
        "warning": (
            "Metrics are based on provisional synthetic labels. "
            "They do not establish real-world detection performance."
        ),
    }


def main():
    report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
    analysis = {
        "source_report": str(REPORT_PATH.relative_to(ROOT)),
        "variants": {},
    }

    for name, variant in report["variants"].items():
        analysis["variants"][name] = analyze_variant(name, variant)

    OUTPUT_PATH.write_text(
        json.dumps(analysis, indent=2), encoding="utf-8"
    )

    for name, result in analysis["variants"].items():
        print(f"\n===== {name} =====")
        print("Action accuracy:", result["action_accuracy"])
        print("Confidence:", json.dumps(result["confidence"], indent=2))
        print("Human review:", json.dumps(result["human_review"], indent=2))
        print("Per-action precision/recall:")
        print(json.dumps(result["per_action"], indent=2))

    print(f"\nSaved analysis: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
