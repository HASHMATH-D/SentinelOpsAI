"""Evaluate prompt variants against the labelled synthetic benchmark."""

import json
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "security_benchmark.json"
OUTPUT = ROOT / "reports" / "benchmark_evaluation.json"

URL = os.getenv("DECIDER_URL", "http://127.0.0.1:8099").rstrip("/")
THRESHOLD = 0.90

ACTIONS = {
    "inspect_authentication": "Inspect authentication events and login history.",
    "inspect_endpoint": "Inspect endpoint and file-access activity.",
    "analyze_network": "Analyze network traffic and outbound transfers.",
    "check_reputation": "Check the source IP against the local synthetic reputation dataset.",
    "correlate_events": "Correlate synthetic events by time and shared indicators.",
    "estimate_severity": "Estimate severity from collected evidence.",
    "finish_investigation": "Finish when evidence is sufficient.",
    "request_human_review": "Stop and request human review."
}

PROMPTS = {
    "A_current": (
        "Choose the single best next investigation step. Consider completed "
        "steps and remaining evidence. Do not perform containment. Finish "
        "only when enough evidence exists; request human review if uncertain."
    ),
    "B_structured": (
        "Select the best next investigation action from the evidence. "
        "Prioritize authentication inspection when login failures or "
        "subsequent successful logins are relevant. Inspect endpoints for "
        "sensitive file access or unusual processes. Analyze network activity "
        "for unusual outbound transfers. Use reputation checks and event "
        "correlation to corroborate evidence. Estimate severity after gathering "
        "sufficient evidence. Never repeat completed actions. Finish only "
        "when justified; request human review when uncertain. Never perform "
        "containment or execute tools."
    ),
    "C_evidence_matched": (
        "Choose the next investigation action based on the specific events. "
        "Do not assume every scenario is malicious. "
        "If authentication failures occur, especially followed by a success, "
        "choose inspect_authentication. If the primary unresolved signal is "
        "sensitive file access or an unusual process, choose inspect_endpoint. "
        "If the primary unresolved signal is a large or unusual outbound "
        "transfer, choose analyze_network. Choose check_reputation when "
        "source-IP reputation is the most useful unresolved evidence. "
        "Choose correlate_events when cross-event relationships are the main "
        "unresolved question. Choose estimate_severity only after evidence "
        "has been collected. Choose finish_investigation only when sufficient "
        "evidence exists. Choose request_human_review if the evidence is "
        "ambiguous. Do not repeat completed actions. Do not perform containment "
        "or execute tools."
    )
}


def evaluate_one(scenario, prompt):
    state = {
        "incident": "synthetic_security_investigation",
        "scenario": scenario["scenario_id"],
        "events": scenario["events"],
        "completed_actions": [],
        "remaining_actions": list(ACTIONS),
        "instruction": "Choose one first action. This is a simulated scenario."
    }

    payload = {
        "state": json.dumps(state),
        "questions": {
            "next_action": {
                "type": "choice",
                "instructions": prompt,
                "criteria": ACTIONS
            }
        }
    }

    request = Request(
        f"{URL}/v1/systemone",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    with urlopen(request, timeout=180) as response:
        data = json.loads(response.read().decode())

    answer = data["answers"]["next_action"]
    action = answer["choice"]
    confidence = answer["confidence"]

    if action not in ACTIONS:
        raise ValueError(f"Invalid action: {action}")

    review = confidence < THRESHOLD or action == "request_human_review"

    return {
        "proposed_action": action,
        "expected_action": scenario["expected_first_action"],
        "action_correct": action == scenario["expected_first_action"],
        "confidence": confidence,
        "threshold": THRESHOLD,
        "final_action": "request_human_review" if review else action,
        "requires_human_review": review,
        "expected_review": scenario["expected_review"],
        "review_decision_matches_label": review == scenario["expected_review"],
        "probabilities": answer.get("probabilities", {}),
        "tools_executed": False,
        "containment_performed": False
    }


def summarize(results):
    successful = [r for r in results if "error" not in r]
    total = len(results)

    return {
        "scenario_count": total,
        "successful_model_calls": len(successful),
        "failed_model_calls": total - len(successful),
        "action_accuracy": (
            sum(r["action_correct"] for r in successful) / len(successful)
            if successful else None
        ),
        "human_review_rate": (
            sum(r["requires_human_review"] for r in successful) / len(successful)
            if successful else None
        ),
        "review_label_agreement": (
            sum(r["review_decision_matches_label"] for r in successful)
            / len(successful) if successful else None
        ),
        "proposed_action_counts": dict(Counter(
            r["proposed_action"] for r in successful
        ))
    }


def main():
    benchmark = json.loads(DATA.read_text(encoding="utf-8"))
    report = {
        "evaluation": "synthetic_labelled_prompt_comparison",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "confidence_threshold": THRESHOLD,
        "threshold_changed": False,
        "production_code_modified": False,
        "tools_executed": False,
        "containment_performed": False,
        "variants": {}
    }

    for variant, prompt in PROMPTS.items():
        print(f"\n===== {variant} =====")
        results = []

        for scenario in benchmark["scenarios"]:
            try:
                result = evaluate_one(scenario, prompt)
                result["scenario_id"] = scenario["scenario_id"]
                print(
                    f"{scenario['scenario_id']}: "
                    f"action={result['proposed_action']}, "
                    f"correct={result['action_correct']}, "
                    f"confidence={result['confidence']:.4f}, "
                    f"review={result['requires_human_review']}"
                )
            except Exception as exc:
                result = {
                    "scenario_id": scenario["scenario_id"],
                    "error": f"{type(exc).__name__}: {exc}"
                }
                print(f"{scenario['scenario_id']}: ERROR: {exc}")

            results.append(result)

        metrics = summarize(results)
        report["variants"][variant] = {
            "results": results,
            "metrics": metrics
        }

        print("\nMetrics:")
        print(json.dumps(metrics, indent=2))

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nSaved report: {OUTPUT}")


if __name__ == "__main__":
    main()
