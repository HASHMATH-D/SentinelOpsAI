"""Evaluate Strands Decider routing on synthetic SentinelOps scenarios.

This script only asks the model for a proposed first action. It does not
execute investigation tools, modify model settings, or perform containment.
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.decider_client import choose_next_action


DATA_PATH = ROOT / "data" / "security_events.json"
REPORT_DIR = ROOT / "reports"

SCENARIO_EXPECTATIONS = {
    "suspicious_login_chain": (
        "Suspicious activity with repeated failures, subsequent success, "
        "sensitive file access, and outbound network transfer."
    ),
    "benign_login": (
        "Apparently routine successful login and approved software activity."
    ),
    "uncertain_activity": (
        "Limited evidence containing a failed login and unusual process."
    ),
}


def main():
    with DATA_PATH.open(encoding="utf-8") as f:
        dataset = json.load(f)

    results = []

    for name, events in dataset["scenarios"].items():
        source_ip = events[0].get("source_ip") if events else None

        state = {
            "incident": "synthetic_security_investigation",
            "scenario": name,
            "scenario_context": SCENARIO_EXPECTATIONS.get(name, ""),
            "event_count": len(events),
            "events": events,
            "completed_actions": [],
            "remaining_actions": [
                "inspect_authentication",
                "inspect_endpoint",
                "analyze_network",
                "check_reputation",
                "correlate_events",
                "estimate_severity",
            ],
            "instruction": (
                "Select one appropriate first investigation action from "
                "the available criteria. Do not execute tools or containment. "
                "Request human review if uncertain."
            ),
        }

        try:
            decision = choose_next_action(json.dumps(state, default=str))
            result = {
                "scenario": name,
                "event_count": len(events),
                "source_ip": source_ip,
                "expected_context": SCENARIO_EXPECTATIONS.get(name, ""),
                "model": decision.get("model"),
                "model_action": decision.get("model_action"),
                "model_confidence": decision.get("model_confidence"),
                "confidence_threshold": decision.get("confidence_threshold"),
                "final_action": decision.get("final_action"),
                "requires_human_review": decision.get(
                    "requires_human_review"
                ),
                "probabilities": decision.get("probabilities", {}),
                "containment_performed": False,
                "error": None,
            }
        except Exception as exc:
            result = {
                "scenario": name,
                "event_count": len(events),
                "source_ip": source_ip,
                "error": f"{type(exc).__name__}: {exc}",
                "final_action": "request_human_review",
                "requires_human_review": True,
                "containment_performed": False,
            }

        results.append(result)

        print(f"\n--- {name} ---")
        print(f"Events: {result['event_count']}")
        print(f"Proposed action: {result.get('model_action', 'unavailable')}")
        print(f"Confidence: {result.get('model_confidence', 'n/a')}")
        print(f"Final action: {result['final_action']}")
        print(f"Human review: {result['requires_human_review']}")
        if result.get("error"):
            print(f"Error: {result['error']}")

    report = {
        "evaluation_type": "synthetic_first_action_routing",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tool_execution_performed": False,
        "containment_performed": False,
        "scenario_count": len(results),
        "results": results,
    }

    REPORT_DIR.mkdir(exist_ok=True)
    output_path = REPORT_DIR / "decider_evaluation.json"
    output_path.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print(f"\nReport saved to: {output_path}")
    print("Investigation tools executed: no")
    print("Containment performed: no")


if __name__ == "__main__":
    main()
