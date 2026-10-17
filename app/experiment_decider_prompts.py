"""Compare two Strands Decider prompts on synthetic security scenarios.

No investigation tools are executed. No containment is performed.
Production client and confidence threshold remain unchanged.
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "data" / "security_events.json"
OUTPUT_PATH = ROOT / "reports" / "decider_prompt_ab.json"

DECIDER_URL = os.getenv("DECIDER_URL", "http://127.0.0.1:8099")
CONFIDENCE_THRESHOLD = 0.90

ACTIONS = {
    "inspect_authentication":
        "Inspect authentication events and login history.",
    "inspect_endpoint":
        "Inspect endpoint and file-access activity.",
    "analyze_network":
        "Analyze network traffic and outbound transfers.",
    "check_reputation":
        "Check the source IP against the local synthetic reputation dataset.",
    "correlate_events":
        "Correlate synthetic events by time and shared indicators.",
    "estimate_severity":
        "Estimate incident severity from collected evidence.",
    "finish_investigation":
        "Finish when sufficient evidence has been gathered.",
    "request_human_review":
        "Stop and request human review."
}

PROMPTS = {
    "A_current": (
        "Choose the single best next investigation step. "
        "Consider completed steps and remaining evidence. "
        "Do not perform containment. Finish only when enough "
        "evidence exists; request human review if uncertain."
    ),
    "B_structured": (
        "Select exactly one next investigation action using the "
        "provided evidence. Prioritize actions that resolve the "
        "most important unanswered questions. "
        "1. For failed logins followed by a successful login, inspect "
        "authentication first. "
        "2. For sensitive file access, inspect endpoint activity. "
        "3. For unusual outbound transfers, analyze network activity. "
        "4. Use reputation checks and event correlation to corroborate "
        "suspicious indicators. "
        "5. Estimate severity after enough evidence has been gathered. "
        "6. Finish only when the available evidence is sufficient. "
        "7. Request human review when evidence is ambiguous or the "
        "best action cannot be determined confidently. "
        "Never repeat a completed action. Choose only from the supplied "
        "options. Do not perform containment or execute tools."
    )
}

SCENARIO_CONTEXT = {
    "suspicious_login_chain":
        "Repeated authentication failures followed by a success, "
        "sensitive file access, and a large outbound transfer.",
    "benign_login":
        "A successful login and approved software activity with "
        "no obvious malicious evidence in this scenario.",
    "uncertain_activity":
        "A failed login and unusual process, with limited evidence."
}


def call_decider(state, instructions):
    payload = {
        "state": json.dumps(state, ensure_ascii=False),
        "questions": {
            "next_action": {
                "type": "choice",
                "instructions": instructions,
                "criteria": ACTIONS
            }
        }
    }

    request = Request(
        f"{DECIDER_URL.rstrip('/')}/v1/systemone",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    with urlopen(request, timeout=180) as response:
        data = json.loads(response.read().decode("utf-8"))

    answer = data.get("answers", {}).get("next_action", {})
    action = answer.get("choice")
    confidence = answer.get("confidence")
    probabilities = answer.get("probabilities", {})

    if action not in ACTIONS:
        raise ValueError(f"Unexpected action: {action!r}")

    if not isinstance(confidence, (int, float)):
        raise ValueError(f"Invalid confidence: {confidence!r}")

    if not isinstance(probabilities, dict):
        raise ValueError("Missing or invalid probability distribution")

    review = confidence < CONFIDENCE_THRESHOLD or (
        action == "request_human_review"
    )

    return {
        "model": data.get("model"),
        "proposed_action": action,
        "confidence": confidence,
        "confidence_threshold": CONFIDENCE_THRESHOLD,
        "final_action": "request_human_review" if review else action,
        "requires_human_review": review,
        "probabilities": probabilities,
        "usage": data.get("usage", {}),
        "containment_performed": False,
        "tools_executed": False
    }


def main():
    with DATA_PATH.open(encoding="utf-8") as file:
        dataset = json.load(file)

    report = {
        "experiment": "prompt_A_B_first_action_comparison",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "endpoint": DECIDER_URL,
        "threshold_changed": False,
        "production_code_modified": False,
        "tools_executed": False,
        "containment_performed": False,
        "scenarios": {}
    }

    for scenario_name, events in dataset["scenarios"].items():
        state = {
            "incident": "synthetic_security_investigation",
            "scenario": scenario_name,
            "scenario_context": SCENARIO_CONTEXT.get(
                scenario_name, ""
            ),
            "events": events,
            "completed_actions": [],
            "remaining_actions": list(ACTIONS.keys()),
            "instruction": (
                "Evaluate the evidence and choose the next action. "
                "This is a simulated scenario."
            )
        }

        scenario_result = {
            "event_count": len(events),
            "variants": {}
        }

        print(f"\n===== {scenario_name} =====")

        for variant, instructions in PROMPTS.items():
            try:
                result = call_decider(state, instructions)
                scenario_result["variants"][variant] = result

                print(
                    f"{variant}: proposed={result['proposed_action']}, "
                    f"confidence={result['confidence']:.4f}, "
                    f"final={result['final_action']}"
                )

                top_probabilities = sorted(
                    result["probabilities"].items(),
                    key=lambda item: item[1],
                    reverse=True
                )[:3]

                print("  Top probabilities:", top_probabilities)

            except (HTTPError, URLError, TimeoutError, ValueError) as exc:
                error_result = {
                    "error": f"{type(exc).__name__}: {exc}",
                    "final_action": "request_human_review",
                    "requires_human_review": True,
                    "tools_executed": False,
                    "containment_performed": False
                }
                scenario_result["variants"][variant] = error_result
                print(f"{variant}: ERROR — {exc}")

        report["scenarios"][scenario_name] = scenario_result

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8"
    )

    print(f"\nReport saved to: {OUTPUT_PATH}")
    print("Production code modified: no")
    print("Investigation tools executed: no")
    print("Containment performed: no")


if __name__ == "__main__":
    main()
