"""HTTP client for the local Strands Decider model."""

import json
import os
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

DECIDER_URL = os.getenv("DECIDER_URL", "http://127.0.0.1:8099")
CONFIDENCE_THRESHOLD = 0.90

INVESTIGATION_ACTIONS = {
    "inspect_authentication": "Inspect authentication events and login history.",
    "inspect_endpoint": "Inspect endpoint and file-access activity.",
    "analyze_network": "Analyze network traffic and outbound transfers.",
    "check_reputation": "Check the source IP against the local synthetic reputation dataset.",
    "correlate_events": "Correlate synthetic events by time and shared indicators.",
    "estimate_severity": "Estimate incident severity from the collected evidence.",
    "finish_investigation": "Finish when sufficient evidence has been gathered.",
    "request_human_review": "Stop and request human review.",
}


def choose_next_action(state: str, timeout: int = 120) -> dict:
    """Ask Decider for one action; gate low-confidence choices."""
    if not isinstance(state, str) or not state.strip():
        raise ValueError("state must be a non-empty string")

    payload = {
        "state": state,
        "questions": {
            "next_action": {
                "type": "choice",
                "instructions": (
                    "Select the best next investigation action from the "
                    "provided evidence and current state. Read "
                    "evidence_router_advice, including ranked_actions and "
                    "their reasons, as advisory evidence for prioritizing the "
                    "next action. Prefer the highest-ranked eligible action "
                    "when its reasons are supported by the actual events. "
                    "The router is advisory only: independently consider the "
                    "events, evidence_history, and completed_actions. Never "
                    "repeat completed actions. Prioritize authentication "
                    "inspection for relevant login failures or failure followed "
                    "by success; endpoint inspection for sensitive file access "
                    "or unusual processes; network analysis for unusual outbound "
                    "transfers; and event correlation when multiple signal "
                    "categories occur. Use reputation checks to corroborate "
                    "indicators and estimate severity when sufficient evidence "
                    "exists. Choose only from the supplied options. Finish only "
                    "when justified; request human review when uncertain. "
                    "Never perform containment or execute actions outside the "
                    "supplied tools."
                ),
                "criteria": INVESTIGATION_ACTIONS,
            }
        },
    }

    request = Request(
        f"{DECIDER_URL.rstrip('/')}/v1/systemone",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urlopen(request, timeout=timeout) as response:
            result = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        raise RuntimeError(
            f"Decider HTTP {exc.code}: "
            f"{exc.read().decode('utf-8', errors='replace')}"
        ) from exc
    except URLError as exc:
        raise RuntimeError(
            f"Cannot reach Decider at {DECIDER_URL}; check the server."
        ) from exc

    answer = result.get("answers", {}).get("next_action", {})
    action = answer.get("choice")
    confidence = answer.get("confidence")

    if action not in INVESTIGATION_ACTIONS:
        raise RuntimeError(f"Invalid Decider action: {action!r}")
    if (
        not isinstance(confidence, (int, float))
        or isinstance(confidence, bool)
        or not 0 <= confidence <= 1
    ):
        raise RuntimeError(f"Invalid Decider confidence: {confidence!r}")

    # Risk-based policy: low-risk evidence gathering may proceed
    # without approval. Sensitive actions remain human-reviewed.
    safe_investigation_actions = {
        "inspect_authentication",
        "inspect_endpoint",
        "analyze_network",
        "check_reputation",
        "correlate_events",
        "estimate_severity",
        "finish_investigation",
    }

    is_safe_investigation = action in safe_investigation_actions
    requires_review = (
        action == "request_human_review"
        or (confidence < CONFIDENCE_THRESHOLD and not is_safe_investigation)
    )

    return {
        "model": result.get("model", "unknown"),
        "model_action": action,
        "model_confidence": confidence,
        "confidence_threshold": CONFIDENCE_THRESHOLD,
        "final_action": (
            "request_human_review" if requires_review else action
        ),
        "requires_human_review": requires_review,
        "probabilities": answer.get("probabilities", {}),
        "usage": result.get("usage", {}),
        "containment_performed": False,
    }
