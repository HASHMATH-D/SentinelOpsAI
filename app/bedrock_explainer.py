"""Cost-free, evidence-grounded incident briefs using local Python only."""

import json


def _get(data, *keys, default=None):
    """Safely retrieve nested dictionary values."""
    current = data
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return default
        current = current[key]
    return current


def generate_incident_brief(evidence, model_id=None):
    """Generate a deterministic incident brief without cloud APIs."""

    scenario = evidence.get("scenario", "Unknown scenario")
    event_count = evidence.get("event_count", 0)
    severity = evidence.get("severity", {})
    decision = evidence.get("decision", {})
    recommendations = evidence.get("recommendations", [])
    limitations = evidence.get("limitations", [])

    severity_label = (
        severity.get("severity")
        or severity.get("label")
        or "undetermined"
    )
    severity_score = severity.get("score", "not available")
    reasons = severity.get("reasons", [])

    if isinstance(decision, dict):
        action = (
            decision.get("final_action")
            or decision.get("model_action")
            or decision.get("action")
            or "request_human_review"
        )
        confidence = decision.get("model_confidence")
        threshold = decision.get("confidence_threshold", 0.90)
        review_required = decision.get("requires_human_review", True)
    else:
        action = "request_human_review"
        confidence = None
        threshold = 0.90
        review_required = True

    auth = evidence.get("authentication", {})
    endpoint = evidence.get("endpoint_activity", {})
    network = evidence.get("network_activity", {})
    reputation = evidence.get("indicator_reputation", {})
    correlation = evidence.get("correlation", {})

    def count_records(value):
        if isinstance(value, list):
            return len(value)
        if isinstance(value, dict):
            for key in ("events", "records", "matches", "results"):
                if isinstance(value.get(key), list):
                    return len(value[key])
            for key in ("event_count", "count", "total"):
                if isinstance(value.get(key), (int, float)):
                    return value[key]
        return 0

    def describe(value):
        if isinstance(value, dict):
            for key in ("verdict", "reputation", "status", "label", "result"):
                if value.get(key) is not None:
                    return str(value[key])
        return "not available"

    lines = [
        f"# Incident Brief: {scenario}",
        "",
        "## Summary",
        f"- Events examined: {event_count}",
        f"- Assessed severity: {severity_label} ({severity_score}/100)",
        f"- Recommended next action: {action}",
        f"- Human review required: {'Yes' if review_required else 'No'}",
        "- Containment performed: No",
        "",
        "## Evidence observed",
        f"- Authentication records returned: {count_records(auth)}",
        f"- Endpoint records returned: {count_records(endpoint)}",
        f"- Network records returned: {count_records(network)}",
        f"- Indicator reputation: {describe(reputation)}",
        f"- Correlation result: {json.dumps(correlation, ensure_ascii=True, default=str)}",
        "",
        "## Severity reasons",
    ]

    if reasons:
        lines.extend(f"- {reason}" for reason in reasons)
    else:
        lines.append("- No explicit severity reasons were provided by the evidence.")

    lines.extend(["", "## Decision confidence"])
    if isinstance(confidence, (int, float)):
        lines.append(f"- Decider confidence: {confidence:.4f}")
        lines.append(f"- Required confidence threshold: {threshold}")
        if confidence < threshold:
            lines.append("- Confidence is below threshold; do not automate consequential response.")
    else:
        lines.append("- Confidence value unavailable; require human review.")

    lines.extend(["", "## Recommendations"])
    if isinstance(recommendations, list) and recommendations:
        lines.extend(f"- {item}" for item in recommendations)
    elif recommendations:
        lines.append(f"- {recommendations}")
    else:
        lines.append("- Have an authorized analyst review the evidence before taking action.")

    lines.extend(["", "## Limitations"])
    if isinstance(limitations, list) and limitations:
        lines.extend(f"- {item}" for item in limitations)
    elif limitations:
        lines.append(f"- {limitations}")
    else:
        lines.append("- This report uses a synthetic dataset and deterministic local analysis.")
    lines.extend([
        "- Observations come from the supplied evidence; they do not establish real-world attribution.",
        "- This brief is generated locally using templates, not a generative AI model.",
        "",
    ])

    return {
        "provider": "Local Python",
        "model_id": None,
        "region": "local",
        "brief": "\n".join(lines),
        "usage": {"input_tokens": 0, "output_tokens": 0},
        "stop_reason": "local_generation_complete",
        "containment_performed": False,
        "source": "local_synthetic_dataset",
    }
