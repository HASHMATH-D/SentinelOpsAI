"""Deterministic evidence-based action ranking for synthetic investigations."""

from collections import Counter


def rank_investigation_actions(events, completed_actions=None):
    """Return ranked candidate actions without executing any tools."""
    completed = set(completed_actions or [])
    events = list(events)

    types = [
        str(event.get("event_type", "")).lower()
        for event in events
    ]
    counts = Counter(types)

    auth_failures = sum(
        event_type in {
            "auth_failure",
            "authentication_failure",
            "failed_login",
        }
        or (
            event_type == "authentication"
            and str(event.get("outcome", "")).lower() in {
                "failure", "failed", "denied"
            }
        )
        for event, event_type in zip(events, types)
    )

    auth_successes = sum(
        event_type in {
            "auth_success",
            "authentication_success",
            "successful_login",
        }
        or (
            event_type == "authentication"
            and str(event.get("outcome", "")).lower() in {
                "success", "successful", "allowed"
            }
        )
        for event, event_type in zip(events, types)
    )

    sensitive_access = any(
        event.get("sensitive") is True
        or (
            event_type == "file_access"
            and any(
                token in str(event.get("file_path", "")).lower()
                for token in ("payroll", "finance", "confidential", "sensitive")
            )
        )
        for event, event_type in zip(events, types)
    )

    unusual_process = any(
        event_type == "unusual_process"
        or (
            event_type == "endpoint"
            and (
                event.get("unusual") is True
                or "unknown" in str(event.get("process_name", "")).lower()
            )
        )
        for event, event_type in zip(events, types)
    )

    outbound_bytes = sum(
        int(event.get("bytes_sent", 0) or 0)
        for event in events
        if str(event.get("direction", "")).lower() == "outbound"
        or str(event.get("event_type", "")).lower()
        in {"network_transfer", "network"}
        and int(event.get("bytes_sent", 0) or 0) > 0
    )

    signals = {
        "authentication": auth_failures > 0,
        "sensitive_or_unusual_endpoint": sensitive_access or unusual_process,
        "outbound_transfer": outbound_bytes >= 1_000_000,
    }
    active_signal_count = sum(signals.values())

    scores = {
        "inspect_authentication": 0,
        "inspect_endpoint": 0,
        "analyze_network": 0,
        "check_reputation": 0,
        "correlate_events": 0,
        "estimate_severity": 0,
    }
    reasons = {action: [] for action in scores}

    if auth_failures:
        scores["inspect_authentication"] += 5
        reasons["inspect_authentication"].append(
            f"{auth_failures} authentication failure event(s)"
        )

    if auth_failures >= 2 or (auth_failures and auth_successes):
        scores["inspect_authentication"] += 3
        reasons["inspect_authentication"].append(
            "Repeated failures or a failure-success sequence"
        )
    elif auth_successes and not auth_failures:
        scores["inspect_authentication"] += 2
        reasons["inspect_authentication"].append(
            "Successful authentication is present; inspect its context"
        )

    if sensitive_access:
        scores["inspect_endpoint"] += 12
        reasons["inspect_endpoint"].append("Sensitive file access observed")

    if unusual_process:
        scores["inspect_endpoint"] += 7
        reasons["inspect_endpoint"].append("Unusual process observed")

    if outbound_bytes >= 1_000_000:
        scores["analyze_network"] += 7
        reasons["analyze_network"].append(
            f"Large outbound transfer: {outbound_bytes} bytes"
        )
    elif outbound_bytes > 0:
        scores["analyze_network"] += 3
        reasons["analyze_network"].append(
            f"Outbound transfer: {outbound_bytes} bytes"
        )

    if active_signal_count >= 2:
        scores["correlate_events"] += 10
        reasons["correlate_events"].append(
            "Multiple independent signal categories are present; "
            "investigate their relationship"
        )

    # Reputation is useful when the event set contains a source IP, but
    # it must not automatically outrank concrete endpoint/network evidence.
    if any(event.get("source_ip") for event in events):
        scores["check_reputation"] += 1
        reasons["check_reputation"].append("Source IP is available")

        only_routine_success = (
            auth_successes > 0
            and auth_failures == 0
            and not sensitive_access
            and not unusual_process
            and outbound_bytes == 0
            and all(
                event_type in {
                    "auth_success",
                    "authentication_success",
                    "successful_login",
                    "authentication",
                    "approved_software",
                }
                for event_type in types
            )
        )
        if only_routine_success:
            scores["check_reputation"] += 4
            reasons["check_reputation"].append(
                "Routine successful activity: reputation is the useful "
                "remaining verification step"
            )

    if events:
        scores["estimate_severity"] += 1
        reasons["estimate_severity"].append(
            "Severity can be assessed after collecting evidence"
        )

    candidates = [
        {
            "action": action,
            "score": score,
            "reasons": reasons[action],
        }
        for action, score in scores.items()
        if action not in completed and score > 0
    ]
    candidates.sort(key=lambda item: (-item["score"], item["action"]))

    return {
        "ranked_actions": candidates,
        "signals": signals,
        "event_type_counts": dict(counts),
        "containment_performed": False,
        "tools_executed": False,
        "note": (
            "Rule-based ranking is advisory. It is not a confirmed attack "
            "verdict and does not authorize tool execution."
        ),
    }
