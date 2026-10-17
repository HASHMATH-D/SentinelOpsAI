"""Deterministic tools for simulated cybersecurity investigations."""

from collections import Counter
from datetime import datetime, timezone


def _parse_time(value):
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError, AttributeError):
        return None


def search_authentication_events(events, user=None, source_ip=None):
    """Search synthetic authentication events using structured filters."""
    results = []
    for event in events:
        if event.get("event_type") != "authentication":
            continue
        if user and event.get("user") != user:
            continue
        if source_ip and event.get("source_ip") != source_ip:
            continue
        results.append(dict(event))
    return {"tool": "search_authentication_events", "count": len(results),
            "events": results}


def inspect_endpoint_activity(events, user=None, device_id=None):
    """Inspect synthetic endpoint and file-access events."""
    accepted = {"endpoint", "file_access"}
    results = [
        dict(event) for event in events
        if event.get("event_type") in accepted
        and (not user or event.get("user") == user)
        and (not device_id or event.get("device_id") == device_id)
    ]
    return {"tool": "inspect_endpoint_activity", "count": len(results),
            "events": results}


def analyze_network_activity(events, source_ip=None):
    """Summarize simulated network events; no live network access occurs."""
    results = [
        dict(event) for event in events
        if event.get("event_type") == "network"
        and (not source_ip or event.get("source_ip") == source_ip)
    ]
    total_bytes = sum(
        e.get("bytes_transferred", 0)
        for e in results
        if isinstance(e.get("bytes_transferred", 0), (int, float))
        and e.get("bytes_transferred", 0) >= 0
    )
    return {"tool": "analyze_network_activity", "count": len(results),
            "total_bytes_transferred": total_bytes, "events": results}


def check_indicator_reputation(source_ip, indicators):
    """Look up an IP in a local synthetic dataset, not a real threat feed."""
    record = indicators.get(source_ip)
    if record is None:
        return {"source_ip": source_ip, "reputation": "unknown",
                "source": "local_synthetic_dataset"}
    return {"source_ip": source_ip, "reputation": record.get("reputation", "unknown"),
            "reason": record.get("reason", ""),
            "source": "local_synthetic_dataset"}


def correlate_security_events(events, window_minutes=60):
    """Link events sharing a user, device, or IP within a time window."""
    valid = []
    for event in events:
        timestamp = _parse_time(event.get("timestamp"))
        if timestamp:
            valid.append((timestamp, event))

    valid.sort(key=lambda item: item[0])
    links = []
    for i, (time_a, a) in enumerate(valid):
        for time_b, b in valid[i + 1:]:
            elapsed = (time_b - time_a).total_seconds() / 60
            if elapsed > window_minutes:
                break
            shared = [
                key for key in ("user", "device_id", "source_ip")
                if a.get(key) and a.get(key) == b.get(key)
            ]
            if shared:
                links.append({
                    "event_a": a.get("event_id"),
                    "event_b": b.get("event_id"),
                    "shared_indicators": shared,
                    "minutes_apart": round(elapsed, 2),
                })

    return {"window_minutes": window_minutes, "links": links,
            "link_count": len(links)}


def estimate_incident_severity(events, reputation):
    """Produce a transparent heuristic score; it is not a confirmed diagnosis."""
    score = 0
    reasons = []

    failed = sum(
        1 for e in events
        if e.get("event_type") == "authentication"
        and e.get("result") == "failure"
    )
    successful = any(
        e.get("event_type") == "authentication"
        and e.get("result") == "success"
        for e in events
    )
    sensitive_access = any(
        e.get("event_type") == "file_access"
        and e.get("sensitive") is True
        for e in events
    )
    large_transfer = any(
        e.get("event_type") == "network"
        and isinstance(e.get("bytes_transferred"), (int, float))
        and e.get("bytes_transferred", 0) >= 1_000_000
        for e in events
    )

    if failed >= 3:
        score += 15
        reasons.append("Three or more failed authentication attempts")
    if failed >= 3 and successful:
        score += 20
        reasons.append("Failed attempts followed by a successful login")
    if sensitive_access:
        score += 25
        reasons.append("Sensitive file access observed")
    if large_transfer:
        score += 25
        reasons.append("Large simulated outbound transfer observed")
    unusual_process = any(
        e.get("event_type") == "endpoint"
        and e.get("activity") == "unusual_process"
        for e in events
    )

    if unusual_process:
        score += 15
        reasons.append("Unusual endpoint process observed")

    if failed == 1 and not successful:
        score += 5
        reasons.append(
            "Isolated failed authentication without a successful login"
        )

    if reputation == "malicious":
        score += 20
        reasons.append("Source indicator marked malicious in local synthetic data")
    elif reputation == "suspicious":
        score += 10
        reasons.append("Source indicator marked suspicious in local synthetic data")

    score = min(score, 100)
    level = ("critical" if score >= 80 else
             "high" if score >= 60 else
             "medium" if score >= 30 else
             "low")

    return {"score": score, "severity": level, "reasons": reasons,
            "assessment": "heuristic; requires evidence review"}


def calculate_investigation_cost(actions):
    """Estimate relative investigation cost using explicit configured units."""
    costs = {
        "search_authentication_events": 1,
        "inspect_endpoint_activity": 2,
        "analyze_network_activity": 2,
        "check_indicator_reputation": 1,
        "correlate_security_events": 2,
        "human_review": 5,
    }
    total = sum(costs.get(action, 3) for action in actions)
    return {"cost_units": total, "actions": list(actions),
            "cost_model": "illustrative relative units, not monetary cost"}


def utc_now():
    """Utility for callers creating new simulated events."""
    return datetime.now(timezone.utc).isoformat()
