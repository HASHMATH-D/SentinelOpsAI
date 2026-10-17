"""Generate additional deterministic synthetic security scenarios."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "data" / "security_benchmark_extended.json"

def event(eid, event_type, source_ip, user, device, **extra):
    return {
        "event_id": eid,
        "event_type": event_type,
        "source_ip": source_ip,
        "user": user,
        "device_id": device,
        "timestamp": "2026-10-15T10:00:00Z",
        **extra,
    }

scenarios = [
    {
        "scenario_id": "repeated_auth_failures",
        "expected_first_action": "inspect_authentication",
        "expected_review": True,
        "events": [
            event("X001", "auth_failure", "198.51.100.77", "alex", "LAP-101"),
            event("X002", "auth_failure", "198.51.100.77", "alex", "LAP-101"),
            event("X003", "auth_failure", "198.51.100.77", "alex", "LAP-101"),
        ],
    },
    {
        "scenario_id": "sensitive_file_access",
        "expected_first_action": "inspect_endpoint",
        "expected_review": True,
        "events": [
            event("X004", "file_access", "203.0.113.25", "jordan", "LAP-303",
                  file_path="finance/payroll.csv", sensitive=True),
        ],
    },
    {
        "scenario_id": "large_outbound_transfer",
        "expected_first_action": "analyze_network",
        "expected_review": True,
        "events": [
            event("X005", "network_transfer", "198.51.100.77", "alex", "LAP-101",
                  bytes_sent=2500000, direction="outbound"),
        ],
    },
    {
        "scenario_id": "known_benign_source",
        "expected_first_action": "check_reputation",
        "expected_review": False,
        "events": [
            event("X006", "auth_success", "192.0.2.10", "sam", "LAP-202"),
        ],
    },
    {
        "scenario_id": "mixed_login_and_transfer",
        "expected_first_action": "correlate_events",
        "expected_review": True,
        "events": [
            event("X007", "auth_failure", "198.51.100.77", "alex", "LAP-101"),
            event("X008", "auth_success", "198.51.100.77", "alex", "LAP-101"),
            event("X009", "network_transfer", "198.51.100.77", "alex", "LAP-101",
                  bytes_sent=2500000, direction="outbound"),
        ],
    },
    {
        "scenario_id": "unusual_endpoint_process",
        "expected_first_action": "inspect_endpoint",
        "expected_review": True,
        "events": [
            event("X010", "unusual_process", "203.0.113.25", "jordan", "LAP-303",
                  process_name="unknown_process"),
        ],
    },
    {
        "scenario_id": "routine_approved_activity",
        "expected_first_action": "inspect_authentication",
        "expected_review": False,
        "events": [
            event("X011", "auth_success", "192.0.2.10", "sam", "LAP-202"),
            event("X012", "approved_software", "192.0.2.10", "sam", "LAP-202"),
        ],
    },
    {
        "scenario_id": "ambiguous_single_failure",
        "expected_first_action": "inspect_authentication",
        "expected_review": True,
        "events": [
            event("X013", "auth_failure", "203.0.113.25", "jordan", "LAP-303"),
        ],
    },
    {
        "scenario_id": "file_access_and_outbound_transfer",
        "expected_first_action": "inspect_endpoint",
        "expected_review": True,
        "events": [
            event("X014", "file_access", "198.51.100.77", "alex", "LAP-101",
                  file_path="finance/payroll.csv", sensitive=True),
            event("X015", "network_transfer", "198.51.100.77", "alex", "LAP-101",
                  bytes_sent=2500000, direction="outbound"),
        ],
    },
    {
        "scenario_id": "benign_source_with_failure",
        "expected_first_action": "inspect_authentication",
        "expected_review": True,
        "events": [
            event("X016", "auth_failure", "192.0.2.10", "sam", "LAP-202"),
        ],
    },
]

benchmark = {
    "name": "SentinelOpsAI Extended Synthetic Benchmark",
    "version": 1,
    "synthetic_only": True,
    "label_status": "provisional_expected_actions",
    "scenarios": scenarios,
}

OUTPUT.write_text(json.dumps(benchmark, indent=2), encoding="utf-8")
print(f"Created: {OUTPUT}")
print(f"New scenarios: {len(scenarios)}")
print("These labels are provisional and should be reviewed before formal evaluation.")
