"""Generate deterministic evidence reports for the SentinelOps dashboard."""

import json
from pathlib import Path

from app.incident_engine import IncidentEngine

ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "data" / "security_events.json"
REPORT_PATH = ROOT / "reports" / "baseline_evidence.json"


def main():
    data = json.loads(DATA_PATH.read_text(encoding="utf-8"))
    results = []

    for scenario, events in data["scenarios"].items():
        users = {event.get("user") for event in events if event.get("user")}
        ips = {
            event.get("source_ip")
            for event in events
            if event.get("source_ip")
        }

        engine = IncidentEngine(
            events=events,
            indicators=data.get("indicators", {}),
        )
        result = engine.investigate(
            user=next(iter(users)) if len(users) == 1 else None,
            source_ip=next(iter(ips)) if len(ips) == 1 else None,
        )

        # Preserve actual tool outputs; do not infer tool execution from
        # the model's recommended action.
        results.append({
            "scenario": scenario,
            "event_count": result["event_count"],
            "authentication": result["authentication"],
            "endpoint_activity": result["endpoint_activity"],
            "network_activity": result["network_activity"],
            "indicator_reputation": result["indicator_reputation"],
            "correlation": result["correlation"],
            "severity": result["severity"],
            "decision": result["decision"],
            "decision_status": result["decision_status"],
            "actions_taken": result["actions_taken"]
            if "actions_taken" in result else engine.actions_taken,
            "investigation_cost": result["investigation_cost"],
            "recommendations": result["recommendations"],
            "containment_performed": False,
            "limitations": result["limitations"],
        })

    report = {
        "source": "local_synthetic_dataset",
        "scenario_count": len(results),
        "containment_performed": False,
        "scenarios": results,
    }
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(
        json.dumps(report, indent=2, default=str),
        encoding="utf-8",
    )

    print(f"Baseline evidence report saved: {REPORT_PATH}")
    for item in results:
        print(
            f'{item["scenario"]}: '
            f'{item["severity"].get("severity", "unknown")} '
            f'({item["severity"].get("score", 0)}/100), '
            f'{len(item["actions_taken"])} recorded actions, '
            f'containment={item["containment_performed"]}'
        )


if __name__ == "__main__":
    main()
