"""Run bounded investigations and save evidence for the dashboard."""

import json
from pathlib import Path

from app.sequential_agent import SequentialInvestigator

ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "data" / "security_events.json"
REPORT_PATH = ROOT / "reports" / "investigation_evidence.json"


def main():
    data = json.loads(DATA_PATH.read_text(encoding="utf-8"))
    results = []

    for name, events in data["scenarios"].items():
        users = sorted({
            event["user"] for event in events if event.get("user")
        })
        ips = sorted({
            event["source_ip"] for event in events if event.get("source_ip")
        })

        investigator = SequentialInvestigator(
            events=events,
            indicators=data.get("indicators", {}),
            max_steps=6,
        )

        result = investigator.investigate(
            user=users[0] if len(users) == 1 else None,
            source_ip=ips[0] if len(ips) == 1 else None,
        )

        results.append({
            "scenario": name,
            "status": result["status"],
            "steps_taken": result["steps_taken"],
            "completed_actions": result["completed_actions"],
            "evidence_history": result["evidence_history"],
            "severity": result["severity"],
            "investigation_cost": result["investigation_cost"],
            "decision": result["decision"],
            "requires_human_review": result["requires_human_review"],
            "containment_performed": result["containment_performed"],
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

    print(f"Evidence report saved to: {REPORT_PATH}")
    print(json.dumps({
        "scenario_count": len(results),
        "scenarios": [
            {
                "scenario": item["scenario"],
                "status": item["status"],
                "steps_taken": item["steps_taken"],
                "completed_actions": item["completed_actions"],
                "requires_human_review": item["requires_human_review"],
                "containment_performed": item["containment_performed"],
            }
            for item in results
        ],
    }, indent=2))


if __name__ == "__main__":
    main()
