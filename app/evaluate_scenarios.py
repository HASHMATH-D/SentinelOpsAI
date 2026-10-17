"""Evaluate all synthetic scenarios and save a dashboard-ready JSON report."""

import json
from datetime import datetime, timezone
from pathlib import Path

from app.incident_engine import IncidentEngine
from app.sequential_agent import SequentialInvestigator

ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "data" / "security_events.json"
REPORT_PATH = ROOT / "reports" / "scenario_evaluation.json"

SCENARIOS = {
    "suspicious_login_chain": {
        "expected_severity": "critical",
        "description": "Repeated login failures followed by sensitive activity.",
    },
    "benign_login": {
        "expected_severity": "low",
        "description": "Successful login and approved software activity.",
    },
    "uncertain_activity": {
        "expected_severity": "medium",
        "description": "Failed login, unusual process, and suspicious indicator.",
    },
}


def run():
    with DATA_PATH.open() as file:
        dataset = json.load(file)

    results = []

    for name, metadata in SCENARIOS.items():
        events = dataset["scenarios"][name]
        baseline = IncidentEngine(events, dataset.get("indicators", {}))
        baseline_report = baseline.investigate()

        sequential = SequentialInvestigator(
            events,
            dataset.get("indicators", {}),
            max_steps=6,
        )
        sequential_report = sequential.investigate()

        decision = sequential_report.get("decision") or {}
        severity = baseline_report["severity"]

        results.append({
            "scenario": name,
            "description": metadata["description"],
            "event_count": len(events),
            "expected_severity": metadata["expected_severity"],
            "observed_severity": severity["severity"],
            "severity_score": severity["score"],
            "severity_reasons": severity["reasons"],
            "severity_label_matches_expectation": (
                severity["severity"] == metadata["expected_severity"]
            ),
            "baseline_decision_status": baseline_report["decision_status"],
            "sequential_status": sequential_report["status"],
            "model_action": decision.get("model_action"),
            "model_confidence": decision.get("model_confidence"),
            "confidence_threshold": decision.get("confidence_threshold", 0.90),
            "requires_human_review": sequential_report[
                "requires_human_review"
            ],
            "sequential_steps_taken": sequential_report["steps_taken"],
            "completed_actions": sequential_report["completed_actions"],
            "containment_performed": (
                baseline_report["decision"].get(
                    "containment_performed", False
                )
                or sequential_report.get("containment_performed", False)
            ),
        })

    report = {
        "project": "SentinelOps AI",
        "report_type": "synthetic_scenario_evaluation",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scenario_count": len(results),
        "all_scenarios_require_review": all(
            result["requires_human_review"] for result in results
        ),
        "containment_performed": any(
            result["containment_performed"] for result in results
        ),
        "severity_label_matches": sum(
            result["severity_label_matches_expectation"]
            for result in results
        ),
        "scenarios": results,
        "limitations": [
            "All event and indicator data are synthetic.",
            "Expected severity labels are provisional evaluation targets.",
            "Severity scores are heuristics, not calibrated probabilities.",
            "Model confidence is not assumed to be calibrated.",
            "No real containment or external security action is performed.",
        ],
    }

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with REPORT_PATH.open("w") as file:
        json.dump(report, file, indent=2)

    print(f"Report saved to: {REPORT_PATH}")
    print(json.dumps({
        "scenario_count": report["scenario_count"],
        "severity_label_matches": report["severity_label_matches"],
        "all_scenarios_require_review": report[
            "all_scenarios_require_review"
        ],
        "containment_performed": report["containment_performed"],
        "scenarios": [
            {
                "scenario": item["scenario"],
                "severity": item["observed_severity"],
                "score": item["severity_score"],
                "status": item["sequential_status"],
                "confidence": item["model_confidence"],
                "review_required": item["requires_human_review"],
            }
            for item in results
        ],
    }, indent=2))


if __name__ == "__main__":
    run()
