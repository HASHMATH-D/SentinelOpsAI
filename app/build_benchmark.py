"""Build a labelled benchmark from existing synthetic security scenarios."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
source = ROOT / "data" / "security_events.json"
destination = ROOT / "data" / "security_benchmark.json"

with source.open(encoding="utf-8") as f:
    dataset = json.load(f)

labels = {
    "suspicious_login_chain": {
        "expected_first_action": "inspect_authentication",
        "expected_review": True,
        "reason": "Repeated login failures followed by success need authentication investigation."
    },
    "benign_login": {
        "expected_first_action": "inspect_authentication",
        "expected_review": False,
        "reason": "Verify the login history before concluding the activity is benign."
    },
    "uncertain_activity": {
        "expected_first_action": "inspect_authentication",
        "expected_review": True,
        "reason": "Limited evidence requires investigation before reaching a conclusion."
    }
}

benchmark = {
    "name": "SentinelOpsAI Synthetic Security Benchmark",
    "version": 1,
    "source": "data/security_events.json",
    "synthetic_only": True,
    "scenarios": []
}

for name, events in dataset["scenarios"].items():
    if name not in labels:
        print(f"Skipping unlabelled scenario: {name}")
        continue

    benchmark["scenarios"].append({
        "scenario_id": name,
        "events": events,
        **labels[name]
    })

destination.write_text(
    json.dumps(benchmark, indent=2),
    encoding="utf-8"
)

print(f"Created: {destination}")
print(f"Labelled scenarios: {len(benchmark['scenarios'])}")
for item in benchmark["scenarios"]:
    print(
        f"- {item['scenario_id']}: "
        f"expected={item['expected_first_action']}, "
        f"human_review={item['expected_review']}"
    )
