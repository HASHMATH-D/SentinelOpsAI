"""Command-line entry point for SentinelOps AI."""

import argparse
import json
from pathlib import Path

from app.incident_engine import IncidentEngine
from app.sequential_agent import SequentialInvestigator

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--scenario",
        choices=("suspicious_login_chain", "benign_login", "uncertain_activity"),
        default="suspicious_login_chain",
    )
    parser.add_argument("--user", help="Optional simulated account filter")
    parser.add_argument("--source-ip", help="Optional simulated source IP")
    parser.add_argument(
        "--mode",
        choices=("baseline", "sequential"),
        default="baseline",
        help="baseline runs all evidence tools; sequential lets Decider select tools",
    )
    parser.add_argument(
        "--max-steps",
        type=int,
        default=6,
        help="Maximum sequential tool calls (1-6)",
    )
    args = parser.parse_args()

    with (ROOT / "data" / "security_events.json").open() as file:
        dataset = json.load(file)

    events = dataset["scenarios"][args.scenario]
    indicators = dataset.get("indicators", {})

    if args.mode == "sequential":
        engine = SequentialInvestigator(
            events, indicators, max_steps=args.max_steps
        )
    else:
        engine = IncidentEngine(events, indicators)

    report = engine.investigate(args.user, args.source_ip)
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
