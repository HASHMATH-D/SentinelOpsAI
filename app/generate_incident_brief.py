"""Generate local incident briefs for existing baseline evidence reports."""

import json
from pathlib import Path

from app.bedrock_explainer import generate_incident_brief

ROOT = Path(__file__).resolve().parents[1]
INPUT_PATH = ROOT / "reports" / "baseline_evidence.json"
OUTPUT_PATH = ROOT / "reports" / "incident_briefs.json"


def main():
    if not INPUT_PATH.exists():
        raise SystemExit(
            "Baseline evidence not found. Run "
            "'python -m app.evaluate_baseline_evidence' first."
        )

    report = json.loads(INPUT_PATH.read_text(encoding="utf-8"))
    results = []

    for evidence in report.get("scenarios", []):
        name = evidence.get("scenario", "unnamed")
        print(f"Generating local brief: {name}")

        try:
            brief = generate_incident_brief(evidence)
            results.append({
                "scenario": name,
                "status": "success",
                **brief,
            })
        except Exception as exc:
            # Keep the workflow honest: a failed cloud call is not a brief.
            results.append({
                "scenario": name,
                "status": "error",
                "error": f"{type(exc).__name__}: {exc}",
                "containment_performed": False,
            })
            print(f"  FAILED: {type(exc).__name__}: {exc}")

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(
        json.dumps({
            "provider": "Local Python",
            "scenario_count": len(results),
            "results": results,
        }, indent=2, default=str),
        encoding="utf-8",
    )

    successes = sum(item["status"] == "success" for item in results)
    print(f"\nBriefs saved: {OUTPUT_PATH}")
    print(f"Successful: {successes}/{len(results)}")


if __name__ == "__main__":
    main()
