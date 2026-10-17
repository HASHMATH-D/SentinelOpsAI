"""Standard-library tests: run with python -m unittest discover -s tests -v."""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.incident_engine import IncidentEngine
from tools.security_tools import (
    calculate_investigation_cost,
    check_indicator_reputation,
    correlate_security_events,
)


with (ROOT / "data" / "security_events.json").open() as file:
    DATASET = json.load(file)


class SecurityToolTests(unittest.TestCase):
    def test_local_indicator_lookup(self):
        result = check_indicator_reputation(
            "198.51.100.77", DATASET["indicators"]
        )
        self.assertEqual(result["reputation"], "malicious")
        self.assertEqual(result["source"], "local_synthetic_dataset")

    def test_unknown_indicator(self):
        self.assertEqual(
            check_indicator_reputation("unknown", {})["reputation"], "unknown"
        )

    def test_cost_is_deterministic(self):
        result = calculate_investigation_cost([
            "search_authentication_events", "human_review"
        ])
        self.assertEqual(result["cost_units"], 6)

    def test_event_correlation(self):
        events = DATASET["scenarios"]["suspicious_login_chain"]
        result = correlate_security_events(events)
        self.assertGreater(result["link_count"], 0)


class IncidentEngineTests(unittest.TestCase):
    def test_suspicious_chain_is_high_severity(self):
        engine = IncidentEngine(
            DATASET["scenarios"]["suspicious_login_chain"],
            DATASET["indicators"],
        )
        result = engine.investigate(source_ip="198.51.100.77")
        self.assertGreaterEqual(result["severity"]["score"], 60)
        self.assertTrue(result["recommendations"])
        self.assertEqual(result["decision_status"], "strands_decider_integrated")
        self.assertIn("decision", result)
        self.assertIn(
            result["decision"]["final_action"],
            {
                "inspect_authentication",
                "inspect_endpoint",
                "analyze_network",
                "request_human_review",
            },
        )
        self.assertFalse(result["decision"]["containment_performed"])

    def test_uncertain_activity_has_nonzero_severity(self):
        engine = IncidentEngine(
            DATASET["scenarios"]["uncertain_activity"],
            DATASET["indicators"],
        )
        result = engine.investigate(source_ip="203.0.113.25")

        self.assertEqual(result["severity"]["score"], 30)
        self.assertEqual(result["severity"]["severity"], "medium")
        self.assertIn(
            "Unusual endpoint process observed",
            result["severity"]["reasons"],
        )
        self.assertIn(
            "Isolated failed authentication without a successful login",
            result["severity"]["reasons"],
        )

    def test_suspicious_chain_score_remains_85(self):
        from tools.security_tools import estimate_incident_severity

        result = estimate_incident_severity(
            DATASET["scenarios"]["suspicious_login_chain"],
            "unknown",
        )
        self.assertEqual(result["score"], 85)

    def test_benign_scenario_is_low_severity(self):
        engine = IncidentEngine(
            DATASET["scenarios"]["benign_login"], DATASET["indicators"]
        )
        result = engine.investigate(source_ip="192.0.2.10")
        self.assertEqual(result["severity"]["severity"], "low")

    def test_duplicate_ids_are_rejected(self):
        event = {
            "event_id": "D1",
            "timestamp": "2026-10-15T00:00:00Z",
            "event_type": "authentication",
        }
        with self.assertRaises(ValueError):
            IncidentEngine([event, event])

    def test_invalid_event_type_is_rejected(self):
        event = {
            "event_id": "D2",
            "timestamp": "2026-10-15T00:00:00Z",
            "event_type": "unknown",
        }
        with self.assertRaises(ValueError):
            IncidentEngine([event])


if __name__ == "__main__":
    unittest.main()
