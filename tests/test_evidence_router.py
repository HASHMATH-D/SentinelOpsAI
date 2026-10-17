"""Unit tests for deterministic evidence-based action ranking."""

import unittest

from app.evidence_router import rank_investigation_actions


class EvidenceRouterTests(unittest.TestCase):
    def test_repeated_auth_failures_prioritize_authentication(self):
        events = [
            {"event_id": "1", "event_type": "auth_failure"},
            {"event_id": "2", "event_type": "auth_failure"},
            {"event_id": "3", "event_type": "auth_failure"},
        ]
        result = rank_investigation_actions(events)
        self.assertEqual(
            result["ranked_actions"][0]["action"],
            "inspect_authentication",
        )

    def test_sensitive_file_access_prioritizes_endpoint(self):
        events = [
            {
                "event_id": "1",
                "event_type": "file_access",
                "file_path": "finance/payroll.csv",
                "sensitive": True,
            }
        ]
        result = rank_investigation_actions(events)
        self.assertEqual(result["ranked_actions"][0]["action"], "inspect_endpoint")

    def test_large_outbound_transfer_prioritizes_network(self):
        events = [
            {
                "event_id": "1",
                "event_type": "network_transfer",
                "direction": "outbound",
                "bytes_sent": 2_500_000,
            }
        ]
        result = rank_investigation_actions(events)
        self.assertEqual(result["ranked_actions"][0]["action"], "analyze_network")

    def test_mixed_auth_and_network_signals_prioritize_correlation(self):
        events = [
            {"event_id": "1", "event_type": "auth_failure"},
            {
                "event_id": "2",
                "event_type": "network_transfer",
                "direction": "outbound",
                "bytes_sent": 2_500_000,
            },
        ]
        result = rank_investigation_actions(events)
        self.assertEqual(result["ranked_actions"][0]["action"], "correlate_events")

    def test_completed_actions_are_excluded(self):
        events = [
            {"event_id": "1", "event_type": "auth_failure"},
        ]
        result = rank_investigation_actions(
            events, completed_actions={"inspect_authentication"}
        )
        actions = [item["action"] for item in result["ranked_actions"]]
        self.assertNotIn("inspect_authentication", actions)

    def test_router_never_executes_tools_or_containment(self):
        result = rank_investigation_actions(
            [{"event_id": "1", "event_type": "auth_failure"}]
        )
        self.assertFalse(result["tools_executed"])
        self.assertFalse(result["containment_performed"])


if __name__ == "__main__":
    unittest.main()
