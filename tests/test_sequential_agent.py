"""Tests for sequential investigation and evidence-router integration."""

import json
import unittest
from pathlib import Path

from app.sequential_agent import SequentialInvestigator

ROOT = Path(__file__).resolve().parents[1]
with (ROOT / "data" / "security_events.json").open() as file:
    DATASET = json.load(file)


def decision(action, confidence=0.99):
    safe_actions = {
        "inspect_authentication", "inspect_endpoint", "analyze_network",
        "check_reputation", "correlate_events", "estimate_severity",
        "finish_investigation",
    }
    review = action == "request_human_review" or (
        confidence < 0.90 and action not in safe_actions
    )
    return {
        "model": "mock-decider-for-test",
        "model_action": action,
        "model_confidence": confidence,
        "confidence_threshold": 0.90,
        "final_action": "request_human_review" if review else action,
        "requires_human_review": review,
        "probabilities": {},
        "containment_performed": False,
    }


class SequentialAgentTests(unittest.TestCase):
    def setUp(self):
        self.events = DATASET["scenarios"]["suspicious_login_chain"]
        self.indicators = DATASET["indicators"]

    def test_executes_multiple_tools_sequentially(self):
        choices = iter([
            decision("inspect_authentication"),
            decision("check_reputation"),
            decision("analyze_network"),
        ])

        agent = SequentialInvestigator(
            self.events,
            self.indicators,
            max_steps=3,
            decider=lambda state: next(choices),
        )
        report = agent.investigate(source_ip="198.51.100.77")

        self.assertEqual(report["steps_taken"], 3)
        self.assertEqual(
            report["completed_actions"],
            [
                "analyze_network",
                "check_reputation",
                "inspect_authentication",
            ],
        )
        self.assertFalse(report["containment_performed"])

    def test_low_confidence_read_only_action_can_execute(self):
        agent = SequentialInvestigator(
            self.events,
            self.indicators,
            max_steps=1,
            decider=lambda state: decision("check_reputation", 0.30),
        )
        report = agent.investigate(source_ip="198.51.100.77")

        self.assertEqual(report["steps_taken"], 1)
        self.assertIn("check_reputation", report["completed_actions"])
        self.assertFalse(report["containment_performed"])

    def test_repeated_action_stops_for_review(self):
        choices = iter([
            decision("inspect_authentication"),
            decision("inspect_authentication"),
        ])
        agent = SequentialInvestigator(
            self.events,
            self.indicators,
            max_steps=3,
            decider=lambda state: next(choices),
        )
        report = agent.investigate()

        self.assertEqual(report["status"], "repeated_action")
        self.assertTrue(report["requires_human_review"])
        self.assertEqual(report["steps_taken"], 1)

    def test_decider_error_stops_for_review(self):
        def broken_decider(state):
            raise RuntimeError("simulated model failure")

        agent = SequentialInvestigator(
            self.events, self.indicators, decider=broken_decider
        )
        report = agent.investigate()

        self.assertEqual(report["status"], "model_unavailable")
        self.assertTrue(report["requires_human_review"])
        self.assertFalse(report["containment_performed"])

    def test_router_advice_is_passed_to_decider(self):
        captured_states = []

        def capturing_decider(state):
            captured_states.append(json.loads(state))
            return decision("inspect_authentication")

        agent = SequentialInvestigator(
            self.events,
            self.indicators,
            max_steps=1,
            decider=capturing_decider,
        )
        agent.investigate()

        self.assertEqual(len(captured_states), 1)
        state = captured_states[0]
        self.assertIn("evidence_router_advice", state)

        advice = state["evidence_router_advice"]
        self.assertIn("ranked_actions", advice)
        self.assertTrue(advice["ranked_actions"])
        self.assertFalse(advice["tools_executed"])
        self.assertFalse(advice["containment_performed"])

    def test_router_excludes_completed_actions_on_next_turn(self):
        captured_states = []
        choices = iter([
            decision("inspect_authentication"),
            decision("check_reputation"),
        ])

        def capturing_decider(state):
            captured_states.append(json.loads(state))
            return next(choices)

        agent = SequentialInvestigator(
            self.events,
            self.indicators,
            max_steps=2,
            decider=capturing_decider,
        )
        report = agent.investigate(source_ip="198.51.100.77")

        self.assertEqual(report["steps_taken"], 2)
        self.assertEqual(len(captured_states), 2)
        self.assertIn(
            "inspect_authentication",
            captured_states[1]["completed_actions"],
        )

        second_advice = captured_states[1]["evidence_router_advice"]
        remaining = {
            item["action"] for item in second_advice["ranked_actions"]
        }
        self.assertNotIn("inspect_authentication", remaining)


    def test_all_six_tools_execute_without_containment(self):
        actions = [
            "inspect_authentication",
            "inspect_endpoint",
            "analyze_network",
            "check_reputation",
            "correlate_events",
            "estimate_severity",
        ]
        choices = iter([decision(action, 0.30) for action in actions])
        agent = SequentialInvestigator(
            self.events, self.indicators, max_steps=6,
            decider=lambda state: next(choices),
        )
        report = agent.investigate(source_ip="198.51.100.77")

        self.assertEqual(report["steps_taken"], 6)
        self.assertEqual(len(report["completed_actions"]), 6)
        self.assertTrue(report["requires_human_review"])
        self.assertFalse(report["containment_performed"])


if __name__ == "__main__":
    unittest.main()
