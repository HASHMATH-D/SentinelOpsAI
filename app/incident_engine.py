"""Evidence-driven investigation workflow for synthetic security incidents."""

import os

from tools.security_tools import (
    analyze_network_activity,
    calculate_investigation_cost,
    check_indicator_reputation,
    correlate_security_events,
    estimate_incident_severity,
    inspect_endpoint_activity,
    search_authentication_events,
)

DECIDER_ENABLED = os.getenv("SENTINELOPS_DECIDER_ENABLED", "true").lower() == "true"


class IncidentEngine:
    def __init__(self, events, indicators=None):
        self.events = [dict(e) for e in events]
        self.indicators = indicators or {}
        self.actions_taken = []
        self.evidence = []
        self._validate_events()

    def _validate_events(self):
        required = ("event_id", "timestamp", "event_type")
        seen = set()
        allowed = {"authentication", "endpoint", "file_access", "network"}

        for event in self.events:
            missing = [key for key in required if not event.get(key)]
            if missing:
                raise ValueError(f"Event missing required fields: {missing}")
            if event["event_id"] in seen:
                raise ValueError(f"Duplicate event_id: {event['event_id']}")
            if event["event_type"] not in allowed:
                raise ValueError(
                    f"Unsupported event type: {event['event_type']}"
                )
            seen.add(event["event_id"])

    def _ask_decider(self, evidence_state):
        """Use Strands Decider if enabled; safely route errors to review."""
        if not DECIDER_ENABLED:
            return {
                "status": "disabled",
                "model_action": None,
                "final_action": "request_human_review",
                "model_confidence": None,
                "requires_human_review": True,
                "error": "Strands Decider integration is disabled.",
                "containment_performed": False,
            }

        try:
            from app.decider_client import choose_next_action

            result = choose_next_action(evidence_state)
            result["status"] = "model_decision_received"
            return result
        except Exception as exc:
            # An unavailable model must never be mistaken for a decision.
            return {
                "status": "model_unavailable",
                "model_action": None,
                "final_action": "request_human_review",
                "model_confidence": None,
                "requires_human_review": True,
                "error": f"{type(exc).__name__}: {exc}",
                "containment_performed": False,
            }

    def investigate(self, user=None, source_ip=None):
        # Infer an IP only when every event with an IP agrees.
        observed_ips = {
            event.get("source_ip")
            for event in self.events
            if event.get("source_ip")
        }
        if source_ip is None and len(observed_ips) == 1:
            source_ip = next(iter(observed_ips))

        # Gather evidence deterministically before asking the decision model.
        auth = search_authentication_events(self.events, user, source_ip)
        endpoint = inspect_endpoint_activity(self.events, user)
        network = analyze_network_activity(self.events, source_ip)

        reputation = (
            check_indicator_reputation(source_ip, self.indicators)
            if source_ip
            else {
                "reputation": "unknown",
                "source": "local_synthetic_dataset",
            }
        )

        correlation = correlate_security_events(self.events)
        severity = estimate_incident_severity(
            self.events, reputation["reputation"]
        )

        self.actions_taken = [
            "search_authentication_events",
            "inspect_endpoint_activity",
            "analyze_network_activity",
            "check_indicator_reputation",
            "correlate_security_events",
        ]
        self.evidence = (
            auth["events"] + endpoint["events"] + network["events"]
        )

        evidence_state = (
            "Synthetic security incident investigation.\n"
            f"Event count: {len(self.events)}\n"
            f"User filter: {user or 'not specified'}\n"
            f"Source IP: {source_ip or 'not specified'}\n"
            f"Indicator reputation: {reputation['reputation']}\n"
            f"Severity score: {severity['score']}/100\n"
            f"Severity label: {severity['severity']}\n"
            f"Authentication evidence: {auth}\n"
            f"Endpoint evidence: {endpoint}\n"
            f"Network evidence: {network}\n"
            f"Correlation evidence: {correlation}\n"
            "Select the next investigation step. Do not perform containment."
        )

        decision = self._ask_decider(evidence_state)
        self.actions_taken.append("strands_decider_next_action")

        recommendations = []
        if severity["score"] >= 60:
            recommendations.extend([
                {
                    "action": "escalate_to_security_analyst",
                    "approval_required": True,
                },
                {
                    "action": "consider_temporary_account_restriction",
                    "approval_required": True,
                },
            ])

        if severity["score"] >= 80:
            recommendations.append({
                "action": "consider_endpoint_isolation",
                "approval_required": True,
            })

        if severity["score"] < 30:
            recommendations.append({
                "action": "continue_monitoring",
                "approval_required": False,
            })

        if decision["requires_human_review"]:
            recommendations.append({
                "action": "human_review_of_next_investigation_step",
                "approval_required": True,
                "reason": decision.get(
                    "error",
                    "Model confidence is below the configured threshold "
                    "or the model is unavailable.",
                ),
            })
        else:
            recommendations.append({
                "action": decision["final_action"],
                "approval_required": True,
                "reason": (
                    "Model-selected investigation step; review evidence "
                    "before taking further action."
                ),
            })

        return {
            "incident_type": "simulated_security_investigation",
            "event_count": len(self.events),
            "authentication": auth,
            "endpoint_activity": endpoint,
            "network_activity": network,
            "indicator_reputation": reputation,
            "correlation": correlation,
            "severity": severity,
            "decision": decision,
            "investigation_cost": calculate_investigation_cost(
                self.actions_taken
            ),
            "recommendations": recommendations,
            "decision_status": (
                "strands_decider_integrated"
                if decision["status"] == "model_decision_received"
                else decision["status"]
            ),
            "limitations": [
                "All events and indicator reputation data are synthetic.",
                "Correlations do not prove causation.",
                "Severity is heuristic, not a confirmed attack verdict.",
                "The model selects from predefined investigation actions.",
                "Low-confidence or unavailable-model decisions require human review.",
                "No real containment, account restriction, or network action is executed.",
                "Amazon Bedrock is not integrated into this workflow yet.",
            ],
        }
