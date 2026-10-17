"""Bounded, evidence-driven sequential investigation for synthetic incidents."""

from app.evidence_router import rank_investigation_actions

from tools.security_tools import (
    analyze_network_activity,
    calculate_investigation_cost,
    check_indicator_reputation,
    correlate_security_events,
    estimate_incident_severity,
    inspect_endpoint_activity,
    search_authentication_events,
)

TOOL_ACTIONS = {
    "inspect_authentication",
    "inspect_endpoint",
    "analyze_network",
    "check_reputation",
    "correlate_events",
    "estimate_severity",
}


class SequentialInvestigator:
    """Let Decider choose one tool per turn; never execute containment."""

    def __init__(self, events, indicators=None, max_steps=6, decider=None):
        if not 1 <= max_steps <= len(TOOL_ACTIONS):
            raise ValueError(f"max_steps must be between 1 and {len(TOOL_ACTIONS)}")

        self.events = [dict(event) for event in events]
        self.indicators = indicators or {}
        self.max_steps = max_steps
        self.decider = decider
        self._validate_events()

    def _validate_events(self):
        required = ("event_id", "timestamp", "event_type")
        allowed = {"authentication", "endpoint", "file_access", "network"}
        seen = set()

        for event in self.events:
            missing = [key for key in required if not event.get(key)]
            if missing:
                raise ValueError(f"Event missing required fields: {missing}")
            if event["event_id"] in seen:
                raise ValueError(f"Duplicate event_id: {event['event_id']}")
            if event["event_type"] not in allowed:
                raise ValueError(f"Unsupported event type: {event['event_type']}")
            seen.add(event["event_id"])

    def _run_tool(self, action, user, source_ip, history):
        if action == "inspect_authentication":
            return search_authentication_events(self.events, user, source_ip)
        if action == "inspect_endpoint":
            return inspect_endpoint_activity(self.events, user)
        if action == "analyze_network":
            return analyze_network_activity(self.events, source_ip)
        if action == "check_reputation":
            if not source_ip:
                return {
                    "reputation": "unknown",
                    "reason": "No source IP was supplied.",
                    "source": "local_synthetic_dataset",
                }
            return check_indicator_reputation(source_ip, self.indicators)
        if action == "correlate_events":
            return correlate_security_events(self.events)
        if action == "estimate_severity":
            reputation = next(
                (
                    item["result"].get("reputation", "unknown")
                    for item in history
                    if item["action"] == "check_reputation"
                ),
                "unknown",
            )
            return estimate_incident_severity(self.events, reputation)
        raise ValueError(f"Unsupported investigation action: {action}")

    def investigate(self, user=None, source_ip=None):
        # Import lazily so tests can inject a fake Decider without HTTP.
        if self.decider is None:
            from app.decider_client import choose_next_action
            decider = choose_next_action
        else:
            decider = self.decider

        history = []
        completed = set()
        status = "max_steps_reached"
        requires_review = False
        final_decision = None

        for step_number in range(1, self.max_steps + 1):
            router_advice = rank_investigation_actions(
                self.events,
                completed_actions=completed,
            )

            state = {
                "incident": "synthetic_security_investigation",
                "event_count": len(self.events),
                "user_filter": user,
                "source_ip": source_ip,
                "events": self.events,
                "completed_actions": sorted(completed),
                "remaining_actions": sorted(TOOL_ACTIONS - completed),
                "evidence_history": history,
                "evidence_router_advice": router_advice,
                "instruction": (
                    "Choose exactly one remaining investigation action, "
                    "finish if sufficient evidence exists, or request human "
                    "review. Never propose or execute containment."
                ),
            }

            try:
                decision = decider(__import__("json").dumps(state, default=str))
            except Exception as exc:
                status = "model_unavailable"
                requires_review = True
                final_decision = {
                    "final_action": "request_human_review",
                    "requires_human_review": True,
                    "error": f"{type(exc).__name__}: {exc}",
                    "containment_performed": False,
                }
                break

            final_decision = decision
            action = decision.get("final_action")

            if decision.get("requires_human_review"):
                status = "human_review_required"
                requires_review = True
                # Preserve the model recommendation for a human reviewer.
                final_decision = {
                    **decision,
                    "review_reason": (
                        "Model confidence below threshold or model requested "
                        "human review. No investigation tool was executed."
                    ),
                    "tool_executed": False,
                    "containment_performed": False,
                }
                break

            if action == "finish_investigation":
                status = "completed"
                break

            if action not in TOOL_ACTIONS:
                status = "invalid_model_action"
                requires_review = True
                break

            if action in completed:
                status = "repeated_action"
                requires_review = True
                break

            try:
                tool_result = self._run_tool(
                    action, user, source_ip, history
                )
            except Exception as exc:
                status = "tool_error"
                requires_review = True
                history.append({
                    "step": step_number,
                    "action": action,
                    "error": f"{type(exc).__name__}: {exc}",
                })
                break

            completed.add(action)
            history.append({
                "step": step_number,
                "action": action,
                "result": tool_result,
                "model_confidence": decision.get("model_confidence"),
            })
        else:
            status = "max_steps_reached"
            requires_review = True

        reputation = next(
            (
                item["result"].get("reputation", "unknown")
                for item in history
                if item["action"] == "check_reputation"
                and "result" in item
            ),
            "unknown",
        )
        severity = estimate_incident_severity(self.events, reputation)

        cost_actions = [item["action"] for item in history if "result" in item]
        cost_actions.append("sequential_decider_step")
        return {
            "incident_type": "simulated_security_investigation",
            "event_count": len(self.events),
            "workflow_mode": "sequential",
            "status": status,
            "steps_taken": len(history),
            "completed_actions": sorted(completed),
            "evidence_history": history,
            "severity": severity,
            "investigation_cost": calculate_investigation_cost(cost_actions),
            "decision": final_decision,
            "requires_human_review": requires_review,
            "containment_performed": False,
            "limitations": [
                "Events and indicator data are synthetic.",
                "Correlations do not establish causation.",
                "Severity is heuristic, not a confirmed attack verdict.",
                "The Decider selects from predefined tools and actions.",
                "Low-confidence decisions, model failures, and loop limits require review.",
                "No real containment or external security action is performed.",
            ],
        }
