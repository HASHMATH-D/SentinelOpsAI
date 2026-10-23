"""SentinelOps AI — synthetic security investigation dashboard."""

import json
from datetime import datetime
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
REPORT_PATH = ROOT / "reports" / "scenario_evaluation.json"
EVENTS_PATH = ROOT / "data" / "security_events.json"
CONFIDENCE_THRESHOLD = 0.90

st.set_page_config(
    page_title="SentinelOps AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


def load_json(path):
    try:
        with path.open(encoding="utf-8") as file:
            return json.load(file)
    except FileNotFoundError:
        st.error(f"File not found: {path}")
        st.stop()
    except (OSError, json.JSONDecodeError) as exc:
        st.error(f"Could not read {path.name}: {exc}")
        st.stop()


report = load_json(REPORT_PATH)
event_data = load_json(EVENTS_PATH)
scenarios = report.get("scenarios", [])
event_scenarios = event_data.get("scenarios", {})
indicators = event_data.get("indicators", {})

if not isinstance(scenarios, list) or not scenarios:
    st.error("The evaluation report has no valid scenarios.")
    st.stop()

df = pd.DataFrame(scenarios)

# Use the exact field names emitted by app.evaluate_scenarios.
required_columns = [
    "scenario",
    "observed_severity",
    "severity_score",
    "model_confidence",
    "sequential_status",
    "requires_human_review",
]

missing = [column for column in required_columns if column not in df.columns]
if missing:
    st.error(f"Evaluation report is missing columns: {missing}")
    st.stop()

df["severity_score"] = pd.to_numeric(
    df["severity_score"], errors="coerce"
).fillna(0)
df["model_confidence"] = pd.to_numeric(
    df["model_confidence"], errors="coerce"
)
df["requires_human_review"] = (
    df["requires_human_review"].fillna(True).astype(bool)
)

with st.sidebar:
    st.title("🛡️ SentinelOps AI")
    st.caption("Intelligent Security Investigation")
    st.divider()

    page = st.radio(
        "Navigation",
        ["Overview", "Incident Explorer", "Investigation Evidence", "Evaluation & Safety"],
    )

    if st.button("↻ Refresh dashboard", use_container_width=True):
        st.rerun()

    st.divider()
    st.caption("Environment: Local synthetic dataset")
    st.caption("Human review: Enforced")
    st.caption("Automated containment: Disabled")

st.title("🛡️ SentinelOps AI")
st.subheader("Security Operations & Investigation Center")
st.caption(
    "Synthetic security telemetry · Local Decider · "
    "Human approval required for low-confidence decisions"
)
st.divider()

if page == "Overview":
    critical_count = int((df["observed_severity"] == "critical").sum())
    review_count = int(df["requires_human_review"].sum())
    avg_score = float(df["severity_score"].mean())
    event_count = sum(
        len(event_scenarios.get(name, [])) for name in df["scenario"]
    )

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Scenarios evaluated", len(df))
    c2.metric("Critical scenarios", critical_count)
    c3.metric("Require human review", review_count)
    c4.metric("Average severity score", f"{avg_score:.1f}/100")

    st.subheader("Scenario severity comparison")
    chart_df = df[["scenario", "severity_score", "observed_severity"]].copy()
    chart_df["display_name"] = chart_df["scenario"].str.replace(
        "_", " ", regex=False
    ).str.title()

    fig = px.bar(
        chart_df,
        x="display_name",
        y="severity_score",
        color="observed_severity",
        text="severity_score",
        category_orders={
            "observed_severity": ["low", "medium", "high", "critical"]
        },
        labels={
            "display_name": "Scenario",
            "severity_score": "Heuristic score / 100",
            "observed_severity": "Severity",
        },
    )
    fig.update_layout(yaxis_range=[0, 100], height=400)
    st.plotly_chart(fig, use_container_width=True)

    left, right = st.columns([1.6, 1])
    with left:
        st.subheader("Scenario summary")
        summary = df[
            ["scenario", "observed_severity", "severity_score", "sequential_status", "model_confidence",
             "requires_human_review"]
        ].copy()
        summary["scenario"] = summary["scenario"].str.replace(
            "_", " ", regex=False
        ).str.title()
        summary["model_confidence"] = summary["model_confidence"].map(lambda x: f"{x:.1%}" if pd.notna(x) else "N/A")
        summary.columns = [
            "Scenario", "Severity", "Score", "Investigation Status",
            "Confidence", "Human Review",
        ]
        st.dataframe(summary, hide_index=True, use_container_width=True)

    with right:
        st.subheader("Safety status")
        st.success("Automated containment is disabled.")
        st.warning(f"{review_count} scenario(s) require human review.")
        st.metric("Synthetic events available", event_count)
        matches = report.get("severity_label_matches")
        if matches is not None:
            st.metric("Severity-label matches", f"{matches}/{len(df)}")
        st.caption(
            "Severity scores are heuristic. Label agreement is not "
            "real-world detection accuracy, and model confidence is "
            "not necessarily calibrated."
        )

elif page == "Incident Explorer":
    st.subheader("Incident Explorer")
    st.write(
        "Inspect scenario severity, synthetic telemetry, indicator "
        "reputation, and event chronology."
    )

    names = df["scenario"].tolist()
    selected = st.selectbox(
        "Select scenario",
        names,
        format_func=lambda x: x.replace("_", " ").title(),
    )

    result = df.loc[df["scenario"] == selected].iloc[0]
    events = event_scenarios.get(selected, [])
    events = sorted(events, key=lambda e: e.get("timestamp", ""))

    ips = sorted({
        str(e["source_ip"]) for e in events if e.get("source_ip")
    })
    users = sorted({
        str(e["user"]) for e in events if e.get("user")
    })
    devices = sorted({
        str(e["device_id"]) for e in events if e.get("device_id")
    })

    a, b, c, d = st.columns(4)
    a.metric("Severity", str(result["observed_severity"]).upper())
    b.metric("Heuristic score", f'{result["severity_score"]:.0f}/100')
    conf = result["model_confidence"]
    c.metric(
        "Decider confidence",
        f"{conf:.1%}" if pd.notna(conf) else "N/A",
    )
    d.metric("Events", len(events))

    st.markdown("#### Incident context")
    x, y = st.columns(2)
    with x:
        st.write("**Scenario:**", selected)
        st.write("**User(s):**", ", ".join(users) or "Not recorded")
        st.write("**Device(s):**", ", ".join(devices) or "Not recorded")
        st.write("**Source IP(s):**", ", ".join(ips) or "Not recorded")
    with y:
        st.write("**Investigation status:**", result["sequential_status"])
        st.write(
            "**Human review required:**",
            "Yes" if result["requires_human_review"] else "No",
        )
        st.write("**Containment performed:** No")
        st.write("**Completed model actions:** Not provided in evaluation summary")

    if result["requires_human_review"] or (
        pd.notna(conf) and conf < CONFIDENCE_THRESHOLD
    ):
        st.warning(
            "Human review required. This dashboard does not authorize "
            "response actions or containment."
        )

    st.markdown("#### Indicator reputation")
    if ips:
        rep_rows = []
        for ip in ips:
            details = indicators.get(ip, {})
            rep_rows.append({
                "Source IP": ip,
                "Reputation": details.get("reputation", "unknown"),
                "Reason": details.get("reason", "No reputation details"),
            })
        st.dataframe(
            pd.DataFrame(rep_rows), hide_index=True, use_container_width=True
        )
    else:
        st.info("No source IP recorded for this scenario.")

    st.markdown("#### Security event timeline")
    if events:
        timeline_rows = []
        for event in events:
            details = []
            for key in (
                "result", "activity", "file", "sensitive",
                "bytes_transferred", "direction",
            ):
                if key in event:
                    value = event[key]
                    if key == "bytes_transferred":
                        value = f"{value:,} bytes"
                    details.append(f"{key.replace('_', ' ').title()}: {value}")

            timeline_rows.append({
                "Timestamp (UTC)": event.get("timestamp", "Unknown"),
                "Event ID": event.get("event_id", "Unknown"),
                "Event Type": event.get("event_type", "Unknown"),
                "User": event.get("user", "—"),
                "Device": event.get("device_id", "—"),
                "Source IP": event.get("source_ip", "—"),
                "Evidence": " · ".join(details) or "No additional details",
            })

        timeline = pd.DataFrame(timeline_rows)
        st.dataframe(
            timeline, hide_index=True, use_container_width=True
        )

        st.markdown("#### Event sequence")
        for index, event in enumerate(events, start=1):
            event_type = event.get("event_type", "event").replace("_", " ").title()
            timestamp = event.get("timestamp", "Unknown")
            event_id = event.get("event_id", "Unknown")
            with st.expander(f"{index}. {timestamp} · {event_id} · {event_type}"):
                st.json(event)

        failures = sum(
            e.get("event_type") == "authentication"
            and e.get("result") == "failure" for e in events
        )
        successes = sum(
            e.get("event_type") == "authentication"
            and e.get("result") == "success" for e in events
        )
        sensitive_access = sum(
            e.get("event_type") == "file_access"
            and e.get("sensitive") is True for e in events
        )
        outbound_bytes = sum(
            e.get("direction") == "outbound"
            and isinstance(e.get("bytes_transferred"), (int, float))
            for e in events
            for _ in [0]
        )
        total_outbound = sum(
            e.get("bytes_transferred", 0)
            for e in events
            if e.get("direction") == "outbound"
            and isinstance(e.get("bytes_transferred", 0), (int, float))
        )

        st.markdown("#### Evidence counters")
        e1, e2, e3, e4 = st.columns(4)
        e1.metric("Authentication failures", failures)
        e2.metric("Successful authentications", successes)
        e3.metric("Sensitive file-access events", sensitive_access)
        e4.metric("Outbound data", f"{total_outbound:,} bytes")
    else:
        st.info("No event records found for this scenario.")

    st.markdown("#### Evaluation record")
    st.json(result.to_dict())

elif page == "Investigation Evidence":
    st.subheader("Investigation Evidence & Tool Execution History")
    evidence_path = ROOT / "reports" / "baseline_evidence.json"

    if not evidence_path.exists():
        st.warning("Baseline evidence report not found.")
        st.code("python -m app.evaluate_baseline_evidence")
        st.stop()

    try:
        evidence_report = json.loads(
            evidence_path.read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as exc:
        st.error(f"Could not read baseline evidence report: {exc}")
        st.stop()

    entries = evidence_report.get("scenarios", [])
    if not entries:
        st.info("No evidence scenarios are available.")
    else:
        names = [entry["scenario"] for entry in entries]
        selected = st.selectbox(
            "Select investigation",
            names,
            format_func=lambda value: value.replace("_", " ").title(),
        )
        entry = next(item for item in entries if item["scenario"] == selected)

        severity = entry.get("severity") or {}
        decision = entry.get("decision") or {}
        recommendations = entry.get("recommendations") or []

        a, b, c, d = st.columns(4)
        a.metric("Events", entry.get("event_count", 0))
        b.metric("Severity", str(severity.get("severity", "unknown")).upper())
        c.metric("Heuristic score", f'{severity.get("score", 0)}/100')
        d.metric("Human review", "Required" if decision.get(
            "requires_human_review", True
        ) else "Required before response")

        if decision.get("requires_human_review", True):
            st.warning(
                "Human review is required. The model recommendation is not "
                "authorization to take response or containment actions."
            )

        st.markdown("#### Actual recorded tool executions")
        actions = entry.get("actions_taken", [])
        if actions:
            for index, action in enumerate(actions, start=1):
                st.write(f"{index}. `{action}`")
        else:
            st.info("No actions are recorded.")

        st.markdown("#### Authentication evidence")
        auth = entry.get("authentication") or {}
        st.metric("Authentication events", auth.get("count", 0))
        if auth.get("events"):
            st.dataframe(
                pd.DataFrame(auth["events"]),
                hide_index=True,
                use_container_width=True,
            )
        else:
            st.info("No authentication events returned.")

        st.markdown("#### Endpoint and file activity")
        endpoint = entry.get("endpoint_activity") or {}
        st.metric("Endpoint-related events", endpoint.get("count", 0))
        if endpoint.get("events"):
            st.dataframe(
                pd.DataFrame(endpoint["events"]),
                hide_index=True,
                use_container_width=True,
            )
        else:
            st.info("No endpoint-related events returned.")

        st.markdown("#### Network activity")
        network = entry.get("network_activity") or {}
        n1, n2 = st.columns(2)
        n1.metric("Network events", network.get("count", 0))
        n2.metric(
            "Total bytes transferred",
            f'{network.get("total_bytes_transferred", 0):,}',
        )
        if network.get("events"):
            st.dataframe(
                pd.DataFrame(network["events"]),
                hide_index=True,
                use_container_width=True,
            )
        else:
            st.info("No network events returned.")

        st.markdown("#### Indicator reputation")
        st.json(entry.get("indicator_reputation") or {})

        st.markdown("#### Event correlation")
        correlation = entry.get("correlation") or {}
        st.metric("Correlated event links", correlation.get("link_count", 0))
        links = correlation.get("links") or []
        if links:
            st.dataframe(
                pd.DataFrame(links),
                hide_index=True,
                use_container_width=True,
            )
        else:
            st.info("No event links were returned.")

        st.markdown("#### Severity explanation")
        st.write(severity.get("assessment", "No assessment supplied."))
        for reason in severity.get("reasons", []):
            st.markdown(f"- {reason}")

        st.markdown("#### Decider output")
        st.write("**Model:**", decision.get("model", "Not recorded"))
        st.write("**Model recommendation:**", decision.get("model_action", "None"))
        confidence = decision.get("model_confidence")
        st.write(
            "**Model confidence:**",
            f"{confidence:.2%}" if isinstance(confidence, (int, float)) else "N/A",
        )
        st.write(
            "**Configured threshold:**",
            f'{decision.get("confidence_threshold", 0.90):.0%}',
        )
        st.write(
            "**Final action:**",
            decision.get("final_action", "Not recorded"),
        )

        st.markdown("#### Recommendations requiring review")
        if recommendations:
            st.dataframe(
                pd.DataFrame(recommendations),
                hide_index=True,
                use_container_width=True,
            )
        else:
            st.info("No recommendations recorded.")

        st.markdown("#### Investigation cost")
        st.json(entry.get("investigation_cost", {}))

        st.success(
            "Automated containment is disabled. This report contains "
            "synthetic evidence and heuristic assessments."
        )

        st.download_button(
            "Download baseline evidence JSON",
            data=json.dumps(entry, indent=2, default=str),
            file_name=f"{selected}_baseline_evidence.json",
            mime="application/json",
        )

elif page == "Evaluation & Safety":
    st.subheader("Evaluation & Safety")
    st.caption(f"Configured confidence threshold: {CONFIDENCE_THRESHOLD:.0%}")

    confidence_df = df[["scenario", "model_confidence"]].copy()
    confidence_df["display_name"] = confidence_df["scenario"].str.replace(
        "_", " ", regex=False
    ).str.title()

    fig = px.bar(
        confidence_df,
        x="display_name",
        y="model_confidence",
        labels={
            "display_name": "Scenario",
            "confidence": "Decider confidence",
        },
        text=confidence_df["model_confidence"].map(lambda x: f"{x:.1%}"),
        title="Model confidence vs review threshold",
    )
    fig.add_hline(
        y=CONFIDENCE_THRESHOLD,
        line_dash="dash",
        annotation_text="Required threshold: 90%",
    )
    fig.update_layout(yaxis_range=[0, 1], height=390)
    st.plotly_chart(fig, use_container_width=True)

    st.markdown("#### Safety checks")
    st.write(
        "**All scenarios require review:**",
        "Yes" if report.get("all_scenarios_require_review", False) else "No",
    )
    st.write(
        "**Containment performed:**",
        "Yes — verify report" if report.get("containment_performed", False)
        else "No",
    )
    st.write(
        "**Severity-label matches:**",
        f'{report.get("severity_label_matches", "N/A")}/{len(df)}',
    )

    st.markdown("#### Review queue")
    review_df = df.loc[
        df["requires_human_review"],
        ["scenario", "observed_severity", "severity_score", "model_confidence", "sequential_status"],
    ].copy()
    if not review_df.empty:
        review_df["scenario"] = review_df["scenario"].str.replace(
            "_", " ", regex=False
        ).str.title()
        review_df["model_confidence"] = review_df["model_confidence"].map(lambda x: f"{x:.1%}" if pd.notna(x) else "N/A")
        st.dataframe(review_df, hide_index=True, use_container_width=True)
    else:
        st.info("No scenarios are currently flagged for review.")

    st.markdown("#### Limitations")
    limitations = report.get("limitations", [])
    if limitations:
        for limitation in limitations:
            st.markdown(f"- {limitation}")
    else:
        st.markdown(
            "- The dataset contains synthetic events, not live telemetry.\n"
            "- Severity is based on deterministic heuristic rules.\n"
            "- Model confidence is not guaranteed to be calibrated.\n"
            "- This dashboard does not execute containment or remediation.\n"
            "- Severity-label agreement on three scenarios is not proof "
            "of general detection performance."
        )

    st.markdown("#### Raw evaluation report")
    st.download_button(
        "Download evaluation JSON",
        data=json.dumps(report, indent=2),
        file_name="scenario_evaluation.json",
        mime="application/json",
    )

st.divider()
st.caption(
    "SentinelOps AI · Research prototype · Synthetic data only · "
    "Not connected to a live SIEM or endpoint security platform"
)
