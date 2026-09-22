"""dashboard/pages/overview.py
Overview — Default landing page for SIH PS-26145 OT Cyber Threat Monitoring Console.
Shows: Header, KPI cards, 7-detector coverage, threat activity timeline,
recent incidents, recent alerts, OT asset summary.
"""

from datetime import datetime, timezone
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

from dashboard.charts import (
    build_threat_activity_chart,
    prepare_multi_threat_timeseries,
)
from dashboard.db import (
    check_db_status,
    fetch_alerts,
    fetch_asset_summary,
    fetch_binned_timeseries,
    fetch_correlated_groups,
    fetch_detector_counts,
    fetch_kpis,
    fetch_timeseries,
    get_active_db_path,
)

# Threat class display name mapping (DB value -> UI label)
THREAT_CLASS_LABELS: dict[str, str] = {
    "ddos": "DDoS",
    "reconnaissance": "Reconnaissance",
    "scanning": "Reconnaissance",
    "dga": "DGA / DNS",
    "dga_dns": "DGA / DNS",
    "dns_tunnel": "DNS Tunnelling",
    "beaconing": "C2 Beaconing",
    "tls_anomaly": "Encrypted Malware / TLS",
    "exfiltration": "Exfiltration",
    "anomalous_behavior": "AI Behavioral Anomaly",
}

# Detector engine mapping
DETECTOR_ENGINES: dict[str, str] = {
    "ddos_detector": "Custom detector",
    "zeek_scan_adapter": "Zeek Scan",
    "dga_detector": "Random Forest",
    "rita_tunnel_adapter": "RITA",
    "rita_beacon_adapter": "RITA",
    "tls_detector": "JA3 + behavioral",
    "exfiltration_detector": "Custom detector",
    "ai_behavioral_anomaly": "Isolation Forest",
}

# Canonical detector engine mapping for display
DETECTOR_DISPLAY_ENGINES: dict[str, str] = {
    "DDoS": "Custom detector",
    "Reconnaissance": "Zeek Scan",
    "DGA / DNS": "Random Forest",
    "DNS Tunnelling": "RITA",
    "C2 Beaconing": "RITA",
    "Encrypted Malware / TLS": "JA3 + behavioral",
    "Exfiltration": "Custom detector",
    "AI Behavioral Anomaly": "Isolation Forest",
}


def _render_header(is_online: bool, status_msg: str, total_alerts: int) -> None:

    """Render top operational SOC header bar with perfect vertical alignment."""
    utc_now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    status_class = "status-live" if is_online else "status-offline"
    status_label = "DATABASE ONLINE" if is_online else "DATABASE OFFLINE"

    st.markdown(
        f"""
        <div class="soc-header">
            <div style="display: flex; flex-direction: column; justify-content: center;">
                <div class="soc-header-title">AKSHI &mdash; OT CYBER THREAT MONITORING CONSOLE</div>
                <div class="soc-header-subtitle">
                    AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
                </div>
            </div>
            <div class="soc-header-meta">
                <div style="display: flex; align-items: center; justify-content: flex-end; gap: 0.5rem;">
                    <span style="font-size: 0.75rem; color: #CBD5E1; text-transform: uppercase; letter-spacing: 0.04em;">Database:</span>
                    <span class="soc-status-badge {status_class}">{status_label}</span>
                </div>
                <div style="margin-top: 5px; color: #CBD5E1; font-size: 0.78rem;">
                    Last updated: <strong style="color: #FFFFFF;">{utc_now}</strong>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _render_kpis(kpis: dict) -> None:
    """Render KPI metric cards."""
    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        st.markdown(
            f"""<div class="kpi-card kpi-card-info">
                <div class="kpi-title">Total Alerts</div>
                <div class="kpi-value">{kpis.get('total_alerts', 0):,}</div>
                <div class="kpi-subtitle">Ingested & Fused</div>
            </div>""",
            unsafe_allow_html=True,
        )

    with col2:
        st.markdown(
            f"""<div class="kpi-card kpi-card-critical">
                <div class="kpi-title">Critical</div>
                <div class="kpi-value" style="color: #CA8A04;">{kpis.get('critical', 0):,}</div>
                <div class="kpi-subtitle">Immediate Action</div>
            </div>""",
            unsafe_allow_html=True,
        )

    with col3:
        st.markdown(
            f"""<div class="kpi-card kpi-card-high">
                <div class="kpi-title">High</div>
                <div class="kpi-value" style="color: #EAB308;">{kpis.get('high', 0):,}</div>
                <div class="kpi-subtitle">Priority</div>
            </div>""",
            unsafe_allow_html=True,
        )

    with col4:
        st.markdown(
            f"""<div class="kpi-card kpi-card-medium">
                <div class="kpi-title">Correlated Incidents</div>
                <div class="kpi-value" style="color: #2563EB;">{kpis.get('correlated_incidents', 0):,}</div>
                <div class="kpi-subtitle">Multi-Stage</div>
            </div>""",
            unsafe_allow_html=True,
        )

    with col5:
        st.markdown(
            f"""<div class="kpi-card kpi-card-info">
                <div class="kpi-title">Affected Assets</div>
                <div class="kpi-value">{kpis.get('compromised_assets', 0):,}</div>
                <div class="kpi-subtitle">Distinct Hosts</div>
            </div>""",
            unsafe_allow_html=True,
        )


def _render_detector_coverage(detector_data: list[dict]) -> None:
    """Render 7-detector coverage section."""
    st.markdown('<div class="soc-section-title">Detection Coverage</div>', unsafe_allow_html=True)

    if not detector_data:
        st.info("No detector data available.")
        return

    # Build detector info from DB data
    detector_info: dict[str, dict] = {}
    for d in detector_data:
        tc = d["threat_class"]
        label = THREAT_CLASS_LABELS.get(tc, tc)
        engine = DETECTOR_ENGINES.get(d.get("detector", ""), d.get("detector", "N/A"))
        detector_info[label] = {
            "alerts": d["alert_count"],
            "incidents": d["incident_count"],
            "engine": engine,
        }

    # Ensure all 8 detectors are represented

    all_detectors = [
        "DDoS", "Reconnaissance", "DGA / DNS", "DNS Tunnelling",
        "C2 Beaconing", "Encrypted Malware / TLS", "Exfiltration", "AI Behavioral Anomaly",
    ]

    # Render in rows of 4
    row1_detectors = all_detectors[:4]
    row2_detectors = all_detectors[4:]

    cols1 = st.columns(4)
    for i, det_name in enumerate(row1_detectors):
        fallback_engine = DETECTOR_DISPLAY_ENGINES.get(det_name, "Operational")
        info = detector_info.get(det_name, {"alerts": 0, "incidents": 0, "engine": fallback_engine})
        engine_str = info.get("engine") or fallback_engine
        if engine_str == "N/A":
            engine_str = fallback_engine
        with cols1[i]:
            st.markdown(
                f"""<div class="detector-card">
                    <div class="detector-card-header">{det_name}</div>
                    <div class="detector-card-metric"><strong>{info['alerts']}</strong> alert{'s' if info['alerts'] != 1 else ''}</div>
                    <div class="detector-card-metric"><strong>{info['incidents']}</strong> incident{'s' if info['incidents'] != 1 else ''}</div>
                    <div class="detector-card-metric">{engine_str}</div>
                    <div class="detector-card-status">Operational</div>
                </div>""",
                unsafe_allow_html=True,
            )

    cols2 = st.columns(4)
    for i, det_name in enumerate(row2_detectors):
        fallback_engine = DETECTOR_DISPLAY_ENGINES.get(det_name, "Operational")
        info = detector_info.get(det_name, {"alerts": 0, "incidents": 0, "engine": fallback_engine})
        engine_str = info.get("engine") or fallback_engine
        if engine_str == "N/A":
            engine_str = fallback_engine
        with cols2[i]:
            st.markdown(
                f"""<div class="detector-card">
                    <div class="detector-card-header">{det_name}</div>
                    <div class="detector-card-metric"><strong>{info['alerts']}</strong> alert{'s' if info['alerts'] != 1 else ''}</div>
                    <div class="detector-card-metric"><strong>{info['incidents']}</strong> incident{'s' if info['incidents'] != 1 else ''}</div>
                    <div class="detector-card-metric">{engine_str}</div>
                    <div class="detector-card-status">Operational</div>
                </div>""",
                unsafe_allow_html=True,
            )



def _render_threat_activity(db_path_str: str) -> None:
    """Render multi-line threat activity timeline chart with distinct colors for all 7 threat classes."""
    st.markdown('<div class="soc-section-title">Threat Activity</div>', unsafe_allow_html=True)

    alerts = fetch_alerts(db_path_str, limit=1000)
    if not alerts:
        st.info("No threat activity recorded.")
        return

    df_ts = prepare_multi_threat_timeseries(alerts, bin_minutes=5)
    if df_ts.empty:
        st.info("No threat activity recorded.")
        return

    chart = build_threat_activity_chart(df_ts, height=260, show_legend=True)
    st.altair_chart(chart, use_container_width=True)


def _render_recent_incidents(groups: list[dict]) -> None:
    """Render recent incidents summary."""
    st.markdown('<div class="soc-section-title">Recent Incidents</div>', unsafe_allow_html=True)

    if not groups:
        st.info("No correlated incidents.")
        return

    for group in groups[:5]:
        cid = group.get("correlation_id", "unknown")
        cid_short = cid[:8] + "..." if len(cid) > 8 else cid
        source = group.get("source", "")
        count = group.get("alert_count", 0)
        highest_sev = group.get("highest_severity", "medium")
        badge_class = f"badge-{highest_sev}"

        # Build attack chain with clean labels
        threats = group.get("threat_classes", [])
        chain_labels = [THREAT_CLASS_LABELS.get(t, t) for t in threats]
        arrow_chain = ' <span class="attack-chain-arrow">&rarr;</span> '.join(chain_labels)

        first_s = group.get("first_seen", "")
        last_s = group.get("last_seen", "")

        st.markdown(
            f"""<div class="incident-card">
                <div class="incident-card-header">
                    <div>
                        <span class="incident-card-id">Incident {cid_short}</span>
                        <span class="{badge_class}" style="margin-left: 0.5rem;">{highest_sev.upper()}</span>
                        <span class="incident-card-meta" style="margin-left: 0.5rem;">({count} alerts)</span>
                    </div>
                    <div class="incident-card-meta">{source}</div>
                </div>
                <div class="attack-chain-box">{arrow_chain}</div>
                <div class="incident-card-meta">
                    {first_s} &mdash; {last_s}
                </div>
            </div>""",
            unsafe_allow_html=True,
        )

    st.markdown("")
    if st.button("View all incidents", key="nav_incidents", use_container_width=False):
        st.switch_page("pages/incidents.py")


def _render_recent_alerts(alerts: list[dict]) -> None:
    """Render compact recent alerts table."""
    st.markdown('<div class="soc-section-title">Recent Alerts</div>', unsafe_allow_html=True)

    if not alerts:
        st.info("No alerts recorded.")
        return

    table_rows = []
    for a in alerts[:10]:
        table_rows.append({
            "Timestamp": a.get("timestamp", "")[:19],
            "Severity": a.get("severity", "").upper(),
            "Threat": THREAT_CLASS_LABELS.get(a.get("threat_class", ""), a.get("threat_class", "")),
            "Source": a.get("source", ""),
            "Destination": a.get("destination", ""),
            "Detector": a.get("detector", ""),
            "Correlation": (a.get("correlation_id") or "-")[:8],
        })

    df = pd.DataFrame(table_rows)
    st.dataframe(df, use_container_width=True, hide_index=True, height=300)


def _render_asset_summary(asset_data: list[dict]) -> None:
    """Render compact OT asset summary."""
    st.markdown('<div class="soc-section-title">OT Asset Summary</div>', unsafe_allow_html=True)

    if not asset_data:
        st.info("No asset inventory loaded.")
        return

    table_rows = []
    for a in asset_data:
        table_rows.append({
            "Asset": a.get("name", "Unknown"),
            "IP": a.get("ip", ""),
            "Criticality": a.get("criticality", "").upper(),
            "Alerts": a.get("alert_count", 0),
            "Last Activity": a.get("last_seen") or "No alerts",
        })

    df = pd.DataFrame(table_rows)
    st.dataframe(df, use_container_width=True, hide_index=True)


# ===== PAGE ENTRY POINT =====

db_path = get_active_db_path()
db_path_str = str(db_path)
is_online, status_msg, alert_count = check_db_status(db_path)

# Header
_render_header(is_online, status_msg, alert_count)

# Handle offline DB
if not is_online:
    st.warning(
        f"Alert database is unavailable at {db_path}. "
        "Please ensure the detection and fusion backend has been initialized."
    )
    st.stop()

# KPIs
kpis = fetch_kpis(db_path_str)
_render_kpis(kpis)

# Handle zero alerts
if alert_count == 0:
    st.info("No alerts recorded yet. The system is actively monitoring OT network telemetry.")
    st.stop()

# 7-Detector Coverage
detector_data = fetch_detector_counts(db_path_str)
_render_detector_coverage(detector_data)

st.markdown("<br>", unsafe_allow_html=True)

# Threat Activity Timeline
_render_threat_activity(db_path_str)

st.markdown("<br>", unsafe_allow_html=True)

# Recent Incidents
correlated = fetch_correlated_groups(db_path_str)
_render_recent_incidents(correlated)

st.markdown("<br>", unsafe_allow_html=True)

# Recent Alerts
recent_alerts = fetch_alerts(db_path_str, limit=10)
_render_recent_alerts(recent_alerts)

st.markdown("<br>", unsafe_allow_html=True)

# OT Asset Summary
asset_data = fetch_asset_summary(db_path_str)
_render_asset_summary(asset_data)
