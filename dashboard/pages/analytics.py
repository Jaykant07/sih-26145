"""dashboard/pages/analytics.py
Analytics — Threat distribution, severity analysis, and detector contribution.
"""

import altair as alt
import pandas as pd
import streamlit as st

from dashboard.charts import (
    THREAT_SPECS,
    build_threat_activity_chart,
    build_threat_distribution_chart,
    prepare_multi_threat_timeseries,
)
from dashboard.db import (
    check_db_status,
    fetch_alerts,
    fetch_correlated_vs_uncorrelated,
    fetch_detector_counts,
    fetch_kpis,
    fetch_severity_distribution,
    fetch_threat_distribution,
    get_active_db_path,
)

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
}

db_path = get_active_db_path()
db_path_str = str(db_path)
is_online, _, _ = check_db_status(db_path)

if not is_online:
    st.warning("Alert database is unavailable.")
    st.stop()

st.markdown('<div class="soc-section-title">Threat Analytics</div>', unsafe_allow_html=True)

kpis = fetch_kpis(db_path_str)
if kpis.get("total_alerts", 0) == 0:
    st.info("No alerts recorded for analysis.")
    st.stop()

# --- Threat Class Distribution & Severity Distribution ---
col1, col2 = st.columns(2)

with col1:
    st.markdown("**Threat Class Distribution**")
    threat_data = fetch_threat_distribution(db_path_str)
    if threat_data:
        # Build standard horizontal bar chart with actual counts and numeric labels
        chart_threat = build_threat_distribution_chart(threat_data, height=240)
        st.altair_chart(chart_threat, use_container_width=True)
    else:
        st.info("No threat class data.")

with col2:
    st.markdown("**Severity Distribution**")
    sev_data = fetch_severity_distribution(db_path_str)
    if sev_data:
        df_sev = pd.DataFrame(sev_data)
        sev_colors = {
            "critical": "#CA8A04",
            "high": "#EAB308",
            "medium": "#2563EB",
            "low": "#64748B",
            "info": "#94A3B8",
        }
        max_sev = int(df_sev["count"].max()) if not df_sev.empty else 1
        x_sev_max = max(max_sev + 1, 5)

        bars_sev = (
            alt.Chart(df_sev)
            .mark_bar(cornerRadiusEnd=3, height=20)
            .encode(
                x=alt.X(
                    "count:Q",
                    title="Total Alerts",
                    axis=alt.Axis(tickMinStep=1, format="d", titleFontSize=11, labelFontSize=10),
                    scale=alt.Scale(domain=[0, x_sev_max]),
                ),
                y=alt.Y(
                    "severity:N",
                    sort=["critical", "high", "medium", "low", "info"],
                    title="",
                ),
                color=alt.Color(
                    "severity:N",
                    scale=alt.Scale(
                        domain=list(sev_colors.keys()),
                        range=list(sev_colors.values()),
                    ),
                    legend=None,
                ),
                tooltip=[
                    alt.Tooltip("severity:N", title="Severity"),
                    alt.Tooltip("count:Q", title="Total Alerts"),
                ],
            )
        )

        labels_sev = (
            alt.Chart(df_sev)
            .mark_text(
                align="left",
                baseline="middle",
                dx=6,
                color="#0F172A",
                fontWeight="bold",
                fontSize=12,
            )
            .encode(
                x="count:Q",
                y=alt.Y("severity:N", sort=["critical", "high", "medium", "low", "info"]),
                text=alt.Text("count:Q", format="d"),
            )
        )

        chart_sev = (bars_sev + labels_sev).properties(height=240).configure_view(strokeWidth=0)
        st.altair_chart(chart_sev, use_container_width=True)
    else:
        st.info("No severity data.")

st.markdown("<br>", unsafe_allow_html=True)

# --- Alert Activity Over Time (Multi-Line Chart for 7 Threat Classes) ---
st.markdown("**Alert Activity Over Time**")

available_threat_labels = [spec["label"] for spec in THREAT_SPECS]

selected_threats = st.multiselect(
    "Filter Visible Threat Lines:",
    options=available_threat_labels,
    default=[],
    placeholder="Showing all 7 Threat Classes (select to isolate specific threats)",
    key="analytics_threat_multiselect",
)

alerts = fetch_alerts(db_path_str, limit=1000)

if alerts:
    df_ts = prepare_multi_threat_timeseries(
        alerts,
        bin_minutes=5,
        selected_threat_labels=selected_threats if selected_threats else None,
    )
    if not df_ts.empty:
        chart_ts = build_threat_activity_chart(df_ts, height=320, show_legend=True)
        st.altair_chart(chart_ts, use_container_width=True)
    else:
        st.info("No activity matching the selected threat filter.")
else:
    st.info("No alerts recorded for timeline activity.")

st.markdown("<br>", unsafe_allow_html=True)

# --- Detector Contribution ---
st.markdown("**Detector Contribution**")
detector_data = fetch_detector_counts(db_path_str)
if detector_data:
    total_alerts = sum(d["alert_count"] for d in detector_data)
    rows = []
    for d in detector_data:
        label = THREAT_CLASS_LABELS.get(d["threat_class"], d["threat_class"])
        share = (d["alert_count"] / total_alerts * 100) if total_alerts > 0 else 0
        rows.append({
            "Detector": label,
            "Engine": d["detector"],
            "Alerts": d["alert_count"],
            "Correlated Incidents": d["incident_count"],
            "Volume Share": f"{share:.1f}%",
        })
    rows.sort(key=lambda x: -x["Alerts"])
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
else:
    st.info("No detector data.")

st.markdown("<br>", unsafe_allow_html=True)

# --- Correlated vs Uncorrelated ---
st.markdown("**Correlated vs Uncorrelated Alerts**")
corr_data = fetch_correlated_vs_uncorrelated(db_path_str)
col1, col2 = st.columns(2)
with col1:
    st.metric("Correlated Alerts", corr_data.get("correlated", 0), help="Alerts fused into multi-stage attack incidents")
with col2:
    st.metric("Uncorrelated Alerts", corr_data.get("uncorrelated", 0), help="Isolated or single-vector threat detections")
