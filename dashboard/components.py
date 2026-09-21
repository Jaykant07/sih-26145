"""dashboard/components.py
Reusable UI components for SIH PS-26145 OT Threat Monitoring Dashboard.
Strict SOC theme: Blue, Yellow/Amber, White, Slate.
Zero detection or scoring logic. Presentation only.
"""

from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional
import altair as alt
import pandas as pd
import streamlit as st


def render_header(db_status: bool, db_msg: str, total_alerts: int) -> None:
    """Render top operational SOC header bar."""
    utc_now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    status_class = "status-live" if db_status else "status-offline"
    status_label = "DATABASE ONLINE" if db_status else "DATABASE OFFLINE"

    header_html = f"""
    <div class="soc-header">
        <div>
            <div class="soc-header-title">SIH PS-26145 &mdash; OT CYBER THREAT MONITORING CONSOLE</div>
            <div style="font-size: 0.8rem; color: #93C5FD; margin-top: 2px;">
                Deterministic Hybrid Threat Detection &amp; OT-Aware Alert Fusion
            </div>
        </div>
        <div class="soc-header-meta">
            <div><span class="soc-status-badge {status_class}">{status_label}</span></div>
            <div style="margin-top: 4px;">System Clock: <strong>{utc_now}</strong></div>
            <div style="color: #CBD5E1;">Recorded Alerts: <strong>{total_alerts:,}</strong></div>
        </div>
    </div>
    """
    st.markdown(header_html, unsafe_allow_html=True)


def render_kpis(kpis: Dict[str, Any]) -> None:
    """Render high-level SOC KPI metric cards."""
    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        st.markdown(
            f"""
            <div class="kpi-card kpi-card-info">
                <div class="kpi-title">Total Alerts</div>
                <div class="kpi-value">{kpis.get('total_alerts', 0):,}</div>
                <div class="kpi-subtitle">Ingested &amp; Fused</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col2:
        st.markdown(
            f"""
            <div class="kpi-card kpi-card-critical">
                <div class="kpi-title">Critical Severity</div>
                <div class="kpi-value" style="color: #CA8A04;">{kpis.get('critical', 0):,}</div>
                <div class="kpi-subtitle">Immediate OT Action</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col3:
        st.markdown(
            f"""
            <div class="kpi-card kpi-card-high">
                <div class="kpi-title">High Severity</div>
                <div class="kpi-value" style="color: #EAB308;">{kpis.get('high', 0):,}</div>
                <div class="kpi-subtitle">Priority Investigations</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col4:
        st.markdown(
            f"""
            <div class="kpi-card kpi-card-medium">
                <div class="kpi-title">Correlated Attacks</div>
                <div class="kpi-value" style="color: #2563EB;">{kpis.get('correlated_incidents', 0):,}</div>
                <div class="kpi-subtitle">Multi-Stage Incidents</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col5:
        st.markdown(
            f"""
            <div class="kpi-card kpi-card-info">
                <div class="kpi-title">Affected Assets</div>
                <div class="kpi-value">{kpis.get('compromised_assets', 0):,}</div>
                <div class="kpi-subtitle">Distinct Internal Hosts</div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_filter_bar() -> Dict[str, Any]:
    """Render compact filter and search controls."""
    with st.expander("ALERT FILTERS & SEARCH", expanded=True):
        col1, col2, col3, col4, col5 = st.columns([2, 2, 1.5, 2, 2.5])

        with col1:
            severity_filter = st.multiselect(
                "Severity",
                options=["critical", "high", "medium", "low", "info"],
                default=[],
                placeholder="All severities",
            )

        with col2:
            threat_options = [
                "reconnaissance",
                "scanning",
                "ddos",
                "beaconing",
                "dga",
                "dga_dns",
                "dns_tunnel",
                "tls_anomaly",
                "exfiltration",
            ]
            threat_filter = st.multiselect(
                "Threat Class",
                options=threat_options,
                default=[],
                placeholder="All threat classes",
            )

        with col3:
            criticality_choice = st.selectbox(
                "Asset Criticality",
                options=["All", "critical", "standard"],
                index=0,
            )

        with col4:
            source_ip = st.text_input("Source / Attacker IP", placeholder="e.g. 192.168.")

        with col5:
            search_query = st.text_input("Search (ID, Dest, Action, Evidence)", placeholder="Keywords...")

    return {
        "severity": severity_filter if severity_filter else None,
        "threat_class": threat_filter if threat_filter else None,
        "asset_criticality": criticality_choice if criticality_choice != "All" else None,
        "source": source_ip.strip() if source_ip.strip() else None,
        "search_term": search_query.strip() if search_query.strip() else None,
    }


def render_timeline(timeseries_data: List[Dict[str, Any]]) -> None:
    """Render time-series threat activity chart using Altair."""
    st.markdown('<div class="soc-section-title">Threat Activity Timeline</div>', unsafe_allow_html=True)
    if not timeseries_data:
        st.info("No threat activity recorded in the timeline window.")
        return

    df = pd.DataFrame(timeseries_data)
    if "time_bucket" in df.columns:
        df["time_bucket"] = pd.to_datetime(df["time_bucket"])

    # Clean SOC Palette for lines
    chart = (
        alt.Chart(df)
        .mark_line(point=True)
        .encode(
            x=alt.X("time_bucket:T", title="Timeline (UTC)", axis=alt.Axis(format="%H:%M:%S")),
            y=alt.Y("count:Q", title="Alert Volume"),
            color=alt.Color(
                "threat_class:N",
                title="Threat Class",
                scale=alt.Scale(
                    domain=[
                        "reconnaissance",
                        "ddos",
                        "beaconing",
                        "dga_dns",
                        "dns_tunnel",
                        "tls_anomaly",
                        "exfiltration",
                    ],
                    range=[
                        "#1E3A8A",  # Reconnaissance: Deep Navy Blue
                        "#CA8A04",  # DDoS: Dark Golden Yellow
                        "#EAB308",  # Beaconing: Vivid Yellow
                        "#2563EB",  # DGA DNS: Royal Blue
                        "#FACC15",  # DNS Tunnel: Bright Yellow
                        "#3B82F6",  # TLS Anomaly: Accent Blue
                        "#A16207",  # Exfiltration: Amber Yellow
                    ],
                ),
            ),
            tooltip=[
                alt.Tooltip("time_bucket:T", title="Time", format="%Y-%m-%d %H:%M:%S"),
                alt.Tooltip("threat_class:N", title="Threat Class"),
                alt.Tooltip("count:Q", title="Alerts"),
            ],
        )
        .properties(height=230)
        .configure_view(strokeWidth=0)
    )

    st.altair_chart(chart, use_container_width=True)


def render_distributions(
    threat_data: List[Dict[str, Any]],
    severity_data: List[Dict[str, Any]],
) -> None:
    """Render side-by-side threat class and severity horizontal bar charts."""
    col1, col2 = st.columns(2)

    with col1:
        st.markdown('<div class="soc-section-title">Threat Class Distribution</div>', unsafe_allow_html=True)
        if not threat_data:
            st.info("No threat class data available.")
        else:
            df_threat = pd.DataFrame(threat_data)
            chart_threat = (
                alt.Chart(df_threat)
                .mark_bar(color="#1E3A8A")
                .encode(
                    x=alt.X("count:Q", title="Total Detections"),
                    y=alt.Y("threat_class:N", sort="-x", title="Threat Class"),
                    tooltip=["threat_class:N", "count:Q"],
                )
                .properties(height=200)
                .configure_view(strokeWidth=0)
            )
            st.altair_chart(chart_threat, use_container_width=True)

    with col2:
        st.markdown('<div class="soc-section-title">Severity Distribution</div>', unsafe_allow_html=True)
        if not severity_data:
            st.info("No severity distribution data available.")
        else:
            df_sev = pd.DataFrame(severity_data)
            sev_colors = {
                "critical": "#CA8A04",
                "high": "#EAB308",
                "medium": "#2563EB",
                "low": "#64748B",
                "info": "#94A3B8",
            }
            chart_sev = (
                alt.Chart(df_sev)
                .mark_bar()
                .encode(
                    x=alt.X("count:Q", title="Total Alerts"),
                    y=alt.Y(
                        "severity:N",
                        sort=["critical", "high", "medium", "low", "info"],
                        title="Severity Level",
                    ),
                    color=alt.Color(
                        "severity:N",
                        scale=alt.Scale(
                            domain=list(sev_colors.keys()),
                            range=list(sev_colors.values()),
                        ),
                        legend=None,
                    ),
                    tooltip=["severity:N", "count:Q"],
                )
                .properties(height=200)
                .configure_view(strokeWidth=0)
            )
            st.altair_chart(chart_sev, use_container_width=True)


def render_alerts_table(alerts: List[Dict[str, Any]]) -> Optional[str]:
    """Render tabular alerts grid and return selected alert_id if any."""
    st.markdown('<div class="soc-section-title">Fused Alert Stream</div>', unsafe_allow_html=True)
    if not alerts:
        st.info("No alerts match the active filter criteria.")
        return None

    # Transform alerts into tabular rows
    table_rows = []
    for a in alerts:
        table_rows.append(
            {
                "Alert ID": a.get("alert_id", ""),
                "Timestamp (UTC)": a.get("timestamp", ""),
                "Severity": a.get("severity", "").upper(),
                "Threat Class": a.get("threat_class", ""),
                "Source IP": a.get("source", ""),
                "Destination IP": a.get("destination", ""),
                "Criticality": a.get("asset_criticality", "standard"),
                "Action": a.get("action_recommended", "investigate"),
                "Correlation ID": a.get("correlation_id") or "-",
            }
        )

    df = pd.DataFrame(table_rows)

    # Allow operator to select an alert to inspect
    st.dataframe(
        df,
        use_container_width=True,
        hide_index=True,
        height=320,
    )

    alert_options = ["(Select an alert to inspect)"] + [a.get("alert_id", "") for a in alerts]
    selected = st.selectbox("Inspect Alert Details by ID:", options=alert_options, index=0)

    if selected and selected != "(Select an alert to inspect)":
        return selected
    return None


def render_alert_detail(alert_data: Dict[str, Any]) -> None:
    """Render full forensic inspection view for a single alert."""
    st.markdown('<div class="soc-section-title">Alert Forensic Investigation</div>', unsafe_allow_html=True)

    alert_id = alert_data.get("alert_id", "")
    severity = alert_data.get("severity", "low").lower()
    threat = alert_data.get("threat_class", "")
    ts = alert_data.get("timestamp", "")
    raw = alert_data.get("raw_alert") or alert_data

    badge_class = f"badge-{severity}" if severity in ["critical", "high", "medium", "low"] else "badge-low"

    st.markdown(
        f"""
        <div style="background-color: #F8FAFC; border: 1px solid #CBD5E1; border-radius: 4px; padding: 1rem; margin-bottom: 1rem;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <span style="font-family: monospace; font-weight: 700; font-size: 1rem; color: #1E3A8A;">Alert {alert_id}</span>
                    <span class="{badge_class}" style="margin-left: 0.5rem;">{severity.upper()}</span>
                </div>
                <div style="font-size: 0.85rem; color: #64748B;">Detected: <strong>{ts}</strong></div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown(f"**Threat Class:** `{threat}`")
        st.markdown(f"**Source IP:** `{alert_data.get('source', '')}`")
    with col2:
        st.markdown(f"**Destination IP:** `{alert_data.get('destination', '')}`")
        st.markdown(f"**Asset Criticality:** `{alert_data.get('asset_criticality', 'standard')}`")
    with col3:
        st.markdown(f"**Detector:** `{raw.get('detector', 'N/A')}`")
        st.markdown(f"**Model Version:** `{raw.get('model_version', 'N/A')}`")
    with col4:
        st.markdown(f"**MITRE ATT&CK:** `{alert_data.get('mitre_technique') or raw.get('mitre_technique', 'N/A')}`")
        st.markdown(f"**Latency Class:** `{raw.get('latency_class', 'event_driven')}`")

    # Recommended Action Box
    action = alert_data.get("action_recommended") or raw.get("action_recommended", "investigate")
    st.markdown(
        f"""
        <div style="background-color: #FEF9C3; border-left: 4px solid #EAB308; padding: 0.6rem 0.8rem; margin: 0.75rem 0; border-radius: 2px;">
            <strong style="color: #854D0E;">Recommended Containment Action:</strong>
            <span style="color: #713F12; font-family: monospace; margin-left: 0.5rem;">{action}</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Supporting Evidence Table
    st.markdown("**Deterministic Supporting Evidence:**")
    evidence = raw.get("supporting_evidence") or alert_data.get("supporting_evidence") or {}
    if evidence:
        evidence_rows = []
        for k, v in evidence.items():
            if isinstance(v, (dict, list)):
                formatted_v = json.dumps(v)
            else:
                formatted_v = str(v)
            evidence_rows.append({"Evidence Field": str(k), "Measurement / Value": formatted_v})

        ev_df = pd.DataFrame(evidence_rows)
        st.table(ev_df)
    else:
        st.info("No supporting evidence dictionary attached to this alert.")

    # Correlation / Attack Chain Details
    correlation_id = alert_data.get("correlation_id")
    if correlation_id:
        st.markdown(
            f"""
            <div class="attack-chain-box">
                <strong>Correlated Incident ID:</strong> <code>{correlation_id}</code><br>
                <strong>Attack Stage Step:</strong> <code>{alert_data.get('attack_chain_step', 'N/A')}</code>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_correlated_incidents(correlated_groups: List[Dict[str, Any]]) -> None:
    """Render multi-stage correlated incident chains."""
    st.markdown('<div class="soc-section-title">Correlated Attack Incidents</div>', unsafe_allow_html=True)
    if not correlated_groups:
        st.info("No multi-stage correlated incidents identified in the current alert set.")
        return

    for group in correlated_groups:
        cid = group.get("correlation_id", "unknown")
        count = group.get("alert_count", 0)
        severities = group.get("severities", [])
        chain = group.get("attack_chain", "")
        sources = ", ".join(group.get("sources", []))
        dests = ", ".join(group.get("destinations", []))
        first_s = group.get("first_seen", "")
        last_s = group.get("last_seen", "")

        # Format chain with arrow symbols
        arrow_chain = chain.replace(" → ", ' <span class="attack-chain-arrow">&rarr;</span> ')

        max_sev = "critical" if "critical" in severities else ("high" if "high" in severities else "medium")
        badge_class = f"badge-{max_sev}"

        st.markdown(
            f"""
            <div style="background-color: #FFFFFF; border: 1px solid #CBD5E1; border-left: 4px solid #EAB308; border-radius: 4px; padding: 0.85rem 1rem; margin-bottom: 0.75rem;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                    <div>
                        <strong style="color: #1E3A8A; font-family: monospace;">INCIDENT {cid}</strong>
                        <span class="{badge_class}" style="margin-left: 0.5rem;">MAX: {max_sev.upper()}</span>
                        <span style="font-size: 0.8rem; color: #64748B; margin-left: 0.5rem;">({count} correlated stages)</span>
                    </div>
                    <div style="font-size: 0.8rem; color: #64748B;">
                        Span: {first_s} &mdash; {last_s}
                    </div>
                </div>
                <div class="attack-chain-box" style="margin-bottom: 0.5rem;">
                    <strong>Attack Chain:</strong> {arrow_chain}
                </div>
                <div style="font-size: 0.8rem; color: #475569;">
                    <strong>Threat Source(s):</strong> <code>{sources}</code> &nbsp;|&nbsp;
                    <strong>Target Destination(s):</strong> <code>{dests}</code>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_asset_inventory(asset_data: List[Dict[str, Any]]) -> None:
    """Render monitored lab assets table with criticality and alert volume."""
    st.markdown('<div class="soc-section-title">Monitored OT Assets &amp; Exposure</div>', unsafe_allow_html=True)
    if not asset_data:
        st.info("No asset inventory loaded or no asset alerts recorded.")
        return

    table_rows = []
    for a in asset_data:
        table_rows.append(
            {
                "Asset Name": a.get("name", "Unknown"),
                "IP Address": a.get("ip", ""),
                "OT Role": a.get("role", ""),
                "Criticality": a.get("criticality", "").upper(),
                "Active Alerts": a.get("alert_count", 0),
                "Last Activity (UTC)": a.get("last_seen") or "No alerts",
            }
        )

    df = pd.DataFrame(table_rows)
    st.dataframe(df, use_container_width=True, hide_index=True)
