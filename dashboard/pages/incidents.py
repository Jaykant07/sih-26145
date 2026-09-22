"""dashboard/pages/incidents.py
Incidents — Correlated attack incidents and alert forensics.
"""

import json
from typing import Any, Dict, List, Optional

import pandas as pd
import streamlit as st

from dashboard.db import (
    fetch_alert_detail,
    fetch_alerts,
    fetch_correlated_groups,
    get_active_db_path,
    check_db_status,
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
    "anomalous_behavior": "AI Behavioral Anomaly",
}


def _render_incident_detail(group: dict, db_path_str: str) -> None:
    """Render detailed view for a single incident."""
    cid = group.get("correlation_id", "")
    threats = group.get("threat_classes", [])
    chain_labels = [THREAT_CLASS_LABELS.get(t, t) for t in threats]

    st.markdown(f"**Correlation ID:** `{cid}`")
    st.markdown(f"**Source:** `{group.get('source', '')}`")
    st.markdown(f"**Severity:** {group.get('highest_severity', 'unknown').upper()}")
    st.markdown(f"**Alert Count:** {group.get('alert_count', 0)}")

    # Attack chain visualization
    st.markdown("**Attack Chain:**")
    chain_html = ""
    for i, label in enumerate(chain_labels):
        if i > 0:
            chain_html += ' <span class="attack-chain-arrow">&rarr;</span> '
        chain_html += f"<strong>{label.upper()}</strong>"
    st.markdown(f'<div class="attack-chain-box">{chain_html}</div>', unsafe_allow_html=True)

    # Fetch individual alerts for this incident
    alerts_in_group = fetch_alerts(
        db_path_str, limit=50, correlation_id=cid
    )

    if alerts_in_group:
        st.markdown("**Individual Alerts:**")
        for alert in sorted(alerts_in_group, key=lambda a: a.get("timestamp", "")):
            tc_label = THREAT_CLASS_LABELS.get(alert.get("threat_class", ""), alert.get("threat_class", ""))
            sev = alert.get("severity", "low")
            badge_class = f"badge-{sev}"
            st.markdown(
                f"""<div style="background-color: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 4px; padding: 0.6rem 0.8rem; margin-bottom: 0.4rem;">
                    <span class="{badge_class}">{sev.upper()}</span>
                    <strong style="margin-left: 0.5rem; color: #1E3A8A;">{tc_label}</strong>
                    <span style="color: #64748B; margin-left: 0.5rem; font-size: 0.8rem;">
                        {alert.get('timestamp', '')[:19]} &mdash;
                        {alert.get('source', '')} &rarr; {alert.get('destination', '')}
                        &mdash; {alert.get('detector', '')}
                    </span>
                </div>""",
                unsafe_allow_html=True,
            )


def _render_alert_forensics(alert_data: dict) -> None:
    """Render full forensic inspection view for a single alert."""
    st.markdown('<div class="soc-section-title">Alert Forensic Investigation</div>', unsafe_allow_html=True)

    alert_id = alert_data.get("alert_id", "")
    severity = alert_data.get("severity", "low").lower()
    threat = alert_data.get("threat_class", "")
    ts = alert_data.get("timestamp", "")
    raw = alert_data.get("raw_alert") or alert_data
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except Exception:
            raw = alert_data

    badge_class = f"badge-{severity}" if severity in ["critical", "high", "medium", "low"] else "badge-low"
    tc_label = THREAT_CLASS_LABELS.get(threat, threat)

    st.markdown(
        f"""<div style="background-color: #F8FAFC; border: 1px solid #CBD5E1; border-radius: 4px; padding: 0.8rem; margin-bottom: 0.75rem;">
            <span style="font-family: monospace; font-weight: 700; color: #1E3A8A;">Alert {alert_id[:12]}...</span>
            <span class="{badge_class}" style="margin-left: 0.5rem;">{severity.upper()}</span>
            <span style="font-size: 0.8rem; color: #64748B; margin-left: 0.5rem;">Detected: {ts[:19]}</span>
        </div>""",
        unsafe_allow_html=True,
    )

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown(f"**Threat Class:** `{tc_label}`")
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

    # Recommended Action
    action = alert_data.get("action_recommended") or raw.get("action_recommended", "investigate")
    st.markdown(
        f"""<div style="background-color: #FEF9C3; border-left: 4px solid #EAB308; padding: 0.5rem 0.7rem; margin: 0.5rem 0; border-radius: 2px;">
            <strong style="color: #854D0E;">Recommended Action:</strong>
            <span style="color: #713F12; font-family: monospace; margin-left: 0.5rem;">{action}</span>
        </div>""",
        unsafe_allow_html=True,
    )

    # Supporting Evidence
    st.markdown("**Supporting Evidence:**")
    evidence = raw.get("supporting_evidence") or alert_data.get("supporting_evidence") or {}
    if isinstance(evidence, str):
        try:
            evidence = json.loads(evidence)
        except Exception:
            evidence = {}
    if evidence:
        evidence_rows = []
        for k, v in evidence.items():
            if isinstance(v, (dict, list)):
                formatted_v = json.dumps(v)
            else:
                formatted_v = str(v)
            evidence_rows.append({"Evidence Field": str(k), "Value": formatted_v})
        st.table(pd.DataFrame(evidence_rows))
    else:
        st.info("No supporting evidence attached.")

    # Correlation info
    correlation_id = alert_data.get("correlation_id")
    if correlation_id:
        st.markdown(
            f"""<div class="attack-chain-box">
                <strong>Correlated Incident ID:</strong> <code>{correlation_id}</code><br>
                <strong>Attack Stage:</strong> <code>{alert_data.get('attack_chain_step', 'N/A')}</code>
            </div>""",
            unsafe_allow_html=True,
        )


# ===== PAGE ENTRY POINT =====

db_path = get_active_db_path()
db_path_str = str(db_path)
is_online, _, _ = check_db_status(db_path)

if not is_online:
    st.warning("Alert database is unavailable.")
    st.stop()

# Compact Filter Bar in Main Content Area
st.markdown('<div class="soc-section-title">Incidents & Forensics</div>', unsafe_allow_html=True)

f_col1, f_col2, f_col3, f_col4 = st.columns([2, 2, 3, 1])
with f_col1:
    sev_filter_val = st.selectbox(
        "Severity",
        options=["All Severities", "Critical", "High", "Medium", "Low"],
        index=0,
        label_visibility="collapsed",
        key="inc_filter_sev_select",
    )
    sev_filter = [sev_filter_val.upper()] if sev_filter_val != "All Severities" else []
with f_col2:
    source_filter = st.text_input(
        "Source IP",
        placeholder="Source IP...",
        label_visibility="collapsed",
        key="inc_filter_src",
    ).strip()
with f_col3:
    search_term = st.text_input(
        "Search incidents...",
        placeholder="Search incidents (ID, IP, threat, detector)...",
        label_visibility="collapsed",
        key="inc_filter_search",
    ).strip()
with f_col4:
    if st.button("Reset", key="btn_reset_inc_filters", use_container_width=True):
        st.session_state["inc_filter_sev_select"] = "All Severities"
        st.session_state["inc_filter_src"] = ""
        st.session_state["inc_filter_search"] = ""
        st.rerun()

# Tab layout: Incidents | Alert Stream
tab_incidents, tab_stream = st.tabs(["Correlated Incidents", "Alert Stream & Forensics"])

with tab_incidents:
    st.markdown('<div class="soc-section-title">Correlated Attack Incidents</div>', unsafe_allow_html=True)
    all_groups = fetch_correlated_groups(db_path_str)
    total_incidents = len(all_groups)

    # Filter correlated incidents
    filtered_groups = []
    for group in all_groups:
        cid = group.get("correlation_id", "")
        group_sev = group.get("highest_severity", "medium").upper()
        group_src = group.get("source", "")
        attack_chain = group.get("attack_chain", "")
        threats = group.get("threat_classes", [])

        # 1. Severity filter
        if sev_filter and group_sev not in [s.upper() for s in sev_filter]:
            continue

        # 2. Source IP filter
        if source_filter and source_filter.lower() not in group_src.lower():
            continue

        # 3. Multi-field search
        if search_term:
            q = search_term.lower()
            group_alerts = fetch_alerts(db_path_str, limit=100, correlation_id=cid)
            dests = " ".join(a.get("destination", "") for a in group_alerts).lower()
            detectors = " ".join(a.get("detector", "") for a in group_alerts).lower()
            evidence_str = " ".join(
                json.dumps(a.get("supporting_evidence", {})) for a in group_alerts
            ).lower()
            threat_str = " ".join(threats).lower()

            matches = (
                q in cid.lower()
                or q in group_src.lower()
                or q in dests
                or q in detectors
                or q in attack_chain.lower()
                or q in threat_str
                or q in evidence_str
            )
            if not matches:
                continue

        filtered_groups.append(group)

    # Incident result count
    st.markdown(
        f"""<div style="font-size: 0.85rem; color: #475569; margin-bottom: 0.85rem; font-weight: 600;">
            Showing {len(filtered_groups)} of {total_incidents} incidents
        </div>""",
        unsafe_allow_html=True,
    )

    if not filtered_groups:
        st.info("No incidents match the selected filters.")
    else:
        for group in filtered_groups:
            cid = group.get("correlation_id", "unknown")
            cid_short = cid[:8] + "..." if len(cid) > 8 else cid
            count = group.get("alert_count", 0)
            highest_sev = group.get("highest_severity", "medium")
            badge_class = f"badge-{highest_sev.lower()}"
            source = group.get("source", "")
            first_s = group.get("first_seen", "")[:19] if group.get("first_seen") else ""
            last_s = group.get("last_seen", "")[:19] if group.get("last_seen") else ""

            threats = group.get("threat_classes", [])
            chain_labels = [THREAT_CLASS_LABELS.get(t, t) for t in threats]
            arrow_chain = ' <span class="attack-chain-arrow">&rarr;</span> '.join(chain_labels)

            # Fetch destinations for this group
            group_alerts = fetch_alerts(db_path_str, limit=50, correlation_id=cid)
            dests = list(set(a.get("destination", "") for a in group_alerts if a.get("destination")))

            st.markdown(
                f"""<div class="incident-card">
                    <div class="incident-card-header">
                        <div>
                            <span class="incident-card-id">INCIDENT {cid_short}</span>
                            <span class="{badge_class}" style="margin-left: 0.5rem;">{highest_sev.upper()}</span>
                            <span class="incident-card-meta" style="margin-left: 0.5rem;">({count} correlated alerts)</span>
                        </div>
                        <div class="incident-card-meta">{first_s} &mdash; {last_s}</div>
                    </div>
                    <div class="attack-chain-box">
                        <strong>Attack Chain:</strong> {arrow_chain}
                    </div>
                    <div style="font-size: 0.78rem; color: #475569;">
                        <strong>Source:</strong> <code>{source}</code>
                        &nbsp;|&nbsp;
                        <strong>Targets:</strong> <code>{', '.join(dests)}</code>
                    </div>
                </div>""",
                unsafe_allow_html=True,
            )

            with st.expander(f"Incident {cid_short} — Details", expanded=False):
                _render_incident_detail(group, db_path_str)

with tab_stream:
    st.markdown('<div class="soc-section-title">Fused Alert Stream</div>', unsafe_allow_html=True)

    all_alerts = fetch_alerts(db_path_str, limit=500)
    total_alerts = len(all_alerts)

    filtered_alerts = []
    for a in all_alerts:
        a_sev = a.get("severity", "").upper()
        a_src = a.get("source", "")
        a_dst = a.get("destination", "")
        a_cid = a.get("correlation_id") or ""
        a_tc = a.get("threat_class", "")
        a_det = a.get("detector", "")
        a_id = a.get("alert_id", "")
        ev_str = json.dumps(a.get("supporting_evidence", {}))

        if sev_filter and a_sev not in [s.upper() for s in sev_filter]:
            continue
        if source_filter and source_filter.lower() not in a_src.lower():
            continue
        if search_term:
            q = search_term.lower()
            matches = (
                q in a_id.lower()
                or q in a_src.lower()
                or q in a_dst.lower()
                or q in a_cid.lower()
                or q in a_tc.lower()
                or q in a_det.lower()
                or q in ev_str.lower()
            )
            if not matches:
                continue

        filtered_alerts.append(a)

    st.markdown(
        f"""<div style="font-size: 0.85rem; color: #475569; margin-bottom: 0.85rem; font-weight: 600;">
            Showing {len(filtered_alerts)} of {total_alerts} alerts
        </div>""",
        unsafe_allow_html=True,
    )

    if not filtered_alerts:
        st.info("No alerts match the active filter criteria.")
    else:
        table_rows = []
        for a in filtered_alerts:
            table_rows.append({
                "Alert ID": a.get("alert_id", "")[:12],
                "Timestamp": a.get("timestamp", "")[:19],
                "Severity": a.get("severity", "").upper(),
                "Threat": THREAT_CLASS_LABELS.get(a.get("threat_class", ""), a.get("threat_class", "")),
                "Source": a.get("source", ""),
                "Destination": a.get("destination", ""),
                "Detector": a.get("detector", ""),
                "Criticality": a.get("asset_criticality", "standard"),
                "Correlation": (a.get("correlation_id") or "-")[:8],
            })

        df = pd.DataFrame(table_rows)
        st.dataframe(df, use_container_width=True, hide_index=True, height=350)

        # Alert detail selector
        alert_options = ["(Select an alert to inspect)"] + [a.get("alert_id", "") for a in filtered_alerts]
        selected = st.selectbox("Inspect Alert:", options=alert_options, index=0)

        if selected and selected != "(Select an alert to inspect)":
            alert_detail = fetch_alert_detail(db_path_str, selected)
            if alert_detail:
                st.markdown("---")
                _render_alert_forensics(alert_detail)
