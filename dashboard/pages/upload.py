"""dashboard/pages/upload.py
PCAP Ingestion & Telemetry Analysis Page for SIH PS-26145 OT Threat Monitoring Console.

Allows operators to upload .pcap / .pcapng files into the existing pipeline:
  1. Validates magic bytes and file integrity safely.
  2. Saves into isolated artifacts/uploads/<pcap_id>/ workspace.
  3. Executes Zeek inside Docker (with JA3 and Scan scripts).
  4. Feeds telemetry through all 7 detectors.
  5. Passes draft alerts through OT-Aware Fusion.
  6. Persists schema-compliant alerts into SQLite datastore scoped to pcap_id.
  7. Provides scoped analysis inspection and transactional deletion.
"""

from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import streamlit as st

from dashboard.db import (
    fetch_pcap_alerts,
    fetch_pcap_alerts_count,
    fetch_pcap_analyses,
    fetch_pcap_analysis,
    get_active_db_path,
)
from ingest.pcap_pipeline import (
    PCAPProcessingError,
    PCAPValidationError,
    delete_pcap_analysis,
    process_pcap_upload,
    validate_pcap_header,
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

ALL_DETECTORS = [
    ("DDoS", "ddos", "Custom detector", "Volumetric anomaly & SYN/UDP flood detection"),
    ("Reconnaissance", "reconnaissance", "Zeek Scan", "Port scan & address sweep heuristics via notice.log"),
    ("DGA / DNS", "dga", "Random Forest", "Domain Generation Algorithm query inference"),
    ("DNS Tunnelling", "dns_tunnel", "RITA", "Covert channel & exfiltration via DNS queries"),
    ("C2 Beaconing", "beaconing", "RITA", "Periodic command & control connection intervals"),
    ("Encrypted Malware / TLS", "tls_anomaly", "JA3 + behavioral", "Suspicious JA3 fingerprints & asymmetric flow ratios"),
    ("Exfiltration", "exfiltration", "Custom detector", "Outbound/inbound data transfer asymmetry detection"),
    ("AI Behavioral Anomaly", "anomalous_behavior", "Isolation Forest", "Unsupervised flow-level behavioral outlier detection"),
]


def _format_bytes(size_bytes: int) -> str:
    """Format byte sizes for display."""
    if size_bytes >= 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.2f} MB"
    if size_bytes >= 1024:
        return f"{size_bytes / 1024:.1f} KB"
    return f"{size_bytes} B"


def _render_header() -> None:
    """Render standardized top SOC header bar."""
    utc_now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    st.markdown(
        f"""
        <div style="background-color: #FFFFFF; border: 1px solid #E2E8F0; border-radius: 6px; padding: 1rem 1.5rem; margin-bottom: 1.5rem;">
            <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 0.75rem;">
                <div>
                    <h1 style="font-size: 1.5rem; font-weight: 700; color: #0F172A; margin: 0 0 0.25rem 0; letter-spacing: -0.02em;">
                        AKSHI &mdash; OT CYBER THREAT MONITORING CONSOLE
                    </h1>
                    <div style="font-size: 0.85rem; color: #64748B; font-weight: 500;">
                        AI-Based Detection of Cyber Threats in Unidirectional IP Traffic // PCAP Analysis
                    </div>
                </div>
                <div style="text-align: right;">
                    <span style="display: inline-block; background-color: #EFF6FF; color: #1D4ED8; font-size: 0.75rem; font-weight: 700; padding: 0.3rem 0.6rem; border-radius: 4px; border: 1px solid #BFDBFE;">
                        INGESTION PIPELINE READY
                    </span>
                    <div style="font-size: 0.75rem; color: #94A3B8; margin-top: 0.35rem; font-family: monospace;">
                        {utc_now}
                    </div>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _render_delete_confirmation(pcap_id: str, db_path: Path) -> None:
    """Render safe confirmation card before deleting a PCAP analysis."""
    meta = fetch_pcap_analysis(str(db_path), pcap_id)
    filename = meta.get("filename", "Unknown capture") if meta else pcap_id
    file_size_str = _format_bytes(meta.get("file_size_bytes", 0)) if meta else "N/A"

    st.markdown(
        f"""
        <div style="background-color: #FEF2F2; border: 1px solid #FCA5A5; border-radius: 6px; padding: 1.25rem; margin-bottom: 1.5rem;">
            <div style="font-size: 1.05rem; font-weight: 700; color: #991B1B; margin-bottom: 0.5rem;">
                Confirm Deletion of PCAP Analysis
            </div>
            <div style="font-size: 0.88rem; color: #7F1D1D; margin-bottom: 0.75rem;">
                Are you sure you want to permanently delete this PCAP analysis record?
            </div>
            <div style="background-color: #FFFFFF; border: 1px solid #FECACA; border-radius: 4px; padding: 0.75rem 1rem; margin-bottom: 1rem; font-size: 0.82rem; color: #334155;">
                <div><strong>Filename:</strong> {filename}</div>
                <div><strong>Capture Size:</strong> {file_size_str}</div>
                <div><strong>PCAP ID:</strong> <code>{pcap_id}</code></div>
                <div style="margin-top: 0.5rem; color: #B91C1C;">
                    <strong>This action permanently removes:</strong>
                    <ul style="margin: 0.25rem 0 0 1.25rem; padding: 0;">
                        <li>Uploaded PCAP capture file on disk</li>
                        <li>Zeek-generated logs and telemetry artifacts</li>
                        <li>7-Detector evaluation results and JSON payloads</li>
                        <li>All PCAP-specific alerts in the SQLite database</li>
                        <li>Analysis session metadata record</li>
                    </ul>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    c1, c2, _ = st.columns([1, 1, 2])
    with c1:
        if st.button("Cancel", key="btn_cancel_delete", use_container_width=True):
            st.session_state["delete_confirm_pcap_id"] = None
            st.rerun()

    with c2:
        if st.button("Delete Permanently", type="primary", key="btn_execute_delete", use_container_width=True):
            try:
                res = delete_pcap_analysis(pcap_id, db_path=db_path)
                st.cache_data.clear()
                if st.session_state.get("selected_pcap_id") == pcap_id:
                    st.session_state["selected_pcap_id"] = None
                st.session_state["delete_confirm_pcap_id"] = None
                st.success(
                    f"Successfully deleted capture analysis: {res.get('deleted_alerts', 0)} alert(s) and associated filesystem artifacts removed."
                )
                st.rerun()
            except Exception as e:
                st.error(f"Failed to delete analysis: {e}")


def _render_upload_section(db_path: Path) -> None:
    """Render capture upload box with stage-based progress execution."""
    st.markdown(
        """
        <div style="background-color: #FFFFFF; border: 1px solid #E2E8F0; border-radius: 6px; padding: 1.25rem; margin-bottom: 1.5rem;">
            <div style="font-size: 0.95rem; font-weight: 700; color: #0F172A; margin-bottom: 0.5rem;">
                Select Network Packet Capture (.pcap / .pcapng)
            </div>
            <div style="font-size: 0.82rem; color: #64748B; margin-bottom: 1rem;">
                Upload a packet capture to execute Zeek protocol parsing (with JA3/JA3S fingerprinting and Scan heuristics)
                followed by all 7 threat detectors and OT-Aware Fusion.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    uploaded_file = st.file_uploader(
        "Upload Capture File",
        type=["pcap", "pcapng"],
        help="Standard libpcap or pcapng format. Maximum file size: 200 MB.",
        label_visibility="collapsed",
        key="pcap_file_uploader",
    )

    if uploaded_file is not None:
        file_size_bytes = len(uploaded_file.getvalue())
        col1, col2, col3 = st.columns(3)
        col1.metric("Selected File", uploaded_file.name)
        col2.metric("File Size", _format_bytes(file_size_bytes))
        col3.metric("Datastore Target", db_path.name)

        if st.button("Start Pipeline Ingestion", type="primary", use_container_width=True, key="btn_run_ingest"):
            progress_container = st.container()
            with progress_container:
                st.markdown("### Ingestion Progress")
                progress_bar = st.progress(0.0)
                status_text = st.empty()
                stage_log = st.empty()

                log_lines = []

                def on_progress(stage: str, msg: str, pct: float) -> None:
                    progress_bar.progress(pct)
                    status_text.markdown(f"**Stage:** `{stage}` — {msg}")
                    log_lines.append(f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] [{stage}] {msg}")
                    stage_log.code("\n".join(log_lines), language="text")

                try:
                    # Pass bytes directly without storing in session_state
                    file_bytes = uploaded_file.getvalue()
                    result = process_pcap_upload(
                        pcap_data=file_bytes,
                        original_filename=uploaded_file.name,
                        db_path=db_path,
                        progress_callback=on_progress,
                    )
                    # Automatically select newly processed PCAP
                    st.session_state["selected_pcap_id"] = result["pcap_id"]
                    st.cache_data.clear()
                    st.success(
                        f"Capture processed successfully! Generated {result['fused_alerts_count']} fused alert(s) across {result.get('telemetry_stats', {}).get('connections_count', 0)} connections."
                    )
                    time.sleep(1.0)
                    st.rerun()
                except PCAPValidationError as ve:
                    progress_bar.progress(0.0)
                    status_text.empty()
                    st.error(f"**Validation Rejected**: {ve}")
                    st.info("Ensure the file is a valid, uncorrupted PCAP/PCAPNG network trace containing at least 24 bytes.")
                except PCAPProcessingError as pe:
                    progress_bar.progress(0.0)
                    status_text.empty()
                    st.error(f"**Processing Error**: {pe}")
                    st.info("Zeek encountered an unrecoverable syntax or truncation error while reading the capture packets.")
                except Exception as ex:
                    progress_bar.progress(0.0)
                    status_text.empty()
                    st.error(f"**Pipeline Execution Error**: {ex}")


def _render_history_section(analyses: list[dict], db_path: Path) -> None:
    """Render compact list of past PCAP analyses."""
    st.markdown('<div class="soc-section-title">PCAP Analysis History</div>', unsafe_allow_html=True)

    if not analyses:
        st.info("No PCAP analyses recorded yet. Upload a network capture above to begin analysis.")
        return

    for a in analyses:
        pid = a["pcap_id"]
        fname = a.get("filename", "Unknown")
        fsize = _format_bytes(a.get("file_size_bytes", 0))
        status = str(a.get("status", "unknown")).upper()
        upload_ts = a.get("upload_timestamp", "")[:19].replace("T", " ")
        alerts_count = a.get("alerts_count", 0)
        duration = f"{a.get('duration_seconds', 0.0):.1f}s" if a.get("duration_seconds") else "N/A"

        is_selected = st.session_state.get("selected_pcap_id") == pid

        card_border = "#2563EB" if is_selected else "#E2E8F0"
        bg_color = "#F8FAFC" if is_selected else "#FFFFFF"
        status_color = "#16A34A" if status == "COMPLETED" else ("#DC2626" if status == "FAILED" else "#CA8A04")

        st.markdown(
            f"""
            <div class="prototype-card" style="background-color: {bg_color}; border: 1px solid {card_border}; border-radius: 6px; padding: 0.85rem 1.25rem; margin-bottom: 0.6rem;">
                <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 0.5rem;">
                    <div>
                        <span style="font-weight: 700; color: #0F172A; font-size: 0.95rem;">{fname}</span>
                        <span style="margin-left: 0.5rem; font-size: 0.75rem; background-color: #F1F5F9; color: #475569; padding: 0.15rem 0.4rem; border-radius: 4px; font-family: monospace;">
                            ID: {pid[:8]}...
                        </span>
                        <span style="margin-left: 0.5rem; font-size: 0.72rem; font-weight: 700; color: {status_color};">
                            {status}
                        </span>
                    </div>
                    <div style="font-size: 0.8rem; color: #64748B;">
                        Size: <strong>{fsize}</strong> &bull; Alerts: <strong>{alerts_count}</strong> &bull; Exec: <strong>{duration}</strong> &bull; Ingested: {upload_ts} UTC
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        c1, c2, _ = st.columns([1, 1, 4])
        with c1:
            if not is_selected:
                if st.button("View Analysis", key=f"btn_view_{pid}", use_container_width=True):
                    st.session_state["selected_pcap_id"] = pid
                    st.session_state["delete_confirm_pcap_id"] = None
                    st.rerun()
            else:
                st.button("Currently Selected", key=f"btn_sel_{pid}", disabled=True, use_container_width=True)
        with c2:
            if st.button("Delete", key=f"btn_del_req_{pid}", use_container_width=True):
                st.session_state["delete_confirm_pcap_id"] = pid
                st.rerun()


def _render_selected_analysis(pcap_id: str, db_path: Path) -> None:
    """Render comprehensive analysis dashboard for the selected PCAP."""
    meta = fetch_pcap_analysis(str(db_path), pcap_id)
    if not meta:
        st.warning(f"Selected PCAP analysis ({pcap_id}) not found.")
        return

    fname = meta.get("filename", "Unknown Capture")
    fsize = _format_bytes(meta.get("file_size_bytes", 0))
    status = str(meta.get("status", "unknown")).upper()
    upload_ts = meta.get("upload_timestamp", "")[:19].replace("T", " ")
    start_ts = meta.get("analysis_start_time", "")[:19].replace("T", " ")
    end_ts = meta.get("analysis_end_time", "")[:19].replace("T", " ")
    duration = f"{meta.get('duration_seconds', 0.0):.2f}s" if meta.get("duration_seconds") else "N/A"

    st.markdown("---")

    # Header Card matching Phase 10 specifications
    st.markdown(
        f"""
        <div class="prototype-card" style="background-color: #FFFFFF; border: 1px solid #CBD5E1; border-left: 4px solid #2563EB; border-radius: 6px; padding: 1.25rem; margin-bottom: 1.25rem;">
            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 0.75rem;">
                <div>
                    <div style="font-size: 0.75rem; font-weight: 700; color: #2563EB; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.2rem;">
                        PCAP ANALYSIS
                    </div>
                    <div style="font-size: 1.2rem; font-weight: 700; color: #0F172A;">
                        {fname}
                    </div>
                    <div style="font-size: 0.78rem; color: #64748B; font-family: monospace; margin-top: 0.2rem;">
                        PCAP ID: {pcap_id}
                    </div>
                </div>
                <div>
                    <span style="background-color: #EFF6FF; color: #1D4ED8; font-size: 0.75rem; font-weight: 700; padding: 0.3rem 0.6rem; border-radius: 4px; border: 1px solid #BFDBFE;">
                        STATUS: {status}
                    </span>
                </div>
            </div>
            <div style="display: flex; gap: 1.5rem; margin-top: 0.85rem; font-size: 0.82rem; color: #475569; flex-wrap: wrap;">
                <div><strong>Filename:</strong> {fname}</div>
                <div><strong>PCAP ID:</strong> <code style="font-size: 0.75rem;">{pcap_id}</code></div>
                <div><strong>File size:</strong> {fsize}</div>
                <div><strong>Status:</strong> {status}</div>
                <div><strong>Upload time:</strong> {upload_ts} UTC</div>
                <div><strong>Analysis start time:</strong> {start_ts} UTC</div>
                <div><strong>Analysis completion time:</strong> {end_ts} UTC</div>
                <div><strong>Duration:</strong> {duration}</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if status == "FAILED":
        err_msg = meta.get("error_message") or "Unknown analysis error occurred during processing."
        st.error(f"**Analysis Processing Failed**: {err_msg}")
        cf1, _ = st.columns([1, 4])
        with cf1:
            if st.button("Delete Analysis", key=f"btn_del_failed_{pcap_id}", type="primary", use_container_width=True):
                st.session_state["delete_confirm_pcap_id"] = pcap_id
                st.rerun()
        return

    # Telemetry Summary Metrics Cards (Connections, DNS, TLS, Hosts, Packets, Alerts)
    m1, m2, m3, m4, m5, m6 = st.columns(6)
    m1.metric("Connections", f"{meta.get('connections_count', 0):,}")
    m2.metric("DNS Queries", f"{meta.get('dns_queries_count', 0):,}")
    m3.metric("TLS Sessions", f"{meta.get('tls_sessions_count', 0):,}")
    m4.metric("Unique Hosts", f"{meta.get('unique_hosts_count', 0):,}")
    m5.metric("Packets", f"{meta.get('packets_count', 0):,}")
    m6.metric("Fused Alerts", f"{meta.get('alerts_count', 0):,}")

    st.markdown("<br>", unsafe_allow_html=True)

    # 8-Detector Results Matrix
    st.markdown('<div class="soc-section-title">Detector Evaluation Matrix (8 Detectors)</div>', unsafe_allow_html=True)

    detector_results = meta.get("detector_results", {})
    threat_breakdown = meta.get("threat_breakdown", {})

    cols_row1 = st.columns(4)
    cols_row2 = st.columns(4)

    for idx, (display_name, key, default_engine, desc) in enumerate(ALL_DETECTORS):
        col = cols_row1[idx] if idx < 4 else cols_row2[idx - 4]
        det_info = detector_results.get(key, {})
        # Map alert count from either detector_results or threat_breakdown
        alerts_n = det_info.get("alerts_count", threat_breakdown.get(key, 0))
        engine = det_info.get("engine", default_engine)

        is_triggered = alerts_n > 0
        badge_bg = "#FEF3C7" if is_triggered else "#F1F5F9"
        badge_color = "#B45309" if is_triggered else "#475569"
        status_label = f"TRIGGERED ({alerts_n})" if is_triggered else "CLEAR (0)"

        with col:
            st.markdown(
                f"""
                <div class="detector-card" style="margin-bottom: 1rem;">
                    <div class="detector-card-header">{display_name}</div>
                    <div style="margin: 0.4rem 0;">
                        <span style="background-color: {badge_bg}; color: {badge_color}; font-size: 0.72rem; font-weight: 700; padding: 0.15rem 0.4rem; border-radius: 4px;">
                            {status_label}
                        </span>
                    </div>
                    <div class="detector-card-metric">Engine: <strong>{engine}</strong></div>
                    <div style="font-size: 0.75rem; color: #64748B; margin-top: 0.35rem; line-height: 1.3;">
                        {desc}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    st.markdown("<br>", unsafe_allow_html=True)

    # PCAP-Scoped Alerts Section
    st.markdown('<div class="soc-section-title">PCAP-Scoped Security Alerts</div>', unsafe_allow_html=True)

    total_alerts = meta.get("alerts_count", 0)
    if total_alerts == 0:
        st.info("No security threats detected in this capture. All telemetry features remained within benign baseline thresholds.")
        return

    # Filter & Pagination Controls Bar
    f_col1, f_col2, f_col3, f_col4 = st.columns([3, 2, 2, 1.2])
    with f_col1:
        search_query = st.text_input(
            "Search alerts",
            placeholder="Filter by IP, threat type, or ID...",
            label_visibility="collapsed",
            key=f"search_{pcap_id}",
        )
    with f_col2:
        sev_filter = st.selectbox(
            "Severity",
            ["All Severities", "Critical", "High", "Medium", "Low"],
            label_visibility="collapsed",
            key=f"sev_{pcap_id}",
        )
    with f_col3:
        threat_options = ["All Threats"] + [label for _, _, label, _ in [(d[0], d[1], d[0], d[3]) for d in ALL_DETECTORS]]
        threat_filter = st.selectbox(
            "Threat Class",
            threat_options,
            label_visibility="collapsed",
            key=f"threat_{pcap_id}",
        )
    with f_col4:
        page_size = st.selectbox(
            "Page Size",
            [10, 20, 50, 100],
            index=1,
            label_visibility="collapsed",
            key=f"page_size_{pcap_id}",
        )

    # Filter state tracking to reset page to 0 on filter change
    filter_state_key = f"filter_state_{pcap_id}"
    current_filter_state = (
        search_query.strip() if search_query else "",
        sev_filter,
        threat_filter,
        page_size,
    )
    page_key = f"alert_page_{pcap_id}"
    if page_key not in st.session_state:
        st.session_state[page_key] = 0

    if st.session_state.get(filter_state_key) != current_filter_state:
        st.session_state[filter_state_key] = current_filter_state
        st.session_state[page_key] = 0

    curr_page = st.session_state[page_key]

    # Resolve filters
    sev_param = sev_filter.lower() if sev_filter != "All Severities" else None
    threat_param = None
    if threat_filter != "All Threats":
        for name, k, _, _ in ALL_DETECTORS:
            if name == threat_filter:
                threat_param = k
                break
    search_param = search_query.strip() if search_query.strip() else None

    # Total matching alerts via database COUNT query
    total_matching_alerts = fetch_pcap_alerts_count(
        db_path_str=str(db_path),
        pcap_id=pcap_id,
        severity=sev_param,
        threat_class=threat_param,
        search_term=search_param,
    )

    total_pages = max(1, (total_matching_alerts + page_size - 1) // page_size)
    if curr_page >= total_pages:
        curr_page = max(0, total_pages - 1)
        st.session_state[page_key] = curr_page

    scoped_alerts = fetch_pcap_alerts(
        db_path_str=str(db_path),
        pcap_id=pcap_id,
        limit=page_size,
        offset=curr_page * page_size,
        severity=sev_param,
        threat_class=threat_param,
        search_term=search_param,
    )

    if scoped_alerts:
        df_rows = []
        for a in scoped_alerts:
            t_label = THREAT_CLASS_LABELS.get(a.get("threat_class", ""), a.get("threat_class", ""))
            df_rows.append({
                "Timestamp": a.get("timestamp", "")[:19],
                "Threat Class": t_label,
                "Severity": str(a.get("severity", "")).upper(),
                "Source": a.get("source", ""),
                "Destination": a.get("destination", ""),
                "Subtype": a.get("subtype", ""),
                "Confidence": f"{a.get('confidence', 0.0):.2f}",
                "Detector": a.get("detector", ""),
                "Alert ID": a.get("alert_id", "")[:8],
            })

        df = pd.DataFrame(df_rows)
        st.dataframe(df, use_container_width=True, hide_index=True)

        # Pagination controls
        start_idx = curr_page * page_size + 1
        end_idx = min(curr_page * page_size + len(scoped_alerts), total_matching_alerts)
        showing_str = f"Showing {start_idx}–{end_idx} of {total_matching_alerts} alerts"

        p_col1, p_col2, p_col3 = st.columns([1, 2, 1])
        with p_col1:
            if curr_page > 0:
                if st.button("Previous Page", key=f"btn_prev_{pcap_id}", use_container_width=True):
                    st.session_state[page_key] = curr_page - 1
                    st.rerun()
        with p_col2:
            st.markdown(
                f"<div style='text-align: center; font-size: 0.82rem; color: #64748B; padding-top: 0.5rem;'>"
                f"{showing_str}"
                f"</div>",
                unsafe_allow_html=True,
            )
        with p_col3:
            if curr_page < total_pages - 1:
                if st.button("Next Page", key=f"btn_next_{pcap_id}", use_container_width=True):
                    st.session_state[page_key] = curr_page + 1
                    st.rerun()

        # On-demand Alert Payload Inspector (Inspect single alert without DOM serialization explosion)
        with st.expander("Inspect Alert Payload (JSON)"):
            alert_ids = [a["alert_id"] for a in scoped_alerts]
            selected_id = st.selectbox(
                "Select alert to inspect",
                alert_ids,
                format_func=lambda aid: f"Alert {aid[:8]} — {next((a.get('threat_class') for a in scoped_alerts if a['alert_id'] == aid), '')}",
                key=f"sel_inspect_{pcap_id}",
            )
            inspect_target = next((a for a in scoped_alerts if a["alert_id"] == selected_id), None)
            if inspect_target:
                st.json(inspect_target)
    else:
        st.info("No alerts matching current filters.")

    # Dedicated Delete Analysis trigger
    st.markdown("---")
    cd1, _ = st.columns([2, 4])
    with cd1:
        if st.button("Delete This PCAP Analysis", key=f"btn_del_selected_bottom_{pcap_id}", type="secondary", use_container_width=True):
            st.session_state["delete_confirm_pcap_id"] = pcap_id
            st.rerun()


def render_upload_page() -> None:
    _render_header()

    db_path = get_active_db_path()

    # Handle pending delete confirmation
    pending_delete = st.session_state.get("delete_confirm_pcap_id")
    if pending_delete:
        _render_delete_confirmation(pending_delete, db_path)

    # 1. Upload & Ingestion Pipeline Form
    _render_upload_section(db_path)

    # 2. PCAP History
    analyses = fetch_pcap_analyses(str(db_path))
    _render_history_section(analyses, db_path)

    # 3. Selected PCAP Detail View
    selected_pcap_id = st.session_state.get("selected_pcap_id")
    if not selected_pcap_id and analyses:
        # Default selection to most recent PCAP
        selected_pcap_id = analyses[0]["pcap_id"]
        st.session_state["selected_pcap_id"] = selected_pcap_id

    if selected_pcap_id:
        _render_selected_analysis(selected_pcap_id, db_path)


render_upload_page()
