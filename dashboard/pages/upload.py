"""dashboard/pages/upload.py
PCAP Ingestion & Telemetry Analysis Page for SIH PS-26145 OT Threat Monitoring Console.

Allows operators to upload .pcap / .pcapng files into the existing pipeline:
  1. Validates magic bytes and file integrity.
  2. Saves into temporary, isolated artifacts/uploads/<uuid>/ workspace.
  3. Executes Zeek inside Docker (with JA3 and Scan scripts).
  4. Feeds telemetry through all 7 detectors.
  5. Passes draft alerts through OT-Aware Fusion.
  6. Persists schema-compliant alerts into SQLite datastore.
"""

from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import streamlit as st

from dashboard.db import get_active_db_path
from ingest.pcap_pipeline import (
    PCAPProcessingError,
    PCAPValidationError,
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
}


def _render_header() -> None:
    """Render standardized top SOC header bar."""
    utc_now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    st.markdown(
        f"""
        <div style="background-color: #FFFFFF; border: 1px solid #E2E8F0; border-radius: 6px; padding: 1rem 1.5rem; margin-bottom: 1.5rem;">
            <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 0.75rem;">
                <div>
                    <h1 style="font-size: 1.5rem; font-weight: 700; color: #0F172A; margin: 0 0 0.25rem 0; letter-spacing: -0.02em;">
                        OT CYBER THREAT MONITORING CONSOLE
                    </h1>
                    <div style="font-size: 0.85rem; color: #64748B; font-weight: 500;">
                        OPERATIONS // PCAP INGESTION & PIPELINE EXECUTION
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


def _render_isolation_notice() -> None:
    """Render notice regarding isolation and non-canonical scoping."""
    st.markdown(
        """
        <div style="background-color: #F8FAFC; border-left: 4px solid #2563EB; padding: 0.85rem 1.25rem; border-radius: 4px; margin-bottom: 1.5rem; font-size: 0.85rem; color: #334155;">
            <strong>Pipeline Isolation Guarantee:</strong> Uploaded captures and derived logs are strictly scoped to
            <code>artifacts/uploads/&lt;session_uuid&gt;/</code>. They are tagged as non-canonical (<code>canonical=False</code>)
            and do not alter the immutable baseline datasets in <code>data/raw/</code>.
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_upload_page() -> None:
    _render_header()
    _render_isolation_notice()

    db_path = get_active_db_path()

    # Upload section
    st.markdown(
        """
        <div style="background-color: #FFFFFF; border: 1px solid #E2E8F0; border-radius: 6px; padding: 1.25rem; margin-bottom: 1.5rem;">
            <div style="font-size: 0.95rem; font-weight: 700; color: #0F172A; margin-bottom: 0.5rem;">
                Select Network Packet Capture (.pcap / .pcapng)
            </div>
            <div style="font-size: 0.82rem; color: #64748B; margin-bottom: 1rem;">
                Files are processed through Zeek with JA3/JA3S fingerprinting, Scan detection, and all 7 threat detectors.
                Default upload limit is 200 MB.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    uploaded_file = st.file_uploader(
        "Upload Capture File",
        type=["pcap", "pcapng"],
        help="Standard libpcap or pcapng format. Maximum file size: 200 MB (Streamlit default).",
        label_visibility="collapsed",
    )

    if uploaded_file is not None:
        file_bytes = uploaded_file.getvalue()
        file_size_kb = len(file_bytes) / 1024
        file_size_mb = file_size_kb / 1024

        col1, col2, col3 = st.columns(3)
        col1.metric("Selected File", uploaded_file.name)
        col2.metric("File Size", f"{file_size_mb:.2f} MB" if file_size_mb >= 1.0 else f"{file_size_kb:.1f} KB")
        col3.metric("Datastore Target", Path(db_path).name)

        if st.button("Start Pipeline Ingestion", type="primary", use_container_width=True):
            # Processing container
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
                    result = process_pcap_upload(
                        pcap_data=file_bytes,
                        original_filename=uploaded_file.name,
                        db_path=db_path,
                        progress_callback=on_progress,
                    )
                    st.session_state["last_upload_result"] = result
                    st.success(f"Capture processed successfully! Generated {result['fused_alerts_count']} fused alert(s).")
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
                    st.error(f"**Unexpected Pipeline Error**: {ex}")

    # Display results if available in session state
    if "last_upload_result" in st.session_state:
        res = st.session_state["last_upload_result"]
        st.markdown("---")
        st.markdown(
            f"""
            <div style="background-color: #FFFFFF; border: 1px solid #E2E8F0; border-radius: 6px; padding: 1.25rem; margin-bottom: 1rem;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
                    <div>
                        <span style="font-size: 1.1rem; font-weight: 700; color: #0F172A;">Ingestion Results Summary</span>
                        <span style="margin-left: 0.5rem; font-size: 0.75rem; background-color: #F1F5F9; color: #475569; padding: 0.2rem 0.5rem; border-radius: 4px; font-family: monospace;">
                            UUID: {res['upload_id'][:8]}...
                        </span>
                    </div>
                    <div style="font-size: 0.8rem; color: #64748B;">
                        Scoped Artifacts: <code>{res['upload_dir']}</code>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Total Fused Alerts", res["fused_alerts_count"])
        m2.metric("Threat Classes Triggered", len(res["threat_breakdown"]))
        m3.metric("Execution Time", f"{res['processing_time_seconds']}s")
        m4.metric("File Size", f"{res['file_size_bytes'] / 1024:.1f} KB")

        # Threat breakdown
        if res["threat_breakdown"]:
            st.markdown("#### Threat Class Breakdown")
            breakdown_cols = st.columns(len(res["threat_breakdown"]))
            for idx, (tclass, count) in enumerate(res["threat_breakdown"].items()):
                with breakdown_cols[idx]:
                    label = THREAT_CLASS_LABELS.get(tclass, tclass.replace("_", " ").title())
                    st.metric(label, count)

        # Alerts table
        alerts = res.get("alerts", [])
        if alerts:
            st.markdown("#### Generated Alerts")
            df_rows = []
            for a in alerts:
                t_label = THREAT_CLASS_LABELS.get(a.get("threat_class", ""), a.get("threat_class", ""))
                df_rows.append({
                    "Timestamp": a.get("timestamp", ""),
                    "Threat Class": t_label,
                    "Severity": str(a.get("severity", "")).upper(),
                    "Source": a.get("source", ""),
                    "Destination": a.get("destination", ""),
                    "Subtype": a.get("subtype", ""),
                    "Confidence": f"{a.get('confidence', 0.0):.2f}",
                    "Detector": a.get("detector", ""),
                    "Correlation ID": a.get("correlation_id") or "Uncorrelated",
                })
            df = pd.DataFrame(df_rows)
            st.dataframe(df, use_container_width=True, hide_index=True)

            with st.expander("Inspect Raw Alert Payloads (JSON)"):
                st.json(alerts)

            # Navigation buttons
            nav_col1, nav_col2 = st.columns(2)
            with nav_col1:
                if st.button("Open Incidents Console", type="primary", use_container_width=True):
                    st.switch_page("pages/incidents.py")
            with nav_col2:
                if st.button("Open Threat Overview", use_container_width=True):
                    st.switch_page("pages/overview.py")
        else:
            st.info("No security threats detected in this capture. Telemetry and flow features remained within benign thresholds.")


render_upload_page()
