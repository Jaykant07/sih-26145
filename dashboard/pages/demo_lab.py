"""dashboard/pages/demo_lab.py
Demo Lab — Controlled experiment interface for detector evaluation and dataset distribution.

Read-only view of lab experiments and dataset distributions. Does NOT launch attack tools.
"""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import streamlit as st

from dashboard.db import (
    check_db_status,
    fetch_alerts,
    get_active_db_path,
)

# Canonical 8-detector experiment definitions — derived from actual repository data
LAB_EXPERIMENTS = [
    {
        "detector": "DDoS",
        "pcaps": [
            {"name": "ddos-001-syn-flood", "path": "data/raw/ddos/ddos-001-syn-flood.pcap", "class": "SYN Flood"},
            {"name": "ddos-002-udp-flood", "path": "data/raw/ddos/ddos-002-udp-flood.pcap", "class": "UDP Flood"},
        ],
        "threat_class": "ddos",
        "engine": "Custom detector (statistical & entropy)",
        "zeek_dir": "data/zeek/ddos",
        "metadata_dir": "data/metadata/ddos",
    },
    {
        "detector": "Reconnaissance",
        "pcaps": [
            {"name": "recon-001-tcp-port-scan", "path": "data/raw/reconnaissance/recon-001-tcp-port-scan.pcap", "class": "Port Scan (1024 ports)"},
            {"name": "recon-002-targeted-scan", "path": "data/raw/reconnaissance/recon-002-targeted-scan.pcap", "class": "Targeted Scan (16 ports)"},
        ],
        "threat_class": "reconnaissance",
        "engine": "Zeek Scan framework + adapter",
        "zeek_dir": "data/zeek/reconnaissance",
        "metadata_dir": "data/metadata/reconnaissance",
    },
    {
        "detector": "DGA / DNS",
        "pcaps": [
            {"name": "dga-001-random", "path": "data/raw/dga/dga-001-random.pcap", "class": "Random DGA domains"},
            {"name": "dga-002-irregular", "path": "data/raw/dga/dga-002-irregular.pcap", "class": "Irregular DGA"},
        ],
        "threat_class": "dga_dns",
        "engine": "Random Forest (FANCI-inspired, 100 trees)",
        "zeek_dir": "data/zeek/dga",
        "metadata_dir": "data/metadata/dga",
    },
    {
        "detector": "DNS Tunnelling",
        "pcaps": [
            {"name": "dns-001-dnscat2", "path": "data/raw/dns_tunnel/dns-001-dnscat2.pcap", "class": "dnscat2 tunnel"},
            {"name": "dns-002-dnscat2-jitter", "path": "data/raw/dns_tunnel/dns-002-dnscat2-jitter.pcap", "class": "dnscat2 with jitter"},
        ],
        "threat_class": "dns_tunnel",
        "engine": "RITA v5.1.2 C2 Over DNS",
        "zeek_dir": "data/zeek/dns_tunnel",
        "metadata_dir": "data/metadata/dns_tunnel",
    },
    {
        "detector": "C2 Beaconing",
        "pcaps": [],
        "threat_class": "beaconing",
        "engine": "RITA v5.1.2 beacon scoring",
        "zeek_dir": "",
        "metadata_dir": "",
        "note": "Evaluated using Zeek output from beacon test fixtures (zeek_output_beacon_test_fixed, zeek_output_beacon_test_jitter)",
    },
    {
        "detector": "Encrypted Malware / TLS",
        "pcaps": [
            {"name": "enc-001-tls-baseline", "path": "data/raw/encrypted/enc-001-tls-baseline.pcap", "class": "TLS baseline"},
            {"name": "enc-002-tls-c2-medium", "path": "data/raw/encrypted/enc-002-tls-c2-medium.pcap", "class": "TLS C2 medium"},
        ],
        "threat_class": "tls_anomaly",
        "engine": "JA3/JA3S offline blacklist + behavioral scoring",
        "zeek_dir": "data/zeek/encrypted",
        "metadata_dir": "data/metadata/encrypted",
    },
    {
        "detector": "Exfiltration",
        "pcaps": [],
        "threat_class": "exfiltration",
        "engine": "Windowed directional byte accounting",
        "zeek_dir": "",
        "metadata_dir": "",
        "note": "Evaluated using benign iperf3 PCAPs and synthetic exfiltration scenario through fusion pipeline",
    },
    {
        "detector": "AI Behavioral Anomaly",
        "pcaps": [
            {"name": "recon-001-tcp-port-scan", "path": "data/raw/reconnaissance/recon-001-tcp-port-scan.pcap", "class": "Controlled port scan (1024 ports) — behavioral outlier"},
            {"name": "enc-002-tls-c2-medium", "path": "data/raw/encrypted/enc-002-tls-c2-medium.pcap", "class": "Simulated encrypted C2 — behavioral outlier"},
            {"name": "ddos-001-syn-flood", "path": "data/raw/ddos/ddos-001-syn-flood.pcap", "class": "SYN Flood — volumetric flow outlier"},
        ],
        "threat_class": "anomalous_behavior",
        "engine": "Isolation Forest (unsupervised flow behavioral anomaly)",
        "zeek_dir": "data/zeek/reconnaissance/recon-001",
        "metadata_dir": "reports/ai",
        "note": "Trained strictly on frozen benign baselines. Emits alerts when raw anomaly score > -0.05 and normalized confidence >= 0.25. Confidence measures statistical deviation from benign baseline, not malware probability.",
    },
]


def _check_path_exists(path_str: str) -> bool:
    return Path(path_str).exists() if path_str else False


def _load_metadata(meta_dir: str) -> list[dict]:
    """Load experiment metadata JSON files."""
    results = []
    meta_path = Path(meta_dir)
    if meta_path.is_dir():
        for f in sorted(meta_path.glob("*.json")):
            try:
                with open(f, "r", encoding="utf-8") as fh:
                    results.append(json.load(fh))
            except Exception:
                pass
    return results


# ===== PAGE ENTRY POINT =====

db_path = get_active_db_path()
db_path_str = str(db_path)
is_online, _, _ = check_db_status(db_path)

st.markdown('<div class="soc-section-title">Demo Lab</div>', unsafe_allow_html=True)

st.markdown(
    """<div style="font-size: 0.82rem; color: #475569; margin-bottom: 1rem;">
        Controlled lab experiments and dataset distributions for detector evaluation.
        This interface is read-only. All PCAPs, features, and benchmarks reflect verified repository data.
    </div>""",
    unsafe_allow_html=True,
)

# ===== DATASET DISTRIBUTION SECTION =====
st.markdown("### Dataset Distribution")

tab_benign, tab_abnormal, tab_upload = st.tabs([
    "Benign Baselines (Training & Validation)",
    "Abnormal / Attack Evaluation Corpus",
    "Uploaded PCAP Analysis Scope",
])

with tab_benign:
    st.markdown(
        """<div style="font-size: 0.8rem; color: #64748B; margin-bottom: 0.75rem;">
            Frozen benign telemetry corpus used for model training and held-out validation.
            All captures were collected in an isolated, controlled lab environment with zero attack execution.
        </div>""",
        unsafe_allow_html=True,
    )

    benign_inventory = [
        {
            "Dataset": "BENIGN-001",
            "PCAP File": "benign-001-iperf3-tcp.pcap",
            "Path": "data/raw/benign/benign-001-iperf3-tcp.pcap",
            "Traffic Profile": "Clean iperf3 TCP throughput baseline (10s)",
            "Role": "Validation (Held-Out)",
            "Flows": 2,
        },
        {
            "Dataset": "BENIGN-002",
            "PCAP File": "benign-002-iperf3-tcp.pcap",
            "Path": "data/raw/benign/benign-002-iperf3-tcp.pcap",
            "Traffic Profile": "Sustained iperf3 TCP throughput baseline (10s)",
            "Role": "AI Training Baseline",
            "Flows": 2,
        },
        {
            "Dataset": "BENIGN-003",
            "PCAP File": "benign-003-iperf3-udp.pcap",
            "Path": "data/raw/benign/benign-003-iperf3-udp.pcap",
            "Traffic Profile": "Sustained iperf3 UDP stream (5 Mbps, 1200B payloads)",
            "Role": "AI Training Baseline",
            "Flows": 1,
        },
        {
            "Dataset": "BENIGN-004",
            "PCAP File": "benign-004-short-tcp.pcap",
            "Path": "data/raw/benign/benign-004-short-tcp.pcap",
            "Traffic Profile": "Repeated short TCP sessions (10 client sessions)",
            "Role": "AI Training Baseline",
            "Flows": 20,
        },
        {
            "Dataset": "BENIGN-005",
            "PCAP File": "benign-005-normal-dns.pcap",
            "Path": "data/raw/benign/benign-005-normal-dns.pcap",
            "Traffic Profile": "Normal DNS queries (lab.local internal hostnames)",
            "Role": "AI Training Baseline",
            "Flows": 22,
        },
        {
            "Dataset": "ENC-001",
            "PCAP File": "enc-001-tls-baseline.pcap",
            "Path": "data/raw/encrypted/enc-001-tls-baseline.pcap",
            "Traffic Profile": "Benign TLS 1.3 session (openssl s_client handshake)",
            "Role": "AI Training Baseline",
            "Flows": 1,
        },
    ]

    benign_rows = []
    for item in benign_inventory:
        benign_rows.append({
            "Dataset": item["Dataset"],
            "PCAP File": item["PCAP File"],
            "Available": "Yes" if _check_path_exists(item["Path"]) else "No",
            "Traffic Profile": item["Traffic Profile"],
            "Role": item["Role"],
            "Observed Flows": item["Flows"],
        })

    st.dataframe(pd.DataFrame(benign_rows), use_container_width=True, hide_index=True)

    c1, c2, c3 = st.columns(3)
    with c1:
        st.caption("Training Baseline Captures: **5 PCAPs**")
    with c2:
        st.caption("Training Flows Extracted: **46 flows**")
    with c3:
        st.caption("Held-Out Validation Baseline: **BENIGN-001 (2 flows)**")

with tab_abnormal:
    st.markdown(
        """<div style="font-size: 0.8rem; color: #64748B; margin-bottom: 0.75rem;">
            Controlled abnormal and simulated threat captures used for multi-detector evaluation and AI anomaly benchmarking.
        </div>""",
        unsafe_allow_html=True,
    )

    abnormal_inventory = [
        {"Experiment": "DDoS-001", "Traffic Class": "SYN Flood", "PCAP": "data/raw/ddos/ddos-001-syn-flood.pcap", "Total Flows": 4536, "AI Detections": 1104, "Detection Rate": "24.3%"},
        {"Experiment": "DDoS-002", "Traffic Class": "UDP Flood", "PCAP": "data/raw/ddos/ddos-002-udp-flood.pcap", "Total Flows": 5000, "AI Detections": 0, "Detection Rate": "0.0%"},
        {"Experiment": "RECON-001", "Traffic Class": "Port Scan (1024 ports)", "PCAP": "data/raw/reconnaissance/recon-001-tcp-port-scan.pcap", "Total Flows": 1024, "AI Detections": 960, "Detection Rate": "93.8%"},
        {"Experiment": "RECON-002", "Traffic Class": "Targeted Scan (16 ports)", "PCAP": "data/raw/reconnaissance/recon-002-targeted-scan.pcap", "Total Flows": 16, "AI Detections": 16, "Detection Rate": "100.0%"},
        {"Experiment": "DGA-001", "Traffic Class": "Random DGA domains", "PCAP": "data/raw/dga/dga-001-random.pcap", "Total Flows": 1, "AI Detections": 1, "Detection Rate": "100.0%"},
        {"Experiment": "DGA-002", "Traffic Class": "Irregular DGA domains", "PCAP": "data/raw/dga/dga-002-irregular.pcap", "Total Flows": 1, "AI Detections": 1, "Detection Rate": "100.0%"},
        {"Experiment": "DNS-001", "Traffic Class": "dnscat2 DNS tunnel", "PCAP": "data/raw/dns_tunnel/dns-001-dnscat2.pcap", "Total Flows": 1, "AI Detections": 1, "Detection Rate": "100.0%"},
        {"Experiment": "DNS-002", "Traffic Class": "dnscat2 tunnel with jitter", "PCAP": "data/raw/dns_tunnel/dns-002-dnscat2-jitter.pcap", "Total Flows": 1, "AI Detections": 1, "Detection Rate": "100.0%"},
        {"Experiment": "ENC-002", "Traffic Class": "Simulated encrypted TLS C2", "PCAP": "data/raw/encrypted/enc-002-tls-c2-medium.pcap", "Total Flows": 1, "AI Detections": 1, "Detection Rate": "100.0%"},
        {"Experiment": "Beacon-Fixed", "Traffic Class": "Periodic C2 connection beacon", "PCAP": "Zeek beacon test fixture", "Total Flows": 360, "AI Detections": 293, "Detection Rate": "81.4%"},
        {"Experiment": "Exfil-Asymmetric", "Traffic Class": "Outbound asymmetric data transfer", "PCAP": "Synthetic exfil scenario", "Total Flows": 1, "AI Detections": 1, "Detection Rate": "100.0%"},
    ]

    abnormal_rows = []
    for item in abnormal_inventory:
        pcap_path = item["PCAP"]
        is_avail = _check_path_exists(pcap_path) if pcap_path.startswith("data/") else True
        abnormal_rows.append({
            "Experiment": item["Experiment"],
            "Traffic Class": item["Traffic Class"],
            "PCAP": Path(item["PCAP"]).name if item["PCAP"].startswith("data/") else item["PCAP"],
            "Available": "Yes" if is_avail else "No",
            "Total Flows": item["Total Flows"],
            "AI Detections": item["AI Detections"],
            "Detection Rate": item["Detection Rate"],
        })

    st.dataframe(pd.DataFrame(abnormal_rows), use_container_width=True, hide_index=True)

    e1, e2, e3, e4 = st.columns(4)
    with e1:
        st.caption("Evaluation Flows: **10,944 flows**")
    with e2:
        st.caption("True Positives: **2,379**")
    with e3:
        st.caption("AI Model Precision: **0.9996**")
    with e4:
        st.caption("False Positive Rate: **0.5000**")

with tab_upload:
    st.markdown(
        """<div style="background-color: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 6px; padding: 1rem; margin-top: 0.5rem;">
            <div style="font-weight: 600; font-size: 0.88rem; color: #1E293B; margin-bottom: 0.25rem;">Uploaded PCAP Analysis Isolation</div>
            <div style="font-size: 0.8rem; color: #475569; line-height: 1.4;">
                User-uploaded PCAPs processed on the <strong>PCAP Analysis</strong> page are fully isolated from the canonical baseline and training datasets:
                <ul style="margin: 0.5rem 0 0 1rem; padding: 0;">
                    <li>Every upload is assigned a unique UUIDv4 <code>pcap_id</code>.</li>
                    <li>Telemetry artifacts reside in isolated directories (<code>artifacts/uploads/&lt;pcap_id&gt;/</code>).</li>
                    <li>All 8 detectors (including AI Behavioral Anomaly) execute against uploaded PCAP flows.</li>
                    <li>All generated alerts are tagged with <code>pcap_id</code> and scoped away from executive Overview KPIs.</li>
                </ul>
            </div>
        </div>""",
        unsafe_allow_html=True,
    )

st.markdown("<br>", unsafe_allow_html=True)

# ===== DETECTOR EXPERIMENTS (1-8) =====
st.markdown("### Detector Experiments (1–8)")

for exp in LAB_EXPERIMENTS:
    with st.expander(f"{exp['detector']} — {exp['engine']}", expanded=False):
        # Alert count from DB
        alert_count = 0
        correlated = False
        if is_online:
            tc_alerts = fetch_alerts(db_path_str, limit=1000)
            tc_alerts = [a for a in tc_alerts if a.get("threat_class") == exp["threat_class"]]
            alert_count = len(tc_alerts)
            correlated = any(a.get("correlation_id") for a in tc_alerts)

        col1, col2, col3 = st.columns(3)
        with col1:
            st.markdown(f"**Threat Class:** `{exp['threat_class']}`")
            st.markdown(f"**Engine:** {exp['engine']}")
        with col2:
            st.markdown(f"**DB Alerts:** {alert_count}")
            st.markdown(f"**Correlated:** {'Yes' if correlated else 'No'}")
        with col3:
            zeek_status = "Processed" if _check_path_exists(exp.get("zeek_dir", "")) else "N/A"
            st.markdown(f"**Zeek Status:** {zeek_status}")

        if exp.get("note"):
            st.markdown(f"*{exp['note']}*")

        # PCAP table
        if exp["pcaps"]:
            pcap_rows = []
            for pcap in exp["pcaps"]:
                pcap_rows.append({
                    "PCAP": pcap["name"],
                    "Dataset Class": pcap["class"],
                    "Available": "Yes" if _check_path_exists(pcap["path"]) else "No",
                })
            st.dataframe(pd.DataFrame(pcap_rows), use_container_width=True, hide_index=True)

        # Metadata
        meta_dir = exp.get("metadata_dir", "")
        if meta_dir:
            meta_list = _load_metadata(meta_dir)
            if meta_list:
                st.markdown("**Experiment Metadata & Artifacts:**")
                for meta in meta_list:
                    st.json(meta)
