"""dashboard/pages/demo_lab.py
Demo Lab — Controlled experiment interface for detector evaluation.

Read-only view of lab experiments. Does NOT launch attack tools.
"""

import json
from pathlib import Path

import pandas as pd
import streamlit as st

from dashboard.db import (
    check_db_status,
    fetch_alerts,
    get_active_db_path,
)

# Lab experiment definitions — derived from actual repository data
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
        Controlled lab experiments for detector evaluation. This interface is read-only.
        PCAPs and results are from the project's test dataset.
    </div>""",
    unsafe_allow_html=True,
)

# Benign baseline
st.markdown("**Benign Baselines**")
benign_pcaps = [
    ("benign-001-iperf3-tcp", "data/raw/benign/benign-001-iperf3-tcp.pcap"),
    ("benign-002-iperf3-tcp", "data/raw/benign/benign-002-iperf3-tcp.pcap"),
]
benign_rows = []
for name, path in benign_pcaps:
    benign_rows.append({
        "PCAP": name,
        "Available": "Yes" if _check_path_exists(path) else "No",
        "Type": "Clean iperf3 TCP traffic",
    })
st.dataframe(pd.DataFrame(benign_rows), use_container_width=True, hide_index=True)

st.markdown("<br>", unsafe_allow_html=True)

# Detector Experiments
st.markdown("**Detector Experiments**")

for exp in LAB_EXPERIMENTS:
    with st.expander(f"{exp['detector']} ({exp['engine']})", expanded=False):
        # Alert count from DB
        alert_count = 0
        correlated = False
        if is_online:
            tc_alerts = fetch_alerts(db_path_str, limit=100)
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
                st.markdown("**Experiment Metadata:**")
                for meta in meta_list:
                    st.json(meta)
