"""dashboard/pages/threat_intel.py
Threat Intelligence — Offline JA3/JA3S suspicious fingerprint snapshot.
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

JA3_BLACKLIST_PATH = Path("data/intel/ja3_blacklist.json")


def _load_ja3_blacklist() -> dict:
    """Load offline JA3/JA3S blacklist from local file."""
    if not JA3_BLACKLIST_PATH.is_file():
        return {}
    try:
        with open(JA3_BLACKLIST_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


# ===== PAGE ENTRY POINT =====

db_path = get_active_db_path()
db_path_str = str(db_path)
is_online, _, _ = check_db_status(db_path)

st.markdown('<div class="soc-section-title">Threat Intelligence</div>', unsafe_allow_html=True)

# Load JA3 blacklist
blacklist = _load_ja3_blacklist()
metadata = blacklist.get("snapshot_metadata", {})
ja3_entries = blacklist.get("ja3", {})
ja3s_entries = blacklist.get("ja3s", {})

# JA3 Fingerprint Table
st.markdown("**JA3 Suspicious Fingerprints**")
if ja3_entries:
    rows = []
    for hash_val, info in ja3_entries.items():
        rows.append({
            "JA3 Hash": hash_val,
            "Family": info.get("family", "Unknown"),
            "Threat": info.get("threat", ""),
            "Confidence": info.get("confidence", 0),
            "Source": info.get("source", ""),
        })
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
else:
    st.info("No JA3 fingerprints loaded.")

st.markdown("<br>", unsafe_allow_html=True)

# JA3S Fingerprint Table
st.markdown("**JA3S Server Fingerprints**")
if ja3s_entries:
    rows = []
    for hash_val, info in ja3s_entries.items():
        rows.append({
            "JA3S Hash": hash_val,
            "Family": info.get("family", "Unknown"),
            "Threat": info.get("threat", ""),
            "Confidence": info.get("confidence", 0),
            "Source": info.get("source", ""),
        })
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
else:
    st.info("No JA3S fingerprints loaded.")

st.markdown("<br>", unsafe_allow_html=True)

# TLS Alert Matches
st.markdown("**TLS Intelligence Matches**")
if is_online:
    tls_alerts = fetch_alerts(db_path_str, limit=50)
    tls_alerts = [a for a in tls_alerts if a.get("threat_class") == "tls_anomaly"]

    if tls_alerts:
        match_rows = []
        for a in tls_alerts:
            evidence = a.get("supporting_evidence", {})
            if isinstance(evidence, str):
                try:
                    evidence = json.loads(evidence)
                except Exception:
                    evidence = {}
            ja3_hash = evidence.get("ja3", "N/A")
            ja3_match = evidence.get("ja3_match", "No match")
            match_rows.append({
                "JA3": ja3_hash,
                "Match": ja3_match,
                "Source": a.get("source", ""),
                "Destination": a.get("destination", ""),
                "Timestamp": a.get("timestamp", "")[:19],
                "Detector": a.get("detector", ""),
            })
        st.dataframe(pd.DataFrame(match_rows), use_container_width=True, hide_index=True)
    else:
        st.info("No TLS anomaly alerts recorded.")
else:
    st.info("Database offline. Cannot display TLS matches.")
