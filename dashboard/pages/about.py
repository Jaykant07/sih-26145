"""dashboard/pages/about.py
About — System information, architecture, and detector overview.
"""

import streamlit as st

# ===== PAGE ENTRY POINT =====

st.markdown('<div class="soc-section-title">About</div>', unsafe_allow_html=True)

st.markdown("**AKSHI**")
st.markdown("AI-Based Detection of Cyber Threats in Unidirectional IP Traffic")

st.markdown("<br>", unsafe_allow_html=True)

# Architecture
st.markdown("**System Architecture**")

arch_components = [
    ("Zeek LTS", "Passive network telemetry ingestion (JSON logs)"),
    ("RITA v5.1.2", "Beacon detection and DNS tunnel analysis"),
    ("Custom Detectors", "DDoS, Reconnaissance, TLS anomaly, Exfiltration"),
    ("AI / ML Detectors", "DGA (Random Forest), Behavioral Anomaly (Isolation Forest)"),
    ("Unified Alert Layer", "Standardized draft alert contract (alerts/draft.py)"),
    ("OT-Aware Fusion", "Source-based correlation, asset criticality, severity escalation"),
    ("SQLite", "Local-first persistent alert storage (WAL mode)"),
    ("Streamlit", "Operator web console and alert drill-down"),
]

for name, desc in arch_components:
    st.markdown(
        f"""<div class="about-arch-item">
            <strong>{name}</strong> &mdash; {desc}
        </div>""",
        unsafe_allow_html=True,
    )

st.markdown("<br>", unsafe_allow_html=True)

# Detectors
st.markdown("**Detection Capabilities (8 Detectors)**")

detectors = [
    ("DDoS", "Statistical & entropy-based volumetric flood detection", "Custom detector", "Track B"),
    ("Reconnaissance", "Port and address scan detection heuristics", "Zeek Scan", "Track A"),
    ("DGA / DNS", "Machine learning algorithmic domain query classifier", "Random Forest", "Track B"),
    ("DNS Tunnelling", "High-frequency DNS query covert channel detection", "RITA", "Track A"),
    ("C2 Beaconing", "Periodic connection beacon interval analysis", "RITA", "Track A"),
    ("Encrypted Malware / TLS", "JA3/JA3S fingerprints & asymmetric flow ratios", "JA3 + behavioral", "Track B"),
    ("Exfiltration", "Asymmetric upload/download data transfer detection", "Custom detector", "Track B"),
    ("AI Behavioral Anomaly", "Unsupervised flow-level behavioral outlier detection", "Isolation Forest", "Track B"),
]

for name, desc, engine, track in detectors:
    st.markdown(
        f"""<div class="about-arch-item">
            <strong>{name}</strong> ({engine}, {track}) &mdash; {desc}
        </div>""",
        unsafe_allow_html=True,
    )

st.markdown("<br>", unsafe_allow_html=True)

# Fusion Pipeline
st.markdown("**OT-Aware Fusion Pipeline**")
st.markdown(
    """
    1. Defense-in-depth ingress validation (fail-closed)
    2. Source-based multi-threat correlation (5-minute window, 2+ distinct threat classes)
    3. Asset criticality resolution (source + destination lookup from config/assets.yaml)
    4. Deterministic severity escalation (base + criticality + correlation)
    5. Final schema validation
    """
)

st.markdown("<br>", unsafe_allow_html=True)

# Project Info
st.markdown("**Project Information**")
st.markdown(
    """
    - **Platform:** AKSHI
    - **Problem Statement:** PS-26145 &mdash; AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
    - **Domain:** Cyber Security / OT Security
    - **Alert Schema:** v1.0.0
    - **Architecture:** Local-first, offline-capable, unidirectional traffic analysis
    - **Dashboard:** Presentation and monitoring only (zero detection logic)
    """
)
