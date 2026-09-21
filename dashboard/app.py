"""dashboard/app.py
Streamlit Main Application for SIH PS-26145 OT Threat Monitoring Dashboard.

Architecture:
- Consumes fused, schema-valid alerts persisted in SQLite.
- Presentation ONLY: zero detection or score calculation logic.
- Professional SOC layout: Blue / Yellow / White / Slate palette.
- Multipage navigation using st.Page / st.navigation.
- Zero decorative animations, emojis, or marketing fluff.
"""

import sys
from pathlib import Path

# Ensure repository root is on sys.path regardless of invocation directory or CLI context
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import streamlit as st

# Configure Streamlit page — must be first st command
st.set_page_config(
    page_title="SIH PS-26145 - OT Cyber Threat Console",
    page_icon=":material/shield:",
    layout="wide",
    initial_sidebar_state="expanded",
)

from dashboard.styles import inject_soc_styles

# Inject global SOC CSS
inject_soc_styles()

# Sidebar branding
with st.sidebar:
    st.markdown(
        """
        <div class="sidebar-brand">
            <div class="sidebar-brand-title">OT SECURITY</div>
            <div class="sidebar-brand-subtitle">Cyber Threat Monitoring Console</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

# Define pages with grouped navigation
pages = {
    "OPERATIONS": [
        st.Page("pages/overview.py", title="Overview", icon=":material/dashboard:", default=True),
        st.Page("pages/upload.py", title="PCAP Ingestion", icon=":material/upload_file:"),
        st.Page("pages/live_monitoring.py", title="Live Monitoring", icon=":material/monitor_heart:"),
        st.Page("pages/incidents.py", title="Incidents", icon=":material/warning:"),
    ],
    "ANALYSIS": [
        st.Page("pages/threat_intel.py", title="Threat Intelligence", icon=":material/policy:"),
        st.Page("pages/analytics.py", title="Analytics", icon=":material/analytics:"),
    ],
    "LAB": [
        st.Page("pages/demo_lab.py", title="Demo Lab", icon=":material/science:"),
        st.Page("pages/asset_inventory.py", title="OT Asset Inventory", icon=":material/inventory:"),
    ],
    "SYSTEM": [
        st.Page("pages/about.py", title="About", icon=":material/info:"),
    ],
}

# Render navigation
pg = st.navigation(pages)

# Run selected page
pg.run()
