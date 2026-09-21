"""dashboard/styles.py
SIH PS-26145 - OT Cyber Threat Dashboard
Design Hierarchy & CSS Styling

Strict SOC palette:
- Blue: #1E3A8A (Navy), #2563EB (Primary Blue), #1D4ED8, #3B82F6 (Accent Blue), #DBEAFE
- Yellow: #EAB308 (Vivid SOC Yellow), #FACC15 (Bright Yellow), #CA8A04 (Dark Gold Yellow), #FEF08A / #FEF9C3 (Soft Yellow)
- White & Neutrals: #FFFFFF, #F8FAFC, #F1F5F9, #E2E8F0, #64748B, #334155, #0F172A

Zero animations, zero glowing borders, zero decorative gradients.
Streamlit deploy buttons, toolbar links, and decoration completely hidden.
"""

import streamlit as st

SOC_CSS = """
<style>
/* Hide Streamlit default header bar, deploy button, and decorations */
header,
[data-testid="stHeader"],
.stDeployButton,
[data-testid="stDeployButton"],
[data-testid="stToolbarActions"],
[data-testid="stHeaderActionElements"],
[data-testid="stDecoration"],
#MainMenu,
footer {
    display: none !important;
    visibility: hidden !important;
    height: 0 !important;
    margin: 0 !important;
    padding: 0 !important;
}

/* Adjust container padding to keep header fully visible and well-spaced */
.block-container {
    padding-top: 2rem !important;
    padding-bottom: 2rem !important;
    padding-left: 2.2rem !important;
    padding-right: 2.2rem !important;
    max-width: 1440px;
}

/* Base overrides */
.stApp {
    background-color: #F8FAFC;
    color: #0F172A;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}

/* ===== SIDEBAR STYLING (DARK NAVY SOC THEME) ===== */
[data-testid="stSidebar"],
[data-testid="stSidebar"] > div:first-child,
[data-testid="stSidebarContent"] {
    background-color: #0F172A !important;
    color: #F8FAFC !important;
    border-right: 1px solid #1E293B !important;
}

[data-testid="stSidebar"] [data-testid="stMarkdown"] p {
    color: #CBD5E1 !important;
    font-size: 0.85rem;
}

[data-testid="stSidebar"] .sidebar-brand {
    padding: 1.1rem 1rem 0.6rem 1rem;
    border-bottom: 2px solid #EAB308;
    margin-bottom: 0.75rem;
}

[data-testid="stSidebar"] .sidebar-brand-title {
    font-size: 0.95rem;
    font-weight: 800;
    color: #FFFFFF !important;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    margin: 0;
}

[data-testid="stSidebar"] .sidebar-brand-subtitle {
    font-size: 0.72rem;
    color: #94A3B8 !important;
    margin-top: 2px;
}

[data-testid="stSidebar"] .sidebar-group-label {
    font-size: 0.68rem;
    font-weight: 700;
    color: #94A3B8 !important;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    padding: 0.75rem 0.5rem 0.25rem 0.5rem;
    margin: 0;
}

/* Multipage Nav Section Headers (OPERATIONS, ANALYSIS, LAB, SYSTEM) */
[data-testid="stSidebarNav"] [data-testid="stSidebarNavItems"] > div > span,
[data-testid="stSidebarNav"] [data-testid="stSidebarNavItems"] > li > span,
[data-testid="stSidebarNav"] [data-testid="stSidebarNavItems"] span,
[data-testid="stSidebarNav"] h2,
[data-testid="stSidebarNav"] h3 {
    font-size: 0.68rem !important;
    font-weight: 700 !important;
    color: #94A3B8 !important;
    text-transform: uppercase !important;
    letter-spacing: 0.08em !important;
}

/* Nav links - inactive */
[data-testid="stSidebarNavLink"] {
    background-color: transparent !important;
    color: #CBD5E1 !important;
    border-radius: 4px !important;
    padding: 0.4rem 0.7rem !important;
    margin: 0.1rem 0 !important;
    transition: background-color 0.15s ease-in-out;
}

[data-testid="stSidebarNavLink"] span {
    color: #CBD5E1 !important;
    font-size: 0.85rem !important;
    font-weight: 500 !important;
}

[data-testid="stSidebarNavLink"] [data-testid="stIconMaterial"] {
    color: #93C5FD !important;
}

/* Nav links - hover */
[data-testid="stSidebarNavLink"]:hover {
    background-color: #1E293B !important;
}

[data-testid="stSidebarNavLink"]:hover span {
    color: #FFFFFF !important;
}

/* Nav links - active / current page */
[data-testid="stSidebarNavLink"][aria-current="page"] {
    background-color: #1D4ED8 !important;
    border-left: 3px solid #EAB308 !important;
}

[data-testid="stSidebarNavLink"][aria-current="page"] span {
    color: #FFFFFF !important;
    font-weight: 700 !important;
}

[data-testid="stSidebarNavLink"][aria-current="page"] [data-testid="stIconMaterial"] {
    color: #FEF08A !important;
}

/* Sidebar separators */
[data-testid="stSidebarNavSeparator"] {
    border-color: #1E293B !important;
}

/* Sidebar form widgets & inputs */
[data-testid="stSidebar"] label {
    color: #CBD5E1 !important;
    font-size: 0.8rem !important;
}

[data-testid="stSidebar"] input {
    background-color: #1E293B !important;
    color: #F8FAFC !important;
    border: 1px solid #334155 !important;
}

[data-testid="stSidebar"] [data-baseweb="select"] > div {
    background-color: #1E293B !important;
    border-color: #334155 !important;
    color: #F8FAFC !important;
}

[data-testid="stSidebar"] [data-baseweb="tag"] {
    background-color: #334155 !important;
    color: #F8FAFC !important;
}

[data-testid="stSidebarCollapseButton"] button {
    color: #94A3B8 !important;
}

/* ===== HEADER ===== */
.soc-header {
    background-color: #1E3A8A;
    color: #FFFFFF;
    padding: 1.1rem 1.5rem;
    border-radius: 6px;
    margin-top: 0.25rem;
    margin-bottom: 1.25rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 3.5px solid #EAB308;
    box-sizing: border-box;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.08);
}

.soc-header-title {
    font-size: 1.2rem;
    font-weight: 800;
    letter-spacing: 0.03em;
    color: #FFFFFF;
    margin: 0;
    padding: 0;
    line-height: 1.25;
}

.soc-header-subtitle {
    font-size: 0.78rem;
    color: #93C5FD;
    margin-top: 4px;
    line-height: 1.35;
    font-weight: 500;
}

.soc-header-meta {
    font-size: 0.78rem;
    color: #E2E8F0;
    text-align: right;
    line-height: 1.5;
    flex-shrink: 0;
    padding-left: 1.5rem;
}

/* Status badge in Yellow / Blue theme (no green or red) */
.soc-status-badge {
    display: inline-block;
    padding: 0.2rem 0.5rem;
    border-radius: 3px;
    font-size: 0.7rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

.status-live {
    background-color: #FEF08A;
    color: #713F12;
    border: 1px solid #EAB308;
}

.status-offline {
    background-color: #F1F5F9;
    color: #475569;
    border: 1px solid #94A3B8;
}

/* ===== KPI CARDS ===== */
.kpi-card {
    background-color: #FFFFFF;
    border: 1px solid #E2E8F0;
    border-radius: 4px;
    padding: 0.75rem 1rem;
    text-align: left;
    margin-bottom: 0.5rem;
}

.kpi-card-critical { border-left: 4px solid #CA8A04; }
.kpi-card-high { border-left: 4px solid #EAB308; }
.kpi-card-medium { border-left: 4px solid #2563EB; }
.kpi-card-info { border-left: 4px solid #1E3A8A; }

.kpi-title {
    font-size: 0.7rem;
    font-weight: 600;
    text-transform: uppercase;
    color: #64748B;
    letter-spacing: 0.05em;
    margin-bottom: 0.15rem;
}

.kpi-value {
    font-size: 1.5rem;
    font-weight: 700;
    color: #0F172A;
    line-height: 1.2;
}

.kpi-subtitle {
    font-size: 0.7rem;
    color: #94A3B8;
    margin-top: 0.15rem;
}

/* ===== SECTION TITLE ===== */
.soc-section-title {
    font-size: 0.85rem;
    font-weight: 700;
    color: #1E3A8A;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-bottom: 0.75rem;
    padding-bottom: 0.3rem;
    border-bottom: 2px solid #EAB308;
}

/* ===== DETECTOR CARDS ===== */
.detector-card {
    background-color: #FFFFFF;
    border: 1px solid #E2E8F0;
    border-radius: 4px;
    padding: 0.75rem;
    height: 100%;
}

.detector-card-header {
    font-size: 0.75rem;
    font-weight: 700;
    color: #1E3A8A;
    text-transform: uppercase;
    letter-spacing: 0.03em;
    margin-bottom: 0.4rem;
    padding-bottom: 0.3rem;
    border-bottom: 2px solid #EAB308;
}

.detector-card-metric {
    font-size: 0.78rem;
    color: #475569;
    margin: 0.2rem 0;
}

.detector-card-metric strong {
    color: #0F172A;
}

.detector-card-status {
    font-size: 0.68rem;
    font-weight: 600;
    color: #1D4ED8;
    text-transform: uppercase;
    margin-top: 0.3rem;
}

/* ===== INCIDENT CARDS ===== */
.incident-card {
    background-color: #FFFFFF;
    border: 1px solid #CBD5E1;
    border-left: 4px solid #EAB308;
    border-radius: 4px;
    padding: 0.75rem 1rem;
    margin-bottom: 0.6rem;
}

.incident-card-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.4rem;
}

.incident-card-id {
    font-family: monospace;
    font-weight: 700;
    color: #1E3A8A;
    font-size: 0.85rem;
}

.incident-card-meta {
    font-size: 0.75rem;
    color: #64748B;
}

/* ===== ATTACK CHAIN ===== */
.attack-chain-box {
    background-color: #F8FAFC;
    border: 1px solid #CBD5E1;
    border-radius: 4px;
    padding: 0.6rem 0.85rem;
    font-family: monospace;
    font-size: 0.8rem;
    color: #1E293B;
    margin-bottom: 0.5rem;
}

.attack-chain-arrow {
    color: #CA8A04;
    font-weight: bold;
    padding: 0 0.3rem;
}

/* ===== SEVERITY BADGES ===== */
.badge-critical {
    background-color: #FEF08A;
    color: #713F12;
    border: 1px solid #CA8A04;
    padding: 2px 7px;
    border-radius: 3px;
    font-weight: 700;
    font-size: 0.7rem;
}

.badge-high {
    background-color: #FEF9C3;
    color: #854D0E;
    border: 1px solid #EAB308;
    padding: 2px 7px;
    border-radius: 3px;
    font-weight: 700;
    font-size: 0.7rem;
}

.badge-medium {
    background-color: #DBEAFE;
    color: #1E40AF;
    border: 1px solid #93C5FD;
    padding: 2px 7px;
    border-radius: 3px;
    font-weight: 600;
    font-size: 0.7rem;
}

.badge-low {
    background-color: #F1F5F9;
    color: #475569;
    border: 1px solid #CBD5E1;
    padding: 2px 7px;
    border-radius: 3px;
    font-weight: 600;
    font-size: 0.7rem;
}

/* ===== LIVE MONITORING ===== */
.live-metric-card {
    background-color: #FFFFFF;
    border: 1px solid #E2E8F0;
    border-radius: 4px;
    padding: 0.6rem 0.8rem;
    text-align: center;
}

.live-metric-label {
    font-size: 0.65rem;
    font-weight: 600;
    text-transform: uppercase;
    color: #64748B;
    letter-spacing: 0.04em;
}

.live-metric-value {
    font-size: 1.25rem;
    font-weight: 700;
    color: #1E3A8A;
}

.live-status-monitoring {
    background-color: #DBEAFE;
    color: #1E40AF;
    border: 1px solid #93C5FD;
    padding: 0.2rem 0.6rem;
    border-radius: 3px;
    font-size: 0.7rem;
    font-weight: 700;
    text-transform: uppercase;
}

.live-status-paused {
    background-color: #FEF9C3;
    color: #854D0E;
    border: 1px solid #EAB308;
    padding: 0.2rem 0.6rem;
    border-radius: 3px;
    font-size: 0.7rem;
    font-weight: 700;
    text-transform: uppercase;
}

.live-status-offline {
    background-color: #F1F5F9;
    color: #475569;
    border: 1px solid #94A3B8;
    padding: 0.2rem 0.6rem;
    border-radius: 3px;
    font-size: 0.7rem;
    font-weight: 700;
    text-transform: uppercase;
}

/* ===== EVIDENCE TABLE ===== */
.evidence-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.85rem;
    margin-top: 0.5rem;
}

.evidence-table th, .evidence-table td {
    padding: 0.4rem 0.6rem;
    text-align: left;
    border-bottom: 1px solid #E2E8F0;
}

.evidence-table th {
    background-color: #F8FAFC;
    color: #475569;
    font-weight: 600;
    width: 35%;
}

.evidence-table td {
    color: #0F172A;
    font-family: monospace;
}

/* ===== INTEL TABLE ===== */
.intel-card {
    background-color: #FFFFFF;
    border: 1px solid #E2E8F0;
    border-radius: 4px;
    padding: 1rem;
    margin-bottom: 0.75rem;
}

.intel-label {
    font-size: 0.7rem;
    font-weight: 600;
    text-transform: uppercase;
    color: #64748B;
    letter-spacing: 0.04em;
}

.intel-value {
    font-size: 0.85rem;
    color: #0F172A;
    font-weight: 600;
}

/* ===== ABOUT PAGE ===== */
.about-arch-item {
    background-color: #FFFFFF;
    border: 1px solid #E2E8F0;
    border-left: 3px solid #2563EB;
    border-radius: 4px;
    padding: 0.5rem 0.8rem;
    margin-bottom: 0.4rem;
    font-size: 0.82rem;
    color: #334155;
}

/* ===== GENERAL OVERRIDES ===== */
/* Compact dataframe styling */
[data-testid="stDataFrame"] {
    font-size: 0.82rem;
}

/* Compact expander */
[data-testid="stExpander"] {
    border: 1px solid #E2E8F0;
    border-radius: 4px;
}
</style>
"""


def inject_soc_styles():
    """Inject SOC CSS into the current Streamlit app page."""
    st.markdown(SOC_CSS, unsafe_allow_html=True)
