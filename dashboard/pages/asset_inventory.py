"""dashboard/pages/asset_inventory.py
OT Asset Inventory — Lab demonstration asset monitoring.

Uses config/assets.yaml as the source. Clearly labeled as LAB ASSET INVENTORY.
"""

import pandas as pd
import streamlit as st

from dashboard.db import (
    check_db_status,
    fetch_asset_summary,
    get_active_db_path,
)

# ===== PAGE ENTRY POINT =====

db_path = get_active_db_path()
db_path_str = str(db_path)
is_online, _, _ = check_db_status(db_path)

st.markdown('<div class="soc-section-title">OT Asset Inventory</div>', unsafe_allow_html=True)

if not is_online:
    st.warning("Alert database is unavailable. Asset alert counts cannot be calculated.")

asset_data = fetch_asset_summary(db_path_str)

if not asset_data:
    st.info("No asset inventory loaded or no assets configured in config/assets.yaml.")
    st.stop()

# Summary metrics
critical_count = sum(1 for a in asset_data if a.get("criticality") == "critical")
standard_count = sum(1 for a in asset_data if a.get("criticality") == "standard")
alerted_count = sum(1 for a in asset_data if a.get("alert_count", 0) > 0)

col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric("Total Assets", len(asset_data))
with col2:
    st.metric("Critical Assets", critical_count)
with col3:
    st.metric("Standard Assets", standard_count)
with col4:
    st.metric("Assets with Alerts", alerted_count)

st.markdown("<br>", unsafe_allow_html=True)

# Asset table
table_rows = []
for a in asset_data:
    table_rows.append({
        "Asset Name": a.get("name", "Unknown"),
        "IP Address": a.get("ip", ""),
        "OT Role / Zone": a.get("zone", ""),
        "Criticality": a.get("criticality", "").upper(),
        "Active Alerts": a.get("alert_count", 0),
        "Last Activity (UTC)": a.get("last_seen") or "No alerts",
    })

df = pd.DataFrame(table_rows)
st.dataframe(df, use_container_width=True, hide_index=True)

# Per-asset detail
st.markdown("<br>", unsafe_allow_html=True)
st.markdown("**Asset Details**")

for a in asset_data:
    if a.get("alert_count", 0) > 0:
        with st.expander(f"{a.get('name', 'Unknown')} ({a.get('ip', '')})", expanded=False):
            st.markdown(f"**IP:** `{a.get('ip', '')}`")
            st.markdown(f"**Criticality:** {a.get('criticality', '').upper()}")
            st.markdown(f"**Zone:** {a.get('zone', '')}")
            st.markdown(f"**Active Alerts:** {a.get('alert_count', 0)}")
            st.markdown(f"**Last Activity:** {a.get('last_seen') or 'No alerts'}")
