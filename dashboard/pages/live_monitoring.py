"""dashboard/pages/live_monitoring.py
Live Monitoring — Real-time network traffic monitoring from Zeek logs.

Reads existing Zeek log data only. Does NOT generate traffic or start Zeek.
"""

import pandas as pd
import altair as alt
import streamlit as st

from dashboard.zeek_monitor import (
    ZeekLogStatus,
    compute_traffic_metrics,
    find_zeek_log_dir,
)


def _format_bytes(b: int) -> str:
    """Format bytes to human-readable string."""
    if b < 1024:
        return f"{b} B"
    elif b < 1024 * 1024:
        return f"{b / 1024:.1f} KB"
    elif b < 1024 * 1024 * 1024:
        return f"{b / (1024*1024):.1f} MB"
    return f"{b / (1024*1024*1024):.1f} GB"


# ===== PAGE ENTRY POINT =====

st.markdown('<div class="soc-section-title">Live Monitoring</div>', unsafe_allow_html=True)

# Discover Zeek logs
status = find_zeek_log_dir()

# Status header
status_col1, status_col2, status_col3 = st.columns([2, 1, 1])
with status_col1:
    if status.available:
        mode_label = "RECORDED DATA" if status.mode == "recorded" else "LIVE"
        st.markdown(
            f"""<div style="font-size: 0.85rem; color: #475569;">
                <strong>Source:</strong> {status.log_dir}
                &nbsp;&nbsp;
                <span class="live-status-{'monitoring' if status.mode == 'live' else 'paused'}">{mode_label}</span>
            </div>""",
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            """<div style="font-size: 0.85rem; color: #475569;">
                <strong>Live Traffic Source:</strong> Not configured
                &nbsp;&nbsp;
                <span class="live-status-offline">OFFLINE</span>
            </div>""",
            unsafe_allow_html=True,
        )

with status_col2:
    logs_available = []
    if status.conn_log:
        logs_available.append("conn.log")
    if status.dns_log:
        logs_available.append("dns.log")
    if status.ssl_log:
        logs_available.append("ssl.log")
    st.markdown(f"**Logs:** {', '.join(logs_available) if logs_available else 'None'}")

with status_col3:
    st.markdown(f"**Mode:** {status.mode.upper()}")

# If not available, show fallback message
if not status.available:
    st.markdown("<br>", unsafe_allow_html=True)
    st.info(
        "Live Zeek monitoring is not currently connected. "
        "To enable live monitoring, configure a Zeek instance to write logs to a monitored directory. "
        "Recorded PCAP results are available through Demo Lab."
    )
    st.stop()

# Monitoring toggle
monitoring_active = st.toggle("Enable Monitoring", value=True, key="live_toggle")

if not monitoring_active:
    st.markdown(
        '<span class="live-status-paused">PAUSED</span>',
        unsafe_allow_html=True,
    )
    st.stop()

# Compute metrics
metrics = compute_traffic_metrics(status.log_dir)

# Traffic Metrics
st.markdown("<br>", unsafe_allow_html=True)
m_cols = st.columns(6)

metric_items = [
    ("Connections", f"{metrics.total_connections:,}"),
    ("Packets", f"{metrics.total_packets:,}"),
    ("Bytes", _format_bytes(metrics.total_bytes)),
    ("Active Hosts", f"{metrics.active_hosts}"),
    ("DNS Queries", f"{metrics.dns_queries:,}"),
    ("TLS Sessions", f"{metrics.tls_sessions:,}"),
]

for i, (label, value) in enumerate(metric_items):
    with m_cols[i]:
        st.markdown(
            f"""<div class="live-metric-card">
                <div class="live-metric-label">{label}</div>
                <div class="live-metric-value">{value}</div>
            </div>""",
            unsafe_allow_html=True,
        )

st.markdown("<br>", unsafe_allow_html=True)

# Traffic Rate Chart
st.markdown("**Traffic Rate**")
if metrics.timeseries:
    df_ts = pd.DataFrame(metrics.timeseries)
    df_ts["timestamp"] = pd.to_datetime(df_ts["timestamp"])

    chart = (
        alt.Chart(df_ts)
        .mark_area(color="#2563EB", opacity=0.3, line={"color": "#1E3A8A", "strokeWidth": 2})
        .encode(
            x=alt.X("timestamp:T", title="Time", axis=alt.Axis(format="%H:%M:%S")),
            y=alt.Y("bytes_per_interval:Q", title="Bytes / Interval"),
            tooltip=[
                alt.Tooltip("timestamp:T", title="Time", format="%H:%M:%S"),
                alt.Tooltip("bytes_per_interval:Q", title="Bytes"),
            ],
        )
        .properties(height=200)
        .configure_view(strokeWidth=0)
    )
    st.altair_chart(chart, use_container_width=True)
else:
    st.info("No traffic timeseries data available.")

st.markdown("<br>", unsafe_allow_html=True)

# Top Talkers and Protocol Activity
col_left, col_right = st.columns(2)

with col_left:
    st.markdown("**Top Sources**")
    if metrics.top_sources:
        df_src = pd.DataFrame(metrics.top_sources)
        df_src.columns = ["Source IP", "Connections", "Bytes"]
        df_src["Bytes"] = df_src["Bytes"].apply(_format_bytes)
        st.dataframe(df_src, use_container_width=True, hide_index=True, height=250)
    else:
        st.info("No source data.")

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("**Top Destinations**")
    if metrics.top_destinations:
        df_dst = pd.DataFrame(metrics.top_destinations)
        df_dst.columns = ["Destination IP", "Connections", "Bytes"]
        df_dst["Bytes"] = df_dst["Bytes"].apply(_format_bytes)
        st.dataframe(df_dst, use_container_width=True, hide_index=True, height=250)
    else:
        st.info("No destination data.")

with col_right:
    st.markdown("**Protocol Activity**")
    if metrics.protocols:
        proto_rows = [{"Protocol": k, "Count": v} for k, v in metrics.protocols.items()]
        df_proto = pd.DataFrame(proto_rows)
        chart_proto = (
            alt.Chart(df_proto)
            .mark_bar(color="#1E3A8A")
            .encode(
                x=alt.X("Count:Q", title="Connections"),
                y=alt.Y("Protocol:N", sort="-x", title="Protocol"),
                tooltip=["Protocol:N", "Count:Q"],
            )
            .properties(height=200)
            .configure_view(strokeWidth=0)
        )
        st.altair_chart(chart_proto, use_container_width=True)
    else:
        st.info("No protocol data.")

st.markdown("<br>", unsafe_allow_html=True)

# Recent Network Events
st.markdown("**Recent Network Events**")
if metrics.recent_connections:
    df_events = pd.DataFrame(metrics.recent_connections)
    df_events.columns = ["Time", "Source", "Destination", "Protocol", "Port", "Bytes"]
    st.dataframe(df_events, use_container_width=True, hide_index=True, height=300)
else:
    st.info("No recent network events.")
