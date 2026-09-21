"""dashboard/charts.py
Centralized, reusable charting module for SIH PS-26145.
Ensures Overview and Analytics pages use the exact same data transformation
and visual rendering logic.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Optional, Sequence

import altair as alt
import pandas as pd

# Canonical specification for the 7 OT threat classes and their semantic colors:
# DDoS: blue, Reconnaissance: purple, DGA / DNS: green, DNS Tunnelling: red,
# C2 Beaconing: cyan/teal, Encrypted Malware / TLS: orange, Exfiltration: brown
THREAT_SPECS: list[dict[str, str]] = [
    {"key": "ddos", "label": "DDoS", "color": "#2563EB"},
    {"key": "reconnaissance", "label": "Reconnaissance", "color": "#7C3AED"},
    {"key": "dga_dns", "label": "DGA / DNS", "color": "#059669"},
    {"key": "dns_tunnel", "label": "DNS Tunnelling", "color": "#DC2626"},
    {"key": "beaconing", "label": "C2 Beaconing", "color": "#0D9488"},
    {"key": "tls_anomaly", "label": "Encrypted Malware / TLS", "color": "#D97706"},
    {"key": "exfiltration", "label": "Exfiltration", "color": "#92400E"},
]

# Aliases / normalizations to canonical threat keys
THREAT_NORM_MAP: dict[str, str] = {
    "ddos": "ddos",
    "reconnaissance": "reconnaissance",
    "scanning": "reconnaissance",
    "dga": "dga_dns",
    "dga_dns": "dga_dns",
    "dns_tunnel": "dns_tunnel",
    "beaconing": "beaconing",
    "tls_anomaly": "tls_anomaly",
    "exfiltration": "exfiltration",
}

LABEL_TO_KEY_MAP: dict[str, str] = {spec["label"]: spec["key"] for spec in THREAT_SPECS}
KEY_TO_LABEL_MAP: dict[str, str] = {spec["key"]: spec["label"] for spec in THREAT_SPECS}
COLOR_MAP: dict[str, str] = {spec["label"]: spec["color"] for spec in THREAT_SPECS}


def prepare_multi_threat_timeseries(
    alerts: Sequence[dict[str, Any]],
    bin_minutes: int = 5,
    selected_threat_labels: Optional[Sequence[str]] = None,
) -> pd.DataFrame:
    """Transform raw alerts into a continuous multi-threat time-series dataframe.

    For every time bucket and for every active threat class, records the exact count
    (0 if no alert occurred). This ensures lines remain continuous without artificial
    interpolation or missing series.
    """
    if not alerts:
        return pd.DataFrame(columns=["time_label", "time_iso", "threat_class", "alert_count"])

    # Determine active threat classes based on optional filter
    if selected_threat_labels:
        active_specs = [s for s in THREAT_SPECS if s["label"] in selected_threat_labels]
        if not active_specs:
            active_specs = THREAT_SPECS
    else:
        active_specs = THREAT_SPECS

    parsed: list[tuple[datetime, str]] = []
    for a in alerts:
        try:
            ts_str = str(a.get("timestamp", "")).replace("Z", "+00:00")
            dt = datetime.fromisoformat(ts_str)
            raw_tc = a.get("threat_class", "")
            norm_key = THREAT_NORM_MAP.get(raw_tc, raw_tc)
            parsed.append((dt, norm_key))
        except Exception:
            continue

    if not parsed:
        return pd.DataFrame(columns=["time_label", "time_iso", "threat_class", "alert_count"])

    min_dt = min(p[0] for p in parsed)
    max_dt = max(p[0] for p in parsed)

    start_b = min_dt.replace(
        minute=(min_dt.minute // bin_minutes) * bin_minutes, second=0, microsecond=0
    )
    end_b = max_dt.replace(
        minute=(max_dt.minute // bin_minutes) * bin_minutes, second=0, microsecond=0
    )

    # Generate continuous sequence of time buckets
    buckets: list[datetime] = []
    curr = start_b
    while curr <= end_b:
        buckets.append(curr)
        curr += timedelta(minutes=bin_minutes)

    # Count alerts per (bucket, threat_key)
    counts: dict[tuple[datetime, str], int] = {}
    for dt, tc_key in parsed:
        b = dt.replace(
            minute=(dt.minute // bin_minutes) * bin_minutes, second=0, microsecond=0
        )
        counts[(b, tc_key)] = counts.get((b, tc_key), 0) + 1

    # Build dense rows: every bucket has an entry for each active threat class
    rows = []
    for b in buckets:
        t_label = b.strftime("%H:%M UTC")
        t_iso = b.isoformat()
        for spec in active_specs:
            c = counts.get((b, spec["key"]), 0)
            rows.append({
                "time_label": t_label,
                "time_iso": t_iso,
                "threat_class": spec["label"],
                "alert_count": c,
            })

    return pd.DataFrame(rows)


def build_threat_activity_chart(
    df: pd.DataFrame,
    height: int = 260,
    show_legend: bool = True,
) -> alt.Chart:
    """Build standardized multi-line threat activity chart with markers for all 7 threat classes."""
    if df.empty:
        return alt.Chart(pd.DataFrame()).mark_text().encode(text=alt.value("No threat activity"))

    domain = [spec["label"] for spec in THREAT_SPECS if spec["label"] in df["threat_class"].values]
    colors = [spec["color"] for spec in THREAT_SPECS if spec["label"] in df["threat_class"].values]

    max_count = int(df["alert_count"].max()) if not df.empty else 1
    y_domain_max = max(max_count + 0.5, 2.5)

    legend_config = (
        alt.Legend(
            orient="top",
            columns=4,
            labelLimit=220,
            title=None,
            symbolStrokeWidth=2,
            symbolSize=80,
            labelFontSize=11,
            labelFontWeight="normal",
        )
        if show_legend
        else None
    )

    # Lines for all threat series
    lines = (
        alt.Chart(df)
        .mark_line(strokeWidth=2, opacity=0.88)
        .encode(
            x=alt.X(
                "time_label:N",
                title="Timeline (UTC)",
                axis=alt.Axis(labelAngle=0, titleFontSize=11, labelFontSize=10),
            ),
            y=alt.Y(
                "alert_count:Q",
                title="Alert Count",
                axis=alt.Axis(tickMinStep=1, format="d", titleFontSize=11, labelFontSize=10),
                scale=alt.Scale(domain=[0, y_domain_max]),
            ),
            color=alt.Color(
                "threat_class:N",
                scale=alt.Scale(domain=domain, range=colors),
                legend=legend_config,
            ),
        )
    )

    # Small circular markers on points
    points = (
        alt.Chart(df)
        .mark_circle(size=45)
        .encode(
            x="time_label:N",
            y="alert_count:Q",
            color=alt.Color("threat_class:N", scale=alt.Scale(domain=domain, range=colors)),
            tooltip=[
                alt.Tooltip("time_label:N", title="Time (UTC)"),
                alt.Tooltip("threat_class:N", title="Threat Class"),
                alt.Tooltip("alert_count:Q", title="Alert Count"),
            ],
        )
    )

    chart = (lines + points).properties(height=height).configure_view(strokeWidth=0)
    return chart


def build_threat_distribution_chart(
    threat_data: Sequence[dict[str, Any]],
    height: int = 240,
) -> alt.Chart:
    """Build standardized horizontal bar chart for threat class distribution with exact integer counts."""
    if not threat_data:
        return alt.Chart(pd.DataFrame()).mark_text().encode(text=alt.value("No threat class data"))

    # Convert to DataFrame with clean display labels
    df = pd.DataFrame(threat_data)
    df["label"] = df["threat_class"].map(
        lambda tc: KEY_TO_LABEL_MAP.get(THREAT_NORM_MAP.get(tc, tc), tc)
    )
    df = df.groupby("label", as_index=False)["count"].sum()
    df = df.sort_values("count", ascending=False)

    max_count = int(df["count"].max()) if not df.empty else 1
    # Scale max must be at least 3 so 1-count bars don't fill the full width to 1.0
    x_domain_max = max(max_count + 1, 3.5)

    bars = (
        alt.Chart(df)
        .mark_bar(color="#1E3A8A", cornerRadiusEnd=3, height=20)
        .encode(
            x=alt.X(
                "count:Q",
                title="Total Detections",
                axis=alt.Axis(tickMinStep=1, format="d", titleFontSize=11, labelFontSize=10),
                scale=alt.Scale(domain=[0, x_domain_max]),
            ),
            y=alt.Y("label:N", sort="-x", title=""),
            tooltip=[
                alt.Tooltip("label:N", title="Threat Class"),
                alt.Tooltip("count:Q", title="Alert Count"),
            ],
        )
    )

    labels = (
        alt.Chart(df)
        .mark_text(
            align="left",
            baseline="middle",
            dx=6,
            color="#0F172A",
            fontWeight="bold",
            fontSize=12,
        )
        .encode(
            x="count:Q",
            y=alt.Y("label:N", sort="-x"),
            text=alt.Text("count:Q", format="d"),
        )
    )

    chart = (bars + labels).properties(height=height).configure_view(strokeWidth=0)
    return chart
