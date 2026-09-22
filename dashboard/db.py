"""dashboard/db.py
Data access layer for Streamlit dashboard.
Wraps storage/sqlite_store.py with caching and error handling.
All queries return clean Python dicts or lists.
Zero detection logic in this module.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import streamlit as st

from storage.sqlite_store import (
    DEFAULT_DB_PATH,
    count_alerts,
    delete_pcap_analysis_records,
    get_alert_by_id,
    get_alerts,
    get_asset_summary,
    get_correlated_groups,
    get_correlated_vs_uncorrelated,
    get_detector_counts,
    get_kpi_summary,
    get_pcap_analyses,
    get_pcap_analysis_by_id,
    get_severity_distribution,
    get_threat_distribution,
    get_timeseries,
    init_db,
)


def get_active_db_path() -> Path:
    """Return the active SQLite database path."""
    return Path("data/alerts.db")


def check_db_status(db_path: Optional[Path] = None) -> Tuple[bool, str, int]:
    """Check if the SQLite database is available and accessible.

    Returns:
        (is_available, status_message, total_alert_count)
    """
    path = db_path or get_active_db_path()
    if not path.exists():
        return False, f"Database file not found: {path}", 0

    try:
        kpis = get_kpi_summary(path, canonical_only=True)
        total = kpis.get("total_alerts", 0)
        return True, "Online", total
    except Exception as e:
        return False, f"Database error: {str(e)}", 0


@st.cache_data(ttl=3)
def fetch_kpis(
    db_path_str: str,
    canonical_only: bool = True,
    pcap_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Fetch KPI summary counters, defaulting to canonical baseline for Overview."""
    try:
        return get_kpi_summary(Path(db_path_str), pcap_id=pcap_id, canonical_only=canonical_only)
    except Exception:
        return {
            "total_alerts": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "correlated_incidents": 0,
            "threat_classes": 0,
            "compromised_assets": 0,
            "first_seen": None,
            "last_seen": None,
        }


@st.cache_data(ttl=3)
def fetch_alerts(
    db_path_str: str,
    limit: int = 100,
    offset: int = 0,
    threat_class: Optional[str] = None,
    severity: Optional[str] = None,
    source: Optional[str] = None,
    destination: Optional[str] = None,
    correlation_id: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    search_term: Optional[str] = None,
    canonical_only: bool = True,
    pcap_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Fetch filtered list of alerts."""
    try:
        return get_alerts(
            db_path=Path(db_path_str),
            limit=limit,
            offset=offset,
            threat_class=threat_class,
            severity=severity,
            source=source,
            destination=destination,
            correlation_id=correlation_id,
            start_time=start_time,
            end_time=end_time,
            search_term=search_term,
            canonical_only=canonical_only,
            pcap_id=pcap_id,
        )
    except Exception:
        return []


@st.cache_data(ttl=3)
def fetch_alert_detail(db_path_str: str, alert_id: str) -> Optional[Dict[str, Any]]:
    """Fetch complete detail for a single alert."""
    try:
        return get_alert_by_id(alert_id, Path(db_path_str))
    except Exception:
        return None


@st.cache_data(ttl=3)
def fetch_threat_distribution(
    db_path_str: str,
    canonical_only: bool = True,
    pcap_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Fetch count of alerts per threat class."""
    try:
        return get_threat_distribution(Path(db_path_str), pcap_id=pcap_id, canonical_only=canonical_only)
    except Exception:
        return []


@st.cache_data(ttl=3)
def fetch_severity_distribution(
    db_path_str: str,
    canonical_only: bool = True,
    pcap_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Fetch count of alerts per severity level."""
    try:
        return get_severity_distribution(Path(db_path_str), pcap_id=pcap_id, canonical_only=canonical_only)
    except Exception:
        return []


@st.cache_data(ttl=3)
def fetch_timeseries(
    db_path_str: str,
    canonical_only: bool = True,
    pcap_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Fetch threat activity timeline grouped by threat class."""
    try:
        return get_timeseries(Path(db_path_str), pcap_id=pcap_id, canonical_only=canonical_only)
    except Exception:
        return []


@st.cache_data(ttl=3)
def fetch_binned_timeseries(
    db_path_str: str,
    bin_minutes: int = 5,
    threat_filter: Optional[Tuple[str, ...]] = None,
    canonical_only: bool = True,
    pcap_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Fetch continuous time-bucketed alert activity for time-series charts.
    
    Returns continuous time intervals (with 0-count gaps filled) so charts
    render a proper time-series line/area without isolated single points.
    """
    from datetime import datetime, timedelta, timezone

    threat_labels_map = {
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

    try:
        alerts = get_alerts(Path(db_path_str), limit=1000, canonical_only=canonical_only, pcap_id=pcap_id)
    except Exception:
        return []

    if threat_filter:
        filter_set = set(threat_filter)
        alerts = [a for a in alerts if a.get("threat_class") in filter_set]

    if not alerts:
        return []

    parsed = []
    for a in alerts:
        try:
            ts_str = a.get("timestamp", "").replace("Z", "+00:00")
            dt = datetime.fromisoformat(ts_str)
            parsed.append((dt, a.get("threat_class", ""), a.get("severity", "")))
        except Exception:
            continue

    if not parsed:
        return []

    min_dt = min(p[0] for p in parsed)
    max_dt = max(p[0] for p in parsed)

    start_bucket = min_dt.replace(
        minute=(min_dt.minute // bin_minutes) * bin_minutes, second=0, microsecond=0
    )
    end_bucket = max_dt.replace(
        minute=(max_dt.minute // bin_minutes) * bin_minutes, second=0, microsecond=0
    )

    bucket_data = {}
    curr = start_bucket
    while curr <= end_bucket + timedelta(minutes=bin_minutes):
        bucket_data[curr] = {"count": 0, "threats": set(), "severities": set(), "threat_counts": {}}
        curr += timedelta(minutes=bin_minutes)

    for dt, tc, sev in parsed:
        b = dt.replace(minute=(dt.minute // bin_minutes) * bin_minutes, second=0, microsecond=0)
        if b in bucket_data:
            bucket_data[b]["count"] += 1
            lbl = threat_labels_map.get(tc, tc)
            bucket_data[b]["threats"].add(lbl)
            bucket_data[b]["severities"].add(sev.upper())
            tc_counts = bucket_data[b]["threat_counts"]
            tc_counts[lbl] = tc_counts.get(lbl, 0) + 1

    results = []
    for b_dt in sorted(bucket_data.keys()):
        d = bucket_data[b_dt]
        threat_str = ", ".join(sorted(d["threats"])) if d["threats"] else "No alerts"
        sev_str = ", ".join(sorted(d["severities"])) if d["severities"] else "NONE"
        results.append({
            "timestamp": b_dt.strftime("%Y-%m-%d %H:%M UTC"),
            "time_iso": b_dt.isoformat(),
            "time_label": b_dt.strftime("%H:%M UTC"),
            "count": d["count"],
            "threats": threat_str,
            "severities": sev_str,
            "is_peak": d["count"] >= 2,
            "threat_counts": d["threat_counts"],
        })
    return results


@st.cache_data(ttl=3)
def fetch_correlated_groups(
    db_path_str: str,
    canonical_only: bool = True,
    pcap_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Fetch multi-stage correlated attack incidents."""
    try:
        return get_correlated_groups(Path(db_path_str), pcap_id=pcap_id, canonical_only=canonical_only)
    except Exception:
        return []


@st.cache_data(ttl=3)
def fetch_asset_summary(
    db_path_str: str,
    canonical_only: bool = True,
    pcap_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Fetch asset inventory with alert counts."""
    try:
        return get_asset_summary(Path(db_path_str), pcap_id=pcap_id, canonical_only=canonical_only)
    except Exception:
        return []


@st.cache_data(ttl=3)
def fetch_detector_counts(
    db_path_str: str,
    canonical_only: bool = True,
    pcap_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Fetch alert and incident counts per detector/threat class."""
    try:
        return get_detector_counts(Path(db_path_str), pcap_id=pcap_id, canonical_only=canonical_only)
    except Exception:
        return []


@st.cache_data(ttl=3)
def fetch_correlated_vs_uncorrelated(
    db_path_str: str,
    canonical_only: bool = True,
    pcap_id: Optional[str] = None,
) -> Dict[str, int]:
    """Fetch correlated vs uncorrelated alert counts."""
    try:
        return get_correlated_vs_uncorrelated(Path(db_path_str), pcap_id=pcap_id, canonical_only=canonical_only)
    except Exception:
        return {"correlated": 0, "uncorrelated": 0}


def fetch_recent_alerts(
    db_path_str: str,
    limit: int = 10,
    canonical_only: bool = True,
    pcap_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Fetch most recent alerts (uncached for freshness)."""
    try:
        return get_alerts(Path(db_path_str), limit=limit, offset=0, canonical_only=canonical_only, pcap_id=pcap_id)
    except Exception:
        return []


# =====================================================================
# PCAP ANALYSIS SPECIFIC DATA FETCHERS
# =====================================================================

@st.cache_data(ttl=2)
def fetch_pcap_analyses(db_path_str: str) -> List[Dict[str, Any]]:
    """Fetch all PCAP analysis records."""
    try:
        return get_pcap_analyses(Path(db_path_str))
    except Exception:
        return []


@st.cache_data(ttl=2)
def fetch_pcap_analysis(db_path_str: str, pcap_id: str) -> Optional[Dict[str, Any]]:
    """Fetch details for a single PCAP analysis record."""
    try:
        return get_pcap_analysis_by_id(pcap_id, Path(db_path_str))
    except Exception:
        return None


@st.cache_data(ttl=2)
def fetch_pcap_alerts(
    db_path_str: str,
    pcap_id: str,
    limit: int = 50,
    offset: int = 0,
    severity: Optional[str] = None,
    threat_class: Optional[str] = None,
    search_term: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Fetch alerts strictly scoped to a specific PCAP ID."""
    try:
        return get_alerts(
            db_path=Path(db_path_str),
            limit=limit,
            offset=offset,
            pcap_id=pcap_id,
            canonical_only=False,
            severity=severity,
            threat_class=threat_class,
            search_term=search_term,
        )
    except Exception:
        return []


@st.cache_data(ttl=2)
def fetch_pcap_alerts_count(
    db_path_str: str,
    pcap_id: str,
    severity: Optional[str] = None,
    threat_class: Optional[str] = None,
    search_term: Optional[str] = None,
) -> int:
    """Fetch total count of alerts matching filters strictly scoped to a specific PCAP ID."""
    try:
        return count_alerts(
            db_path=Path(db_path_str),
            pcap_id=pcap_id,
            canonical_only=False,
            severity=severity,
            threat_class=threat_class,
            search_term=search_term,
        )
    except Exception:
        return 0

