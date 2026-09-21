"""
SQLite Alert Store for PS-26145.

Provides local-first persistent storage for validated, fused alerts.
All database access is parameterized to prevent SQL injection.
"""

from __future__ import annotations

from contextlib import contextmanager
import json
import logging
from pathlib import Path
import sqlite3
from typing import Any, Generator, Optional

from alerts.draft import DraftAlert

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH: Path = Path(__file__).resolve().parent.parent / "data" / "alerts.db"

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    flow_id TEXT,
    threat_class TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence REAL NOT NULL,
    source TEXT NOT NULL,
    destination TEXT NOT NULL,
    detector TEXT NOT NULL,
    model_version TEXT,
    schema_version TEXT,
    subtype TEXT,
    latency_class TEXT,
    asset_criticality TEXT,
    correlation_id TEXT,
    correlated_alert_ids TEXT,
    supporting_evidence TEXT,
    raw_alert TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_threat_class ON alerts(threat_class);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_source ON alerts(source);
CREATE INDEX IF NOT EXISTS idx_alerts_destination ON alerts(destination);
CREATE INDEX IF NOT EXISTS idx_alerts_correlation_id ON alerts(correlation_id);
"""


@contextmanager
def get_connection(db_path: Path | str = DEFAULT_DB_PATH) -> Generator[sqlite3.Connection, None, None]:
    """Context manager for SQLite connections with foreign keys and WAL mode."""
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=10.0)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        yield conn
    finally:
        conn.close()


def init_db(db_path: Path | str = DEFAULT_DB_PATH) -> Path:
    """Initialize database tables and indexes."""
    path = Path(db_path)
    with get_connection(path) as conn:
        conn.executescript(_SCHEMA_SQL)
        conn.commit()
    logger.debug("Initialized SQLite alert store at %s", path)
    return path


def _to_alert_dict(alert: dict[str, Any] | DraftAlert) -> dict[str, Any]:
    if hasattr(alert, "to_dict"):
        return alert.to_dict()
    return dict(alert)


def insert_alert(alert: dict[str, Any] | DraftAlert, db_path: Path | str = DEFAULT_DB_PATH) -> str:
    """Insert a single alert into SQLite. Returns alert_id."""
    init_db(db_path)
    d = _to_alert_dict(alert)
    alert_id = d.get("alert_id", "")

    evidence_str = json.dumps(d.get("supporting_evidence", {}))
    corr_ids_str = json.dumps(d.get("correlated_alert_ids", []))
    raw_str = json.dumps(d)

    sql = """
    INSERT INTO alerts (
        alert_id, timestamp, flow_id, threat_class, severity,
        confidence, source, destination, detector, model_version,
        schema_version, subtype, latency_class, asset_criticality,
        correlation_id, correlated_alert_ids, supporting_evidence, raw_alert
    ) VALUES (
        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
    )
    ON CONFLICT(alert_id) DO UPDATE SET
        severity=excluded.severity,
        asset_criticality=excluded.asset_criticality,
        correlation_id=excluded.correlation_id,
        correlated_alert_ids=excluded.correlated_alert_ids,
        supporting_evidence=excluded.supporting_evidence,
        raw_alert=excluded.raw_alert;
    """

    with get_connection(db_path) as conn:
        conn.execute(
            sql,
            (
                alert_id,
                d.get("timestamp", ""),
                d.get("flow_id", ""),
                d.get("threat_class", ""),
                d.get("severity", ""),
                float(d.get("confidence", 0.0)),
                d.get("source", ""),
                d.get("destination", ""),
                d.get("detector", ""),
                d.get("model_version", ""),
                d.get("schema_version", "1.0.0"),
                d.get("subtype"),
                d.get("latency_class"),
                d.get("asset_criticality"),
                d.get("correlation_id"),
                corr_ids_str,
                evidence_str,
                raw_str,
            ),
        )
        conn.commit()

    return alert_id


def insert_alerts(alerts: list[dict[str, Any] | DraftAlert], db_path: Path | str = DEFAULT_DB_PATH) -> int:
    """Batch insert multiple alerts within a single transaction."""
    if not alerts:
        return 0

    init_db(db_path)
    count = 0

    sql = """
    INSERT INTO alerts (
        alert_id, timestamp, flow_id, threat_class, severity,
        confidence, source, destination, detector, model_version,
        schema_version, subtype, latency_class, asset_criticality,
        correlation_id, correlated_alert_ids, supporting_evidence, raw_alert
    ) VALUES (
        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
    )
    ON CONFLICT(alert_id) DO UPDATE SET
        severity=excluded.severity,
        asset_criticality=excluded.asset_criticality,
        correlation_id=excluded.correlation_id,
        correlated_alert_ids=excluded.correlated_alert_ids,
        supporting_evidence=excluded.supporting_evidence,
        raw_alert=excluded.raw_alert;
    """

    with get_connection(db_path) as conn:
        params = []
        for a in alerts:
            d = _to_alert_dict(a)
            params.append((
                d.get("alert_id", ""),
                d.get("timestamp", ""),
                d.get("flow_id", ""),
                d.get("threat_class", ""),
                d.get("severity", ""),
                float(d.get("confidence", 0.0)),
                d.get("source", ""),
                d.get("destination", ""),
                d.get("detector", ""),
                d.get("model_version", ""),
                d.get("schema_version", "1.0.0"),
                d.get("subtype"),
                d.get("latency_class"),
                d.get("asset_criticality"),
                d.get("correlation_id"),
                json.dumps(d.get("correlated_alert_ids", [])),
                json.dumps(d.get("supporting_evidence", {})),
                json.dumps(d),
            ))
        conn.executemany(sql, params)
        conn.commit()
        count = len(params)

    return count


def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    """Convert SQLite row to clean alert dictionary."""
    d = dict(row)
    if "raw_alert" in d and d["raw_alert"]:
        try:
            raw = json.loads(d["raw_alert"])
            return raw
        except Exception:
            pass

    # Fallback to reconstructing from columns
    if "supporting_evidence" in d and isinstance(d["supporting_evidence"], str):
        try:
            d["supporting_evidence"] = json.loads(d["supporting_evidence"])
        except Exception:
            pass
    if "correlated_alert_ids" in d and isinstance(d["correlated_alert_ids"], str):
        try:
            d["correlated_alert_ids"] = json.loads(d["correlated_alert_ids"])
        except Exception:
            pass
    return d


def get_alert_by_id(alert_id: str, db_path: Path | str = DEFAULT_DB_PATH) -> Optional[dict[str, Any]]:
    """Retrieve single alert by ID."""
    path = Path(db_path)
    if not path.is_file():
        return None

    with get_connection(path) as conn:
        row = conn.execute("SELECT * FROM alerts WHERE alert_id = ?;", (alert_id,)).fetchone()
        if row:
            return _row_to_dict(row)
    return None


def get_alerts(
    db_path: Path | str = DEFAULT_DB_PATH,
    threat_class: Optional[str] = None,
    severity: Optional[str] = None,
    source: Optional[str] = None,
    destination: Optional[str] = None,
    asset_criticality: Optional[str] = None,
    detector: Optional[str] = None,
    correlation_id: Optional[str] = None,
    search: Optional[str] = None,
    search_term: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """Retrieve filtered alerts ordered by timestamp descending."""
    path = Path(db_path)
    if not path.is_file():
        return []

    conditions: list[str] = []
    params: list[Any] = []

    if threat_class:
        conditions.append("threat_class = ?")
        params.append(threat_class)
    if severity:
        conditions.append("severity = ?")
        params.append(severity.lower())
    if source:
        conditions.append("source = ?")
        params.append(source)
    if destination:
        conditions.append("destination = ?")
        params.append(destination)
    if asset_criticality:
        conditions.append("asset_criticality = ?")
        params.append(asset_criticality.lower())
    if detector:
        conditions.append("detector = ?")
        params.append(detector)
    if correlation_id:
        conditions.append("correlation_id = ?")
        params.append(correlation_id)
    if start_time:
        conditions.append("timestamp >= ?")
        params.append(start_time)
    if end_time:
        conditions.append("timestamp <= ?")
        params.append(end_time)
    s = search or search_term
    if s:
        search_like = f"%{s.strip()}%"
        conditions.append("(source LIKE ? OR destination LIKE ? OR alert_id LIKE ? OR correlation_id LIKE ? OR raw_alert LIKE ?)")
        params.extend([search_like, search_like, search_like, search_like, search_like])

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    sql = f"SELECT * FROM alerts {where_clause} ORDER BY timestamp DESC LIMIT ? OFFSET ?;"
    params.extend([limit, offset])

    with get_connection(path) as conn:
        rows = conn.execute(sql, params).fetchall()
        return [_row_to_dict(r) for r in rows]


def get_kpi_summary(db_path: Path | str = DEFAULT_DB_PATH) -> dict[str, int]:
    """Retrieve aggregate summary counts for KPI cards."""
    path = Path(db_path)
    defaults = {
        "total_alerts": 0,
        "critical": 0,
        "critical_alerts": 0,
        "high": 0,
        "high_alerts": 0,
        "medium": 0,
        "medium_alerts": 0,
        "low": 0,
        "low_alerts": 0,
        "correlated_incidents": 0,
        "unique_sources": 0,
        "compromised_assets": 0,
        "unique_threat_classes": 0,
        "threat_classes": 0,
    }
    if not path.is_file():
        return defaults

    with get_connection(path) as conn:
        total = conn.execute("SELECT COUNT(*) FROM alerts;").fetchone()[0]
        if total == 0:
            return defaults

        crit = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'critical';").fetchone()[0]
        high = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'high';").fetchone()[0]
        med = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'medium';").fetchone()[0]
        low = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'low';").fetchone()[0]
        corr = conn.execute("SELECT COUNT(DISTINCT correlation_id) FROM alerts WHERE correlation_id IS NOT NULL AND correlation_id != '';").fetchone()[0]
        srcs = conn.execute("SELECT COUNT(DISTINCT source) FROM alerts;").fetchone()[0]
        threats = conn.execute("SELECT COUNT(DISTINCT threat_class) FROM alerts;").fetchone()[0]

        return {
            "total_alerts": total,
            "critical": crit,
            "critical_alerts": crit,
            "high": high,
            "high_alerts": high,
            "medium": med,
            "medium_alerts": med,
            "low": low,
            "low_alerts": low,
            "correlated_incidents": corr,
            "unique_sources": srcs,
            "compromised_assets": srcs,
            "unique_threat_classes": threats,
            "threat_classes": threats,
        }


def get_threat_distribution(db_path: Path | str = DEFAULT_DB_PATH) -> list[dict[str, Any]]:
    """Get alert counts grouped by threat_class."""
    path = Path(db_path)
    if not path.is_file():
        return []

    sql = "SELECT threat_class, COUNT(*) as count FROM alerts GROUP BY threat_class ORDER BY count DESC;"
    with get_connection(path) as conn:
        rows = conn.execute(sql).fetchall()
        return [{"threat_class": r["threat_class"], "count": r["count"]} for r in rows]


def get_severity_distribution(db_path: Path | str = DEFAULT_DB_PATH) -> list[dict[str, Any]]:
    """Get alert counts grouped by severity."""
    path = Path(db_path)
    if not path.is_file():
        return []

    sql = "SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity;"
    with get_connection(path) as conn:
        rows = conn.execute(sql).fetchall()
        data = {r["severity"].lower(): r["count"] for r in rows}

    # Maintain standard ordering
    order = ["critical", "high", "medium", "low", "info"]
    return [{"severity": s, "count": data.get(s, 0)} for s in order if s in data or data.get(s, 0) > 0]


def get_detector_counts(db_path: Path | str = DEFAULT_DB_PATH) -> list[dict[str, Any]]:
    """Get alert and correlated incident counts per threat_class for detector coverage."""
    path = Path(db_path)
    if not path.is_file():
        return []

    sql = """
    SELECT
        threat_class,
        detector,
        COUNT(*) as alert_count,
        COUNT(DISTINCT CASE WHEN correlation_id IS NOT NULL AND correlation_id != '' THEN correlation_id END) as incident_count
    FROM alerts
    GROUP BY threat_class
    ORDER BY threat_class;
    """
    with get_connection(path) as conn:
        rows = conn.execute(sql).fetchall()
        return [
            {
                "threat_class": r["threat_class"],
                "detector": r["detector"],
                "alert_count": r["alert_count"],
                "incident_count": r["incident_count"],
            }
            for r in rows
        ]


def get_correlated_vs_uncorrelated(db_path: Path | str = DEFAULT_DB_PATH) -> dict[str, int]:
    """Get counts of correlated vs uncorrelated alerts."""
    path = Path(db_path)
    if not path.is_file():
        return {"correlated": 0, "uncorrelated": 0}

    with get_connection(path) as conn:
        corr = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE correlation_id IS NOT NULL AND correlation_id != '';"
        ).fetchone()[0]
        uncorr = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE correlation_id IS NULL OR correlation_id = '';"
        ).fetchone()[0]
    return {"correlated": corr, "uncorrelated": uncorr}


def get_timeseries(db_path: Path | str = DEFAULT_DB_PATH, interval_minutes: int = 5) -> list[dict[str, Any]]:
    """Get timeline of alert activity grouped by threat_class."""
    path = Path(db_path)
    if not path.is_file():
        return []

    sql = """
    SELECT
        substr(timestamp, 1, 16) as time_bucket,
        threat_class,
        COUNT(*) as count
    FROM alerts
    GROUP BY time_bucket, threat_class
    ORDER BY time_bucket ASC;
    """
    with get_connection(path) as conn:
        rows = conn.execute(sql).fetchall()
        return [
            {
                "time_bucket": r["time_bucket"],
                "threat_class": r["threat_class"],
                "count": r["count"],
            }
            for r in rows
        ]


def get_correlated_groups(db_path: Path | str = DEFAULT_DB_PATH) -> list[dict[str, Any]]:
    """Get multi-threat correlation groups with metadata."""
    path = Path(db_path)
    if not path.is_file():
        return []

    sql = """
    SELECT
        correlation_id,
        source,
        COUNT(*) as alert_count,
        MIN(timestamp) as first_seen,
        MAX(timestamp) as last_seen,
        GROUP_CONCAT(DISTINCT threat_class) as threat_classes_str
    FROM alerts
    WHERE correlation_id IS NOT NULL AND correlation_id != ''
    GROUP BY correlation_id
    ORDER BY first_seen DESC;
    """
    with get_connection(path) as conn:
        rows = conn.execute(sql).fetchall()
        results = []
        for r in rows:
            cid = r["correlation_id"]
            # Find highest severity in this group
            sev_row = conn.execute(
                "SELECT severity FROM alerts WHERE correlation_id = ? ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END ASC LIMIT 1;",
                (cid,),
            ).fetchone()
            highest_sev = sev_row["severity"] if sev_row else "unknown"

            threats = [t.strip() for t in r["threat_classes_str"].split(",")] if r["threat_classes_str"] else []

            results.append({
                "correlation_id": cid,
                "source": r["source"],
                "sources": [r["source"]],
                "alert_count": r["alert_count"],
                "first_seen": r["first_seen"],
                "last_seen": r["last_seen"],
                "threat_classes": threats,
                "highest_severity": highest_sev,
                "attack_chain": " → ".join(threats) if threats else "single-threat",
            })
        return results


def get_asset_summary(
    db_path: Path | str = DEFAULT_DB_PATH,
    asset_inventory: Optional[dict[str, Any]] = None,
) -> list[dict[str, Any]]:
    """Summarize alerts against lab demonstration asset inventory."""
    path = Path(db_path)
    if asset_inventory is None:
        try:
            from fusion.criticality import load_asset_inventory
            inv = load_asset_inventory()
        except Exception:
            inv = {}
    else:
        inv = asset_inventory

    alert_counts: dict[str, int] = {}
    last_seen_map: dict[str, str] = {}

    if path.is_file():
        with get_connection(path) as conn:
            # Count alerts where asset IP is source OR destination
            rows = conn.execute(
                "SELECT ip, SUM(c) as total, MAX(last_ts) as last_ts FROM ("
                "  SELECT source as ip, COUNT(*) as c, MAX(timestamp) as last_ts FROM alerts GROUP BY source"
                "  UNION ALL"
                "  SELECT destination as ip, COUNT(*) as c, MAX(timestamp) as last_ts FROM alerts GROUP BY destination"
                ") GROUP BY ip;"
            ).fetchall()
            for r in rows:
                alert_counts[r["ip"]] = r["total"]
                last_seen_map[r["ip"]] = r["last_ts"] or ""

    results = []
    for ip, meta in inv.items():
        results.append({
            "ip": ip,
            "name": meta.get("name", "Unknown Asset"),
            "role": meta.get("zone", ""),
            "criticality": meta.get("criticality", "unknown"),
            "zone": meta.get("zone", "Unzoned"),
            "alert_count": alert_counts.get(ip, 0),
            "last_seen": last_seen_map.get(ip) or None,
        })

    results.sort(key=lambda x: (0 if x["criticality"] == "critical" else (1 if x["criticality"] == "standard" else 2), -x["alert_count"]))
    return results


def clear_alerts(db_path: Path | str = DEFAULT_DB_PATH) -> None:
    """Clear all alerts from database (for test isolation)."""
    path = Path(db_path)
    if path.is_file():
        with get_connection(path) as conn:
            conn.execute("DELETE FROM alerts;")
            conn.commit()
