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
    created_at TEXT DEFAULT (datetime('now')),
    pcap_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_threat_class ON alerts(threat_class);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_source ON alerts(source);
CREATE INDEX IF NOT EXISTS idx_alerts_destination ON alerts(destination);
CREATE INDEX IF NOT EXISTS idx_alerts_correlation_id ON alerts(correlation_id);

CREATE TABLE IF NOT EXISTS pcap_analyses (
    pcap_id TEXT PRIMARY KEY,
    filename TEXT NOT NULL,
    file_size_bytes INTEGER NOT NULL,
    pcap_format TEXT,
    upload_timestamp TEXT NOT NULL,
    analysis_start_time TEXT,
    analysis_end_time TEXT,
    duration_seconds REAL,
    status TEXT NOT NULL,
    error_message TEXT,
    connections_count INTEGER DEFAULT 0,
    dns_queries_count INTEGER DEFAULT 0,
    tls_sessions_count INTEGER DEFAULT 0,
    unique_hosts_count INTEGER DEFAULT 0,
    packets_count INTEGER DEFAULT 0,
    alerts_count INTEGER DEFAULT 0,
    threat_breakdown TEXT,
    severity_breakdown TEXT,
    detector_results TEXT,
    artifact_dir TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_pcap_analyses_upload_ts ON pcap_analyses(upload_timestamp);
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


def _build_scope_condition(
    pcap_id: Optional[str] = None,
    canonical_only: bool = False,
) -> tuple[Optional[str], list[Any]]:
    """Helper to return SQL condition and parameters for scoping by pcap_id or canonical-only."""
    if pcap_id is not None:
        return "pcap_id = ?", [pcap_id]
    if canonical_only:
        return "(pcap_id IS NULL OR pcap_id = '')", []
    return None, []


def init_db(db_path: Path | str = DEFAULT_DB_PATH) -> Path:
    """Initialize database tables, indexes, and apply backward-compatible migrations."""
    path = Path(db_path)
    with get_connection(path) as conn:
        conn.executescript(_SCHEMA_SQL)
        # Ensure pcap_id column exists on alerts table for pre-existing databases
        try:
            conn.execute("ALTER TABLE alerts ADD COLUMN pcap_id TEXT;")
        except sqlite3.OperationalError:
            pass  # Column already exists

        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_pcap_id ON alerts(pcap_id);")

        # Backfill pcap_id for any historical alerts where upload_id was stored in supporting_evidence
        try:
            cursor = conn.execute(
                "SELECT alert_id, supporting_evidence FROM alerts WHERE pcap_id IS NULL AND supporting_evidence LIKE '%upload_id%';"
            )
            rows = cursor.fetchall()
            for r in rows:
                try:
                    ev = json.loads(r["supporting_evidence"])
                    uid = ev.get("upload_id")
                    if uid:
                        conn.execute("UPDATE alerts SET pcap_id = ? WHERE alert_id = ?;", (uid, r["alert_id"]))
                except Exception:
                    pass
        except Exception:
            pass

        conn.commit()
    logger.debug("Initialized SQLite alert store at %s", path)
    return path


def _to_alert_dict(alert: dict[str, Any] | DraftAlert) -> dict[str, Any]:
    if hasattr(alert, "to_dict"):
        return alert.to_dict()
    return dict(alert)


def insert_alert(
    alert: dict[str, Any] | DraftAlert,
    db_path: Path | str = DEFAULT_DB_PATH,
    pcap_id: Optional[str] = None,
) -> str:
    """Insert a single alert into SQLite. Returns alert_id."""
    init_db(db_path)
    d = _to_alert_dict(alert)
    alert_id = d.get("alert_id", "")

    evidence_dict = d.get("supporting_evidence", {})
    evidence_str = json.dumps(evidence_dict)
    corr_ids_str = json.dumps(d.get("correlated_alert_ids", []))
    raw_str = json.dumps(d)

    resolved_pcap_id = pcap_id or d.get("pcap_id")
    if not resolved_pcap_id and isinstance(evidence_dict, dict):
        resolved_pcap_id = evidence_dict.get("upload_id")

    sql = """
    INSERT INTO alerts (
        alert_id, timestamp, flow_id, threat_class, severity,
        confidence, source, destination, detector, model_version,
        schema_version, subtype, latency_class, asset_criticality,
        correlation_id, correlated_alert_ids, supporting_evidence, raw_alert,
        pcap_id
    ) VALUES (
        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
    )
    ON CONFLICT(alert_id) DO UPDATE SET
        severity=excluded.severity,
        asset_criticality=excluded.asset_criticality,
        correlation_id=excluded.correlation_id,
        correlated_alert_ids=excluded.correlated_alert_ids,
        supporting_evidence=excluded.supporting_evidence,
        raw_alert=excluded.raw_alert,
        pcap_id=excluded.pcap_id;
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
                resolved_pcap_id,
            ),
        )
        conn.commit()

    return alert_id


def insert_alerts(
    alerts: list[dict[str, Any] | DraftAlert],
    db_path: Path | str = DEFAULT_DB_PATH,
    pcap_id: Optional[str] = None,
) -> int:
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
        correlation_id, correlated_alert_ids, supporting_evidence, raw_alert,
        pcap_id
    ) VALUES (
        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
    )
    ON CONFLICT(alert_id) DO UPDATE SET
        severity=excluded.severity,
        asset_criticality=excluded.asset_criticality,
        correlation_id=excluded.correlation_id,
        correlated_alert_ids=excluded.correlated_alert_ids,
        supporting_evidence=excluded.supporting_evidence,
        raw_alert=excluded.raw_alert,
        pcap_id=excluded.pcap_id;
    """

    with get_connection(db_path) as conn:
        params = []
        for a in alerts:
            d = _to_alert_dict(a)
            evidence_dict = d.get("supporting_evidence", {})
            resolved_pcap_id = pcap_id or d.get("pcap_id")
            if not resolved_pcap_id and isinstance(evidence_dict, dict):
                resolved_pcap_id = evidence_dict.get("upload_id")

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
                json.dumps(evidence_dict),
                json.dumps(d),
                resolved_pcap_id,
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
            if "pcap_id" in d and d["pcap_id"] and "pcap_id" not in raw:
                raw["pcap_id"] = d["pcap_id"]
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
    pcap_id: Optional[str] = None,
    canonical_only: bool = False,
    limit: Optional[int] = None,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """Retrieve filtered alerts ordered by timestamp descending."""
    path = Path(db_path)
    if not path.is_file():
        return []

    conditions: list[str] = []
    params: list[Any] = []

    scope_cond, scope_params = _build_scope_condition(pcap_id=pcap_id, canonical_only=canonical_only)
    if scope_cond:
        conditions.append(scope_cond)
        params.extend(scope_params)

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
    if limit is not None and limit > 0:
        sql = f"SELECT * FROM alerts {where_clause} ORDER BY timestamp DESC LIMIT ? OFFSET ?;"
        params.extend([limit, offset])
    else:
        sql = f"SELECT * FROM alerts {where_clause} ORDER BY timestamp DESC;"

    with get_connection(path) as conn:
        rows = conn.execute(sql, params).fetchall()
        return [_row_to_dict(r) for r in rows]


def count_alerts(
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
    pcap_id: Optional[str] = None,
    canonical_only: bool = False,
) -> int:
    """Count filtered alerts."""
    path = Path(db_path)
    if not path.is_file():
        return 0

    conditions: list[str] = []
    params: list[Any] = []

    scope_cond, scope_params = _build_scope_condition(pcap_id=pcap_id, canonical_only=canonical_only)
    if scope_cond:
        conditions.append(scope_cond)
        params.extend(scope_params)

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
    sql = f"SELECT COUNT(*) FROM alerts {where_clause};"

    with get_connection(path) as conn:
        row = conn.execute(sql, params).fetchone()
        return int(row[0]) if row else 0


def get_kpi_summary(
    db_path: Path | str = DEFAULT_DB_PATH,
    pcap_id: Optional[str] = None,
    canonical_only: bool = False,
) -> dict[str, int]:
    """Retrieve aggregate summary counts for KPI cards, optionally scoped to pcap_id or canonical-only."""
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

    conditions = []
    params = []
    scope_cond, scope_params = _build_scope_condition(pcap_id=pcap_id, canonical_only=canonical_only)
    if scope_cond:
        conditions.append(scope_cond)
        params.extend(scope_params)

    where_base = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    def _query(extra_cond: str = "") -> int:
        local_conds = list(conditions)
        local_params = list(params)
        if extra_cond:
            local_conds.append(extra_cond)
        clause = f"WHERE {' AND '.join(local_conds)}" if local_conds else ""
        with get_connection(path) as conn:
            return conn.execute(f"SELECT COUNT(*) FROM alerts {clause};", local_params).fetchone()[0]

    with get_connection(path) as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM alerts {where_base};", params).fetchone()[0]
        if total == 0:
            return defaults

        crit = _query("severity = 'critical'")
        high = _query("severity = 'high'")
        med = _query("severity = 'medium'")
        low = _query("severity = 'low'")

        corr_conds = list(conditions) + ["correlation_id IS NOT NULL AND correlation_id != ''"]
        corr_clause = f"WHERE {' AND '.join(corr_conds)}"
        corr = conn.execute(f"SELECT COUNT(DISTINCT correlation_id) FROM alerts {corr_clause};", params).fetchone()[0]

        srcs = conn.execute(f"SELECT COUNT(DISTINCT source) FROM alerts {where_base};", params).fetchone()[0]
        threats = conn.execute(f"SELECT COUNT(DISTINCT threat_class) FROM alerts {where_base};", params).fetchone()[0]

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


def get_threat_distribution(
    db_path: Path | str = DEFAULT_DB_PATH,
    pcap_id: Optional[str] = None,
    canonical_only: bool = False,
) -> list[dict[str, Any]]:
    """Get alert counts grouped by threat_class."""
    path = Path(db_path)
    if not path.is_file():
        return []

    conditions = []
    params = []
    scope_cond, scope_params = _build_scope_condition(pcap_id=pcap_id, canonical_only=canonical_only)
    if scope_cond:
        conditions.append(scope_cond)
        params.extend(scope_params)

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    sql = f"SELECT threat_class, COUNT(*) as count FROM alerts {where_clause} GROUP BY threat_class ORDER BY count DESC;"
    with get_connection(path) as conn:
        rows = conn.execute(sql, params).fetchall()
        return [{"threat_class": r["threat_class"], "count": r["count"]} for r in rows]


def get_severity_distribution(
    db_path: Path | str = DEFAULT_DB_PATH,
    pcap_id: Optional[str] = None,
    canonical_only: bool = False,
) -> list[dict[str, Any]]:
    """Get alert counts grouped by severity."""
    path = Path(db_path)
    if not path.is_file():
        return []

    conditions = []
    params = []
    scope_cond, scope_params = _build_scope_condition(pcap_id=pcap_id, canonical_only=canonical_only)
    if scope_cond:
        conditions.append(scope_cond)
        params.extend(scope_params)

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    sql = f"SELECT severity, COUNT(*) as count FROM alerts {where_clause} GROUP BY severity;"
    with get_connection(path) as conn:
        rows = conn.execute(sql, params).fetchall()
        data = {r["severity"].lower(): r["count"] for r in rows}

    order = ["critical", "high", "medium", "low", "info"]
    return [{"severity": s, "count": data.get(s, 0)} for s in order if s in data or data.get(s, 0) > 0]


def get_detector_counts(
    db_path: Path | str = DEFAULT_DB_PATH,
    pcap_id: Optional[str] = None,
    canonical_only: bool = False,
) -> list[dict[str, Any]]:
    """Get alert and correlated incident counts per threat_class for detector coverage."""
    path = Path(db_path)
    if not path.is_file():
        return []

    conditions = []
    params = []
    scope_cond, scope_params = _build_scope_condition(pcap_id=pcap_id, canonical_only=canonical_only)
    if scope_cond:
        conditions.append(scope_cond)
        params.extend(scope_params)

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    sql = f"""
    SELECT
        threat_class,
        detector,
        COUNT(*) as alert_count,
        COUNT(DISTINCT CASE WHEN correlation_id IS NOT NULL AND correlation_id != '' THEN correlation_id END) as incident_count
    FROM alerts
    {where_clause}
    GROUP BY threat_class
    ORDER BY threat_class;
    """
    with get_connection(path) as conn:
        rows = conn.execute(sql, params).fetchall()
        return [
            {
                "threat_class": r["threat_class"],
                "detector": r["detector"],
                "alert_count": r["alert_count"],
                "incident_count": r["incident_count"],
            }
            for r in rows
        ]


def get_correlated_vs_uncorrelated(
    db_path: Path | str = DEFAULT_DB_PATH,
    pcap_id: Optional[str] = None,
    canonical_only: bool = False,
) -> dict[str, int]:
    """Get counts of correlated vs uncorrelated alerts."""
    path = Path(db_path)
    if not path.is_file():
        return {"correlated": 0, "uncorrelated": 0}

    conditions = []
    params = []
    scope_cond, scope_params = _build_scope_condition(pcap_id=pcap_id, canonical_only=canonical_only)
    if scope_cond:
        conditions.append(scope_cond)
        params.extend(scope_params)

    with get_connection(path) as conn:
        corr_conds = list(conditions) + ["correlation_id IS NOT NULL AND correlation_id != ''"]
        corr_sql = f"SELECT COUNT(*) FROM alerts WHERE {' AND '.join(corr_conds)};"
        corr = conn.execute(corr_sql, params).fetchone()[0]

        uncorr_conds = list(conditions) + ["(correlation_id IS NULL OR correlation_id = '')"]
        uncorr_sql = f"SELECT COUNT(*) FROM alerts WHERE {' AND '.join(uncorr_conds)};"
        uncorr = conn.execute(uncorr_sql, params).fetchone()[0]

    return {"correlated": corr, "uncorrelated": uncorr}


def get_timeseries(
    db_path: Path | str = DEFAULT_DB_PATH,
    interval_minutes: int = 5,
    pcap_id: Optional[str] = None,
    canonical_only: bool = False,
) -> list[dict[str, Any]]:
    """Get timeline of alert activity grouped by threat_class."""
    path = Path(db_path)
    if not path.is_file():
        return []

    conditions = []
    params = []
    scope_cond, scope_params = _build_scope_condition(pcap_id=pcap_id, canonical_only=canonical_only)
    if scope_cond:
        conditions.append(scope_cond)
        params.extend(scope_params)

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    sql = f"""
    SELECT
        substr(timestamp, 1, 16) as time_bucket,
        threat_class,
        COUNT(*) as count
    FROM alerts
    {where_clause}
    GROUP BY time_bucket, threat_class
    ORDER BY time_bucket ASC;
    """
    with get_connection(path) as conn:
        rows = conn.execute(sql, params).fetchall()
        return [
            {
                "time_bucket": r["time_bucket"],
                "threat_class": r["threat_class"],
                "count": r["count"],
            }
            for r in rows
        ]


def get_correlated_groups(
    db_path: Path | str = DEFAULT_DB_PATH,
    pcap_id: Optional[str] = None,
    canonical_only: bool = False,
) -> list[dict[str, Any]]:
    """Get multi-threat correlation groups with metadata."""
    path = Path(db_path)
    if not path.is_file():
        return []

    conditions = ["correlation_id IS NOT NULL AND correlation_id != ''"]
    params = []
    scope_cond, scope_params = _build_scope_condition(pcap_id=pcap_id, canonical_only=canonical_only)
    if scope_cond:
        conditions.append(scope_cond)
        params.extend(scope_params)

    where_clause = f"WHERE {' AND '.join(conditions)}"
    sql = f"""
    SELECT
        correlation_id,
        source,
        COUNT(*) as alert_count,
        MIN(timestamp) as first_seen,
        MAX(timestamp) as last_seen,
        GROUP_CONCAT(DISTINCT threat_class) as threat_classes_str
    FROM alerts
    {where_clause}
    GROUP BY correlation_id
    ORDER BY first_seen DESC;
    """
    with get_connection(path) as conn:
        rows = conn.execute(sql, params).fetchall()
        results = []
        for r in rows:
            cid = r["correlation_id"]
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
    pcap_id: Optional[str] = None,
    canonical_only: bool = False,
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

    conditions = []
    params = []
    scope_cond, scope_params = _build_scope_condition(pcap_id=pcap_id, canonical_only=canonical_only)
    if scope_cond:
        conditions.append(scope_cond)
        params.extend(scope_params)
    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    if path.is_file():
        with get_connection(path) as conn:
            query = f"""
            SELECT ip, SUM(c) as total, MAX(last_ts) as last_ts FROM (
              SELECT source as ip, COUNT(*) as c, MAX(timestamp) as last_ts FROM alerts {where_clause} GROUP BY source
              UNION ALL
              SELECT destination as ip, COUNT(*) as c, MAX(timestamp) as last_ts FROM alerts {where_clause} GROUP BY destination
            ) GROUP BY ip;
            """
            rows = conn.execute(query, params + params).fetchall()
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
            conn.execute("DELETE FROM pcap_analyses;")
            conn.commit()


# =====================================================================
# PCAP ANALYSIS SESSION MANAGEMENT (pcap_analyses)
# =====================================================================

def insert_pcap_analysis(record: dict[str, Any], db_path: Path | str = DEFAULT_DB_PATH) -> str:
    """Insert or update a PCAP analysis metadata record."""
    init_db(db_path)
    pcap_id = record["pcap_id"]

    sql = """
    INSERT INTO pcap_analyses (
        pcap_id, filename, file_size_bytes, pcap_format, upload_timestamp,
        analysis_start_time, analysis_end_time, duration_seconds, status,
        error_message, connections_count, dns_queries_count, tls_sessions_count,
        unique_hosts_count, packets_count, alerts_count, threat_breakdown,
        severity_breakdown, detector_results, artifact_dir
    ) VALUES (
        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
    )
    ON CONFLICT(pcap_id) DO UPDATE SET
        filename=excluded.filename,
        file_size_bytes=excluded.file_size_bytes,
        pcap_format=excluded.pcap_format,
        analysis_start_time=excluded.analysis_start_time,
        analysis_end_time=excluded.analysis_end_time,
        duration_seconds=excluded.duration_seconds,
        status=excluded.status,
        error_message=excluded.error_message,
        connections_count=excluded.connections_count,
        dns_queries_count=excluded.dns_queries_count,
        tls_sessions_count=excluded.tls_sessions_count,
        unique_hosts_count=excluded.unique_hosts_count,
        packets_count=excluded.packets_count,
        alerts_count=excluded.alerts_count,
        threat_breakdown=excluded.threat_breakdown,
        severity_breakdown=excluded.severity_breakdown,
        detector_results=excluded.detector_results,
        artifact_dir=excluded.artifact_dir;
    """

    threat_str = json.dumps(record.get("threat_breakdown", {}))
    sev_str = json.dumps(record.get("severity_breakdown", {}))
    det_str = json.dumps(record.get("detector_results", {}))

    with get_connection(db_path) as conn:
        conn.execute(
            sql,
            (
                pcap_id,
                record.get("filename", ""),
                record.get("file_size_bytes", 0),
                record.get("pcap_format", ""),
                record.get("upload_timestamp", ""),
                record.get("analysis_start_time"),
                record.get("analysis_end_time"),
                record.get("duration_seconds", 0.0),
                record.get("status", "processing"),
                record.get("error_message"),
                record.get("connections_count", 0),
                record.get("dns_queries_count", 0),
                record.get("tls_sessions_count", 0),
                record.get("unique_hosts_count", 0),
                record.get("packets_count", 0),
                record.get("alerts_count", 0),
                threat_str,
                sev_str,
                det_str,
                record.get("artifact_dir", ""),
            ),
        )
        conn.commit()

    return pcap_id


def update_pcap_analysis(
    pcap_id: str,
    updates: dict[str, Any],
    db_path: Path | str = DEFAULT_DB_PATH,
) -> bool:
    """Update fields on an existing pcap_analyses row."""
    init_db(db_path)
    if not updates:
        return False

    set_clauses = []
    params = []
    for k, v in updates.items():
        if k in ("threat_breakdown", "severity_breakdown", "detector_results") and isinstance(v, (dict, list)):
            v = json.dumps(v)
        set_clauses.append(f"{k} = ?")
        params.append(v)

    params.append(pcap_id)
    sql = f"UPDATE pcap_analyses SET {', '.join(set_clauses)} WHERE pcap_id = ?;"

    with get_connection(db_path) as conn:
        cursor = conn.execute(sql, params)
        conn.commit()
        return cursor.rowcount > 0


def _pcap_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    """Convert pcap_analyses row to dict with JSON fields unpacked."""
    d = dict(row)
    for json_field in ("threat_breakdown", "severity_breakdown", "detector_results"):
        if json_field in d and isinstance(d[json_field], str) and d[json_field]:
            try:
                d[json_field] = json.loads(d[json_field])
            except Exception:
                d[json_field] = {}
        elif json_field in d and not d[json_field]:
            d[json_field] = {}
    return d


def get_pcap_analyses(db_path: Path | str = DEFAULT_DB_PATH) -> list[dict[str, Any]]:
    """Retrieve all PCAP analysis records ordered by upload_timestamp descending."""
    path = Path(db_path)
    if not path.is_file():
        return []

    init_db(path)
    with get_connection(path) as conn:
        rows = conn.execute("SELECT * FROM pcap_analyses ORDER BY upload_timestamp DESC;").fetchall()
        return [_pcap_row_to_dict(r) for r in rows]


def get_pcap_analysis_by_id(pcap_id: str, db_path: Path | str = DEFAULT_DB_PATH) -> Optional[dict[str, Any]]:
    """Retrieve single PCAP analysis record by pcap_id."""
    path = Path(db_path)
    if not path.is_file():
        return None

    init_db(path)
    with get_connection(path) as conn:
        row = conn.execute("SELECT * FROM pcap_analyses WHERE pcap_id = ?;", (pcap_id,)).fetchone()
        if row:
            return _pcap_row_to_dict(row)
    return None


def delete_pcap_analysis_records(pcap_id: str, db_path: Path | str = DEFAULT_DB_PATH) -> tuple[int, int]:
    """
    Transactionally delete all database records belonging to a pcap_id:
      1. Associated alerts in alerts table
      2. The PCAP session record in pcap_analyses table
    Returns (alerts_deleted, analyses_deleted).
    """
    path = Path(db_path)
    if not path.is_file():
        return (0, 0)

    with get_connection(path) as conn:
        c1 = conn.execute("DELETE FROM alerts WHERE pcap_id = ?;", (pcap_id,)).rowcount
        c2 = conn.execute("DELETE FROM pcap_analyses WHERE pcap_id = ?;", (pcap_id,)).rowcount
        conn.commit()
        return (c1, c2)

