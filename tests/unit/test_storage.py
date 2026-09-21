"""tests/unit/test_storage.py
Unit tests for SQLite storage layer (storage/sqlite_store.py).
"""

from pathlib import Path
import sqlite3
import pytest

from storage.sqlite_store import (
    get_alert_by_id,
    get_alerts,
    get_asset_summary,
    get_correlated_groups,
    get_kpi_summary,
    get_severity_distribution,
    get_threat_distribution,
    get_timeseries,
    init_db,
    insert_alert,
    insert_alerts,
)


@pytest.fixture
def temp_db(tmp_path: Path) -> Path:
    """Create a temporary SQLite database initialized with the schema."""
    db_path = tmp_path / "test_alerts.db"
    init_db(db_path)
    return db_path


@pytest.fixture
def sample_alerts():
    """Sample valid alert dictionaries representing multi-threat scenario."""
    return [
        {
            "alert_id": "alert-001",
            "timestamp": "2026-09-19T10:00:00Z",
            "flow_id": "flow-100",
            "threat_class": "reconnaissance",
            "severity": "low",
            "confidence": 0.95,
            "source": "192.168.56.200",
            "destination": "192.168.56.10",
            "asset_criticality": "critical",
            "correlation_id": "corr-group-1",
            "mitre_technique": "T1046",
            "action_recommended": "block_ip",
            "detector": "zeek_scan_adapter",
            "model_version": "1.0.0",
            "schema_version": "1.0.0",
            "supporting_evidence": {"scan_type": "port_scan", "ports_contacted": 15},
        },
        {
            "alert_id": "alert-002",
            "timestamp": "2026-09-19T10:05:00Z",
            "flow_id": "flow-101",
            "threat_class": "beaconing",
            "severity": "high",
            "confidence": 0.88,
            "source": "192.168.56.200",
            "destination": "198.51.100.25",
            "asset_criticality": "standard",
            "correlation_id": "corr-group-1",
            "mitre_technique": "T1071.001",
            "action_recommended": "isolate_host",
            "detector": "rita_beacon_adapter",
            "model_version": "1.0.0",
            "schema_version": "1.0.0",
            "supporting_evidence": {"beacon_score": 0.92, "connection_count": 120},
        },
        {
            "alert_id": "alert-003",
            "timestamp": "2026-09-19T10:10:00Z",
            "flow_id": "flow-102",
            "threat_class": "exfiltration",
            "severity": "critical",
            "confidence": 0.99,
            "source": "192.168.56.10",
            "destination": "203.0.113.5",
            "asset_criticality": "critical",
            "correlation_id": None,
            "mitre_technique": "T1048",
            "action_recommended": "isolate_host",
            "detector": "exfiltration_detector",
            "model_version": "1.0.0",
            "schema_version": "1.0.0",
            "supporting_evidence": {"outbound_bytes": 52428800, "byte_ratio": 45.2},
        },
    ]


def test_init_db(temp_db: Path):
    """Verify database initialization creates tables and indexes idempotently."""
    assert temp_db.exists()

    # Re-running init_db must not raise error
    init_db(temp_db)

    # Verify tables and indexes exist
    conn = sqlite3.connect(temp_db)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='alerts';")
    assert cursor.fetchone() is not None

    cursor.execute("SELECT name FROM sqlite_master WHERE type='index';")
    indexes = {row[0] for row in cursor.fetchall()}
    assert "idx_alerts_timestamp" in indexes
    assert "idx_alerts_threat_class" in indexes
    assert "idx_alerts_severity" in indexes
    assert "idx_alerts_source" in indexes
    assert "idx_alerts_correlation_id" in indexes
    conn.close()


def test_insert_alert_and_get_by_id(temp_db: Path, sample_alerts):
    """Test inserting an alert and retrieving it by primary key."""
    a1 = sample_alerts[0]
    res = insert_alert(a1, temp_db)
    assert res == "alert-001"

    # Inserting duplicate should safely update/upsert and return alert_id
    dup_res = insert_alert(a1, temp_db)
    assert dup_res == "alert-001"

    retrieved = get_alert_by_id("alert-001", temp_db)
    assert retrieved is not None
    assert retrieved["alert_id"] == "alert-001"
    assert retrieved["threat_class"] == "reconnaissance"
    assert retrieved["severity"] == "low"
    assert retrieved["source"] == "192.168.56.200"
    assert retrieved["destination"] == "192.168.56.10"
    assert retrieved["asset_criticality"] == "critical"
    assert retrieved["correlation_id"] == "corr-group-1"
    assert retrieved["supporting_evidence"]["scan_type"] == "port_scan"


def test_insert_alerts_batch(temp_db: Path, sample_alerts):
    """Test batch inserting alerts."""
    inserted = insert_alerts(sample_alerts, temp_db)
    assert inserted == 3

    all_alerts = get_alerts(temp_db)
    assert len(all_alerts) == 3


def test_get_alerts_filtering(temp_db: Path, sample_alerts):
    """Test multi-parameter filtering on get_alerts."""
    insert_alerts(sample_alerts, temp_db)

    # Filter by threat_class
    recon = get_alerts(temp_db, threat_class="reconnaissance")
    assert len(recon) == 1
    assert recon[0]["alert_id"] == "alert-001"

    # Filter by severity
    crit = get_alerts(temp_db, severity="critical")
    assert len(crit) == 1
    assert crit[0]["alert_id"] == "alert-003"

    # Filter by source
    src_filtered = get_alerts(temp_db, source="192.168.56.200")
    assert len(src_filtered) == 2

    # Filter by correlation_id
    corr = get_alerts(temp_db, correlation_id="corr-group-1")
    assert len(corr) == 2

    # Search term across evidence and action
    search_res = get_alerts(temp_db, search_term="port_scan")
    assert len(search_res) == 1
    assert search_res[0]["alert_id"] == "alert-001"

    search_action = get_alerts(temp_db, search_term="isolate_host")
    assert len(search_action) == 2

    # Pagination: limit & offset
    paginated = get_alerts(temp_db, limit=2, offset=0)
    assert len(paginated) == 2
    paginated_offset = get_alerts(temp_db, limit=2, offset=2)
    assert len(paginated_offset) == 1


def test_get_kpi_summary(temp_db: Path, sample_alerts):
    """Test KPI aggregation calculations."""
    insert_alerts(sample_alerts, temp_db)

    kpis = get_kpi_summary(temp_db)
    assert kpis["total_alerts"] == 3
    assert kpis["critical"] == 1
    assert kpis["high"] == 1
    assert kpis["low"] == 1
    assert kpis["medium"] == 0
    assert kpis["correlated_incidents"] == 1
    assert kpis["threat_classes"] == 3
    assert kpis["compromised_assets"] == 2  # 192.168.56.200, 192.168.56.10


def test_get_threat_and_severity_distribution(temp_db: Path, sample_alerts):
    """Test distribution aggregation queries."""
    insert_alerts(sample_alerts, temp_db)

    threat_dist = get_threat_distribution(temp_db)
    threat_map = {item["threat_class"]: item["count"] for item in threat_dist}
    assert threat_map["reconnaissance"] == 1
    assert threat_map["beaconing"] == 1
    assert threat_map["exfiltration"] == 1

    sev_dist = get_severity_distribution(temp_db)
    sev_map = {item["severity"]: item["count"] for item in sev_dist}
    assert sev_map["critical"] == 1
    assert sev_map["high"] == 1
    assert sev_map["low"] == 1


def test_get_correlated_groups(temp_db: Path, sample_alerts):
    """Test multi-threat attack chain reconstruction."""
    insert_alerts(sample_alerts, temp_db)

    groups = get_correlated_groups(temp_db)
    assert len(groups) == 1

    grp = groups[0]
    assert grp["correlation_id"] == "corr-group-1"
    assert grp["alert_count"] == 2
    assert "reconnaissance → beaconing" in grp["attack_chain"]
    assert "192.168.56.200" in grp["sources"]


def test_get_asset_summary(temp_db: Path, sample_alerts):
    """Test asset summary joining with alerts."""
    insert_alerts(sample_alerts, temp_db)

    assets = get_asset_summary(temp_db)
    assert len(assets) > 0
    # 192.168.56.10 (PLC-01) is in assets.yaml and present in sample_alerts
    plc = next((a for a in assets if a["ip"] == "192.168.56.10"), None)
    assert plc is not None
    assert plc["alert_count"] >= 1
