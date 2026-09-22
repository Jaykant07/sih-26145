import sys
from pathlib import Path
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pytest
from streamlit.testing.v1 import AppTest

from dashboard.db import (
    check_db_status,
    fetch_alert_detail,
    fetch_alerts,
    fetch_asset_summary,
    fetch_correlated_groups,
    fetch_kpis,
    fetch_pcap_alerts,
    fetch_pcap_alerts_count,
    fetch_severity_distribution,
    fetch_threat_distribution,
    fetch_timeseries,
)
from storage.sqlite_store import count_alerts, init_db, insert_alerts


@pytest.fixture
def sample_test_alerts():
    """Sample alerts for dashboard query testing."""
    return [
        {
            "alert_id": "dash-001",
            "timestamp": "2026-09-19T11:00:00Z",
            "flow_id": "f-1",
            "threat_class": "reconnaissance",
            "severity": "low",
            "confidence": 0.90,
            "source": "192.168.56.200",
            "destination": "192.168.56.10",
            "asset_criticality": "critical",
            "correlation_id": "c-100",
            "mitre_technique": "T1046",
            "action_recommended": "block_ip",
            "detector": "zeek_scan_adapter",
            "model_version": "1.0.0",
            "schema_version": "1.0.0",
            "supporting_evidence": {"scan_type": "port_scan"},
        },
        {
            "alert_id": "dash-002",
            "timestamp": "2026-09-19T11:05:00Z",
            "flow_id": "f-2",
            "threat_class": "beaconing",
            "severity": "high",
            "confidence": 0.85,
            "source": "192.168.56.200",
            "destination": "198.51.100.1",
            "asset_criticality": "standard",
            "correlation_id": "c-100",
            "mitre_technique": "T1071.001",
            "action_recommended": "isolate_host",
            "detector": "rita_beacon_adapter",
            "model_version": "1.0.0",
            "schema_version": "1.0.0",
            "supporting_evidence": {"score": 0.9},
        },
    ]


def test_check_db_status_missing(tmp_path: Path):
    """Test db status when database file does not exist."""
    missing = tmp_path / "nonexistent.db"
    online, msg, count = check_db_status(missing)
    assert not online
    assert "not found" in msg.lower()
    assert count == 0


def test_check_db_status_empty(tmp_path: Path):
    """Test db status on an initialized empty database."""
    db_file = tmp_path / "empty.db"
    init_db(db_file)

    online, msg, count = check_db_status(db_file)
    assert online
    assert msg == "Online"
    assert count == 0


def test_check_db_status_populated(tmp_path: Path, sample_test_alerts):
    """Test db status on a populated database."""
    db_file = tmp_path / "populated.db"
    init_db(db_file)
    insert_alerts(sample_test_alerts, db_file)

    online, msg, count = check_db_status(db_file)
    assert online
    assert msg == "Online"
    assert count == 2


def test_fetch_functions_empty_db(tmp_path: Path):
    """Test all fetch_* functions return safe structures on empty database."""
    db_file = tmp_path / "empty.db"
    init_db(db_file)
    p_str = str(db_file)

    kpis = fetch_kpis(p_str)
    assert kpis["total_alerts"] == 0
    assert kpis["critical"] == 0

    alerts = fetch_alerts(p_str)
    assert alerts == []

    detail = fetch_alert_detail(p_str, "nonexistent")
    assert detail is None

    threat_dist = fetch_threat_distribution(p_str)
    assert threat_dist == []

    sev_dist = fetch_severity_distribution(p_str)
    assert sev_dist == []

    ts = fetch_timeseries(p_str)
    assert ts == []

    incidents = fetch_correlated_groups(p_str)
    assert incidents == []

    assets = fetch_asset_summary(p_str)
    assert isinstance(assets, list)


def test_fetch_functions_populated(tmp_path: Path, sample_test_alerts):
    """Test all fetch_* functions return expected results when populated."""
    db_file = tmp_path / "populated.db"
    init_db(db_file)
    insert_alerts(sample_test_alerts, db_file)
    p_str = str(db_file)

    kpis = fetch_kpis(p_str)
    assert kpis["total_alerts"] == 2
    assert kpis["high"] == 1
    assert kpis["low"] == 1
    assert kpis["correlated_incidents"] == 1

    alerts = fetch_alerts(p_str)
    assert len(alerts) == 2

    detail = fetch_alert_detail(p_str, "dash-001")
    assert detail is not None
    assert detail["alert_id"] == "dash-001"
    assert detail["threat_class"] == "reconnaissance"

    threat_dist = fetch_threat_distribution(p_str)
    assert len(threat_dist) == 2

    sev_dist = fetch_severity_distribution(p_str)
    assert len(sev_dist) == 2

    incidents = fetch_correlated_groups(p_str)
    assert len(incidents) == 1
    assert incidents[0]["correlation_id"] == "c-100"


def test_streamlit_app_empty_state(tmp_path: Path, monkeypatch):
    """Test full Streamlit AppTest execution on an empty database."""
    empty_db = tmp_path / "alerts.db"
    init_db(empty_db)

    # Monkeypatch get_active_db_path
    monkeypatch.setattr("dashboard.db.get_active_db_path", lambda: empty_db)
    import dashboard.pages.overview
    monkeypatch.setattr("dashboard.pages.overview.get_active_db_path", lambda: empty_db)

    app_path = Path(__file__).resolve().parent.parent.parent / "dashboard" / "app.py"
    at = AppTest.from_file(str(app_path))
    at.run(timeout=10)
    assert len(at.exception) == 0
    # Check info banner appears for zero alerts
    assert any("No alerts recorded yet" in info.value for info in at.info)


def test_streamlit_app_populated_state(tmp_path: Path, sample_test_alerts, monkeypatch):
    """Test full Streamlit AppTest execution on a populated database."""
    pop_db = tmp_path / "alerts.db"
    init_db(pop_db)
    insert_alerts(sample_test_alerts, pop_db)

    # Monkeypatch get_active_db_path
    monkeypatch.setattr("dashboard.db.get_active_db_path", lambda: pop_db)
    import dashboard.pages.overview
    monkeypatch.setattr("dashboard.pages.overview.get_active_db_path", lambda: pop_db)

    app_path = Path(__file__).resolve().parent.parent.parent / "dashboard" / "app.py"
    at = AppTest.from_file(str(app_path))
    at.run(timeout=10)
    assert len(at.exception) == 0
    # In populated state, dataframe and tabs are present
    assert len(at.dataframe) > 0


def test_count_alerts_and_pcap_pagination(tmp_path: Path):
    """Test database-level alert counting and pagination scoping."""
    db_file = tmp_path / "pcap_pagination.db"
    init_db(db_file)
    p_str = str(db_file)

    alerts = [
        {
            "alert_id": f"alert-{i:03d}",
            "timestamp": f"2026-09-20T10:{i:02d}:00Z",
            "flow_id": f"f-{i}",
            "threat_class": "ddos" if i % 2 == 0 else "beaconing",
            "severity": "critical" if i < 5 else "high",
            "confidence": 0.95,
            "source": f"192.168.1.{10 + i}",
            "destination": "10.0.0.1",
            "detector": "ddos_detector" if i % 2 == 0 else "rita_beacon_adapter",
            "pcap_id": "upload_abc123",
            "raw_alert": {"pcap_id": "upload_abc123"},
        }
        for i in range(15)
    ]
    # Also insert 2 alerts under a different pcap_id
    other_alerts = [
        {
            "alert_id": f"other-{i:03d}",
            "timestamp": f"2026-09-20T11:{i:02d}:00Z",
            "flow_id": f"f-other-{i}",
            "threat_class": "dga",
            "severity": "medium",
            "confidence": 0.88,
            "source": "10.0.0.50",
            "destination": "10.0.0.1",
            "detector": "dga_detector",
            "pcap_id": "upload_other999",
            "raw_alert": {"pcap_id": "upload_other999"},
        }
        for i in range(2)
    ]
    insert_alerts(alerts, db_file, pcap_id="upload_abc123")
    insert_alerts(other_alerts, db_file, pcap_id="upload_other999")

    # 1. Total count scoped to upload_abc123
    assert count_alerts(db_file, pcap_id="upload_abc123") == 15
    assert fetch_pcap_alerts_count(p_str, pcap_id="upload_abc123") == 15

    # 2. Count with severity filter
    assert fetch_pcap_alerts_count(p_str, pcap_id="upload_abc123", severity="critical") == 5
    assert fetch_pcap_alerts_count(p_str, pcap_id="upload_abc123", severity="high") == 10

    # 3. Count with threat class filter
    assert fetch_pcap_alerts_count(p_str, pcap_id="upload_abc123", threat_class="ddos") == 8
    assert fetch_pcap_alerts_count(p_str, pcap_id="upload_abc123", threat_class="beaconing") == 7

    # 4. Count with search term
    assert fetch_pcap_alerts_count(p_str, pcap_id="upload_abc123", search_term="192.168.1.10") == 1

    # 5. Pagination offset & limit
    page0 = fetch_pcap_alerts(p_str, pcap_id="upload_abc123", limit=5, offset=0)
    assert len(page0) == 5
    assert page0[0]["alert_id"] == "alert-014"  # timestamp DESC

    page1 = fetch_pcap_alerts(p_str, pcap_id="upload_abc123", limit=5, offset=5)
    assert len(page1) == 5
    assert page1[0]["alert_id"] == "alert-009"

    page2 = fetch_pcap_alerts(p_str, pcap_id="upload_abc123", limit=5, offset=10)
    assert len(page2) == 5
    assert page2[0]["alert_id"] == "alert-004"

    # Other pcap is isolated
    assert fetch_pcap_alerts_count(p_str, pcap_id="upload_other999") == 2

