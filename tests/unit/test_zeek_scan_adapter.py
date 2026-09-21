"""Unit tests for detectors/scanning/zeek_scan_adapter.py."""

import json
from pathlib import Path
import pytest
import jsonschema

from alerts.constants import LatencyClass, ThreatClass, Severity
from alerts.validator import validate_draft_alert
from detectors.scanning.zeek_scan_adapter import ZeekScanAdapter, DETECTOR_NAME, MODEL_VERSION


@pytest.fixture
def adapter() -> ZeekScanAdapter:
    return ZeekScanAdapter()


@pytest.fixture
def alert_schema() -> dict:
    schema_path = Path("docs/04_alert_schema.json")
    with open(schema_path, "r", encoding="utf-8") as f:
        return json.load(f)


class TestZeekScanAdapter:
    """Tests covering all requirements for Zeek Scan Adapter."""

    def test_01_port_scan_emits_reconnaissance_alert(self, adapter: ZeekScanAdapter) -> None:
        """Requirement 1: Scan::Port_Scan -> reconnaissance alert."""
        record = {
            "ts": 1789720389.391378,
            "note": "Scan::Port_Scan",
            "msg": "192.168.56.102 scanned at least 15 unique ports of host 192.168.56.254 in 0m0s",
            "sub": "local",
            "src": "192.168.56.102",
            "dst": "192.168.56.254",
            "actions": ["Notice::ACTION_LOG"],
            "email_dest": [],
            "suppress_for": 3600.0,
        }
        alert = adapter.process_notice(record)
        assert alert is not None
        assert alert.threat_class == ThreatClass.RECONNAISSANCE
        assert alert.threat_class == "reconnaissance"
        assert alert.subtype == "port_scan"
        assert alert.source == "192.168.56.102"
        assert alert.destination == "192.168.56.254"
        assert alert.supporting_evidence["scan_count"] == "scan_count unavailable in native notice"
        assert alert.supporting_evidence["native_notice"] == record

    def test_02_address_scan_emits_reconnaissance_alert(self, adapter: ZeekScanAdapter) -> None:
        """Requirement 2: Scan::Address_Scan -> reconnaissance alert."""
        record = {
            "ts": 1789720400.123456,
            "note": "Scan::Address_Scan",
            "msg": "192.168.56.102 scanned at least 25 unique hosts on port 80/tcp",
            "sub": "local",
            "src": "192.168.56.102",
            "dst": "192.168.56.1",
            "actions": ["Notice::ACTION_LOG"],
        }
        alert = adapter.process_notice(record)
        assert alert is not None
        assert alert.threat_class == "reconnaissance"
        assert alert.subtype == "address_scan"
        assert alert.source == "192.168.56.102"
        assert alert.destination == "192.168.56.1"

    def test_03_non_scan_notice_ignored(self, adapter: ZeekScanAdapter) -> None:
        """Requirement 3: Non-scan notices are ignored."""
        non_scan_records = [
            {"ts": 1789720000.0, "note": "SSH::Password_Guessing", "src": "10.0.0.1"},
            {"ts": 1789720001.0, "note": "Notice::Weird", "src": "10.0.0.2"},
            {"ts": 1789720002.0, "note": "TeamCymruMalwareHashRegistry::Match", "src": "10.0.0.3"},
            {"ts": 1789720003.0, "note": "HTTP::SQL_Injection_Attempt", "src": "10.0.0.4"},
        ]
        for rec in non_scan_records:
            alert = adapter.process_notice(rec)
            assert alert is None

    def test_04_malformed_notice_safely_handled(self, adapter: ZeekScanAdapter) -> None:
        """Requirement 4: Malformed lines and structures are safely handled without crash."""
        assert adapter.parse_notice_line("") is None
        assert adapter.parse_notice_line("   \n") is None
        assert adapter.parse_notice_line("invalid json string {not:json}") is None
        assert adapter.parse_notice_line('["not a dict"]') is None
        assert adapter.parse_notice_line('12345') is None
        assert adapter.process_notice(None) is None  # type: ignore
        assert adapter.process_notice([]) is None  # type: ignore

    def test_05_optional_and_missing_fields_safely_handled(self, adapter: ZeekScanAdapter) -> None:
        """Requirement 5: Notices with missing or non-standard fields are handled safely."""
        minimal_record = {
            "note": "Scan::Port_Scan",
        }
        alert = adapter.process_notice(minimal_record)
        assert alert is not None
        assert alert.source == "unknown"
        assert alert.destination == "unknown"
        assert alert.threat_class == "reconnaissance"
        assert alert.subtype == "port_scan"
        assert alert.supporting_evidence["scan_count"] == "scan_count unavailable in native notice"
        assert isinstance(alert.timestamp, str)

        # Test with custom native count field if present
        record_with_count = {
            "note": "Scan::Port_Scan",
            "src": "10.0.0.5",
            "dst": "10.0.0.9",
            "p": 25,
        }
        alert2 = adapter.process_notice(record_with_count)
        assert alert2 is not None
        assert alert2.supporting_evidence["scan_count"] == 25

    def test_06_latency_class_explicitly_set_to_event_driven(self, adapter: ZeekScanAdapter) -> None:
        """Requirement 6: latency_class is explicitly set to 'event_driven'."""
        record = {
            "ts": 1789720389.0,
            "note": "Scan::Port_Scan",
            "src": "192.168.56.102",
            "dst": "192.168.56.254",
        }
        alert = adapter.process_notice(record)
        assert alert is not None
        assert alert.latency_class == "event_driven"
        assert alert.latency_class == LatencyClass.EVENT_DRIVEN
        d = alert.to_dict()
        assert d["latency_class"] == "event_driven"

    def test_07_alert_validates_against_validator_and_schema(
        self, adapter: ZeekScanAdapter, alert_schema: dict
    ) -> None:
        """Requirement 7: Resulting alert passes project validator and JSON schema."""
        record = {
            "ts": 1789720389.391378,
            "note": "Scan::Port_Scan",
            "msg": "192.168.56.102 scanned at least 15 unique ports of host 192.168.56.254 in 0m0s",
            "sub": "local",
            "src": "192.168.56.102",
            "dst": "192.168.56.254",
            "actions": ["Notice::ACTION_LOG"],
        }
        alert = adapter.process_notice(record)
        assert alert is not None
        alert_dict = alert.to_dict()

        # 1. Project validator
        is_valid, errors = validate_draft_alert(alert_dict)
        assert is_valid is True
        assert errors == []

        # 2. Schema JSON validation (docs/04_alert_schema.json)
        jsonschema.validate(instance=alert_dict, schema=alert_schema)

    def test_08_process_notice_log_file(self, tmp_path: Path, adapter: ZeekScanAdapter) -> None:
        """Test reading notice log from file end-to-end."""
        log_file = tmp_path / "notice.log"
        entries = [
            json.dumps({"ts": 1000.0, "note": "Scan::Port_Scan", "src": "1.1.1.1", "dst": "2.2.2.2"}),
            "corrupted non-json line",
            json.dumps({"ts": 1001.0, "note": "SSH::Login_Failed", "src": "3.3.3.3"}),
            json.dumps({"ts": 1002.0, "note": "Scan::Address_Scan", "src": "4.4.4.4", "dst": "5.5.5.5"}),
        ]
        log_file.write_text("\n".join(entries), encoding="utf-8")

        alerts = adapter.process_notice_log(log_file)
        assert len(alerts) == 2
        assert alerts[0].subtype == "port_scan"
        assert alerts[1].subtype == "address_scan"
