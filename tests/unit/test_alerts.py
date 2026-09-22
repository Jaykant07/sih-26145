"""Unit tests for alerts — Unified DRAFT alert factory and validator."""

from datetime import datetime, timezone
import json
import logging
import math
import uuid
import pytest

from alerts.constants import LatencyClass, Severity, ThreatClass, SCHEMA_VERSION
from alerts.draft import DraftAlert, create_draft_alert
from alerts.validator import (
    AlertValidationError,
    SCHEMA_PATH,
    load_alert_schema,
    validate_alert,
    validate_draft_alert,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_alert(**overrides) -> DraftAlert:
    """Create a valid DraftAlert with sensible defaults, applying overrides."""
    kwargs = dict(
        timestamp="2026-09-16T12:00:00+00:00",
        flow_id="w_10.0.0.1_100_110",
        threat_class=ThreatClass.DDOS,
        severity=Severity.HIGH,
        confidence=0.85,
        source="10.0.0.50",
        destination="10.0.0.1",
        supporting_evidence={"pkt_rate": 1500.0, "z_score": 6.5},
        detector="ddos_detector",
        detector_version="0.1.0",
    )
    kwargs.update(overrides)
    return create_draft_alert(**kwargs)


# ---------------------------------------------------------------------------
# Section 19: Required Tests
# ---------------------------------------------------------------------------

class TestUnifiedAlertLayer:

    def test_01_valid_hand_built_alert_validates(self) -> None:
        """TEST 1: Valid hand-built alert dictionary validates against schema."""
        raw_alert = {
            "alert_id": str(uuid.uuid4()),
            "timestamp": "2026-09-19T14:30:00+00:00",
            "flow_id": "flow-manual-01",
            "threat_class": "ddos",
            "severity": "critical",
            "confidence": 0.95,
            "source": "192.168.1.10",
            "destination": "192.168.1.1",
            "supporting_evidence": {"pps": 120000, "entropy": 0.12},
            "detector": "ddos_detector",
            "model_version": "1.0.0",
            "schema_version": "1.0.0",
            "latency_class": "event_driven",
        }
        is_valid, errors = validate_draft_alert(raw_alert)
        assert is_valid is True
        assert errors == []
        validated = validate_alert(raw_alert)
        assert validated["alert_id"] == raw_alert["alert_id"]

    def test_02_factory_generated_alert_validates(self) -> None:
        """TEST 2: Factory-generated alert validates."""
        alert = create_draft_alert(
            threat_class=ThreatClass.DDOS,
            confidence=0.85,
            source="10.0.0.50",
            destination="10.0.0.1",
            supporting_evidence={"rate": 5000},
            detector="ddos_detector",
            model_version="1.0.0",
        )
        is_valid, errors = validate_draft_alert(alert.to_dict())
        assert is_valid is True
        assert errors == []

    def test_03_alert_id_exists(self) -> None:
        """TEST 3: alert_id exists and is non-empty string."""
        alert = _make_alert()
        assert alert.alert_id is not None
        assert isinstance(alert.alert_id, str)
        assert len(alert.alert_id) > 0

    def test_04_alert_id_is_valid_uuidv4(self) -> None:
        """TEST 4: alert_id is a valid UUIDv4."""
        alert = _make_alert()
        parsed = uuid.UUID(alert.alert_id, version=4)
        assert parsed.version == 4
        assert str(parsed) == alert.alert_id.lower()

    def test_05_timestamp_exists_and_is_utc_iso8601(self) -> None:
        """TEST 5: timestamp exists and is timezone-aware UTC ISO-8601."""
        # Auto-generated timestamp
        alert = create_draft_alert(
            threat_class=ThreatClass.DDOS,
            confidence=0.85,
            source="10.0.0.50",
            destination="10.0.0.1",
            supporting_evidence={"rate": 5000},
            detector="ddos_detector",
        )
        assert alert.timestamp is not None
        dt = datetime.fromisoformat(alert.timestamp.replace("Z", "+00:00"))
        assert dt.tzinfo is not None
        assert dt.utcoffset().total_seconds() == 0

    def test_06_schema_version_is_correct(self) -> None:
        """TEST 6: schema_version is automatically populated as 1.0.0."""
        alert = _make_alert()
        assert alert.schema_version == SCHEMA_VERSION
        assert alert.to_dict()["schema_version"] == "1.0.0"

    def test_07_missing_required_field_rejected(self) -> None:
        """TEST 7: Missing required field -> rejected."""
        base = _make_alert().to_dict()
        del base["destination"]
        is_valid, errors = validate_draft_alert(base)
        assert is_valid is False
        assert any("destination" in err for err in errors)

    def test_08_empty_supporting_evidence_rejected(self) -> None:
        """TEST 8: Empty supporting_evidence -> rejected."""
        base = _make_alert().to_dict()
        base["supporting_evidence"] = {}
        is_valid, errors = validate_draft_alert(base)
        assert is_valid is False
        assert any("supporting_evidence" in err for err in errors)

    def test_09_confidence_below_allowed_range_rejected(self) -> None:
        """TEST 9: Confidence below allowed range (< 0.0) -> rejected."""
        base = _make_alert().to_dict()
        base["confidence"] = -0.01
        is_valid, errors = validate_draft_alert(base)
        assert is_valid is False
        assert any("confidence" in err for err in errors)

    def test_10_confidence_above_allowed_range_rejected(self) -> None:
        """TEST 10: Confidence above allowed range (> 1.0) -> rejected."""
        base = _make_alert().to_dict()
        base["confidence"] = 1.01
        is_valid, errors = validate_draft_alert(base)
        assert is_valid is False
        assert any("confidence" in err for err in errors)

    def test_11_invalid_threat_class_rejected(self) -> None:
        """TEST 11: Invalid threat_class -> rejected."""
        base = _make_alert().to_dict()
        base["threat_class"] = "unauthorized_magic"
        is_valid, errors = validate_draft_alert(base)
        assert is_valid is False
        assert any("threat_class" in err for err in errors)

    def test_12_invalid_latency_class_rejected(self) -> None:
        """TEST 12: Invalid latency_class -> rejected."""
        base = _make_alert().to_dict()
        base["latency_class"] = "realtime_instant"
        is_valid, errors = validate_draft_alert(base)
        assert is_valid is False
        assert any("latency_class" in err for err in errors)

    def test_13_invalid_model_version_rejected(self) -> None:
        """TEST 13: Invalid model_version format/value -> rejected."""
        base = _make_alert().to_dict()
        base["model_version"] = 123  # Non-string
        del base["detector_version"]
        is_valid, errors = validate_draft_alert(base)
        assert is_valid is False
        assert any("model_version" in err for err in errors)

    def test_14_malformed_evidence_rejected(self) -> None:
        """TEST 14: Malformed evidence (e.g. non-object string) -> rejected."""
        base = _make_alert().to_dict()
        base["supporting_evidence"] = "string_is_not_an_object"
        is_valid, errors = validate_draft_alert(base)
        assert is_valid is False
        assert any("supporting_evidence" in err for err in errors)

    def test_15_valid_ddos_style_alert_accepted(self) -> None:
        """TEST 15: Valid DDoS-style alert -> accepted."""
        alert = create_draft_alert(
            threat_class=ThreatClass.DDOS,
            severity=Severity.CRITICAL,
            confidence=0.98,
            source="multiple",
            destination="192.168.56.10",
            supporting_evidence={
                "packet_rate": 25000.0,
                "byte_rate": 15000000.0,
                "source_entropy": 0.05,
                "z_score": 12.4,
            },
            detector="ddos_detector",
            model_version="1.0.0",
            subtype="syn_flood",
            latency_class=LatencyClass.EVENT_DRIVEN,
        )
        assert alert.threat_class == "ddos"
        is_valid, errors = validate_draft_alert(alert.to_dict())
        assert is_valid is True

    def test_16_valid_dga_style_alert_accepted(self) -> None:
        """TEST 16: Valid DGA-style alert -> accepted."""
        alert = create_draft_alert(
            threat_class=ThreatClass.DGA,
            severity=Severity.HIGH,
            confidence=0.88,
            source="192.168.56.102",
            destination="192.168.56.254",
            supporting_evidence={
                "domain": "vn0xg58vzlubb.lab.local",
                "shannon_entropy": 3.42,
                "digit_ratio": 0.23,
                "ngram_frequency_distance": 22.4,
                "model_probability": 0.88,
            },
            detector="dga_classifier",
            model_version="1.0.0",
            subtype="dga_dns",
            latency_class=LatencyClass.EVENT_DRIVEN,
        )
        assert alert.threat_class == "dga"
        is_valid, errors = validate_draft_alert(alert.to_dict())
        assert is_valid is True

    def test_17_valid_tls_style_alert_accepted(self) -> None:
        """TEST 17: Valid TLS-style alert -> accepted."""
        alert = create_draft_alert(
            threat_class=ThreatClass.TLS_ANOMALY,
            severity=Severity.HIGH,
            confidence=0.90,
            source="192.168.56.102",
            destination="198.51.100.80",
            supporting_evidence={
                "ja3": "a0e9f5d64349fb13191bc781f81f42e1",
                "ja3_match": True,
                "ja3_threat_name": "Cobalt Strike Malleable C2",
                "behavioral_score": 0.58,
                "mean_packet_size": 612.0,
                "byte_ratio": 5.4,
            },
            detector="tls_anomaly_detector",
            model_version="1.0.0",
            subtype="encrypted_malware",
            latency_class=LatencyClass.EVENT_DRIVEN,
        )
        assert alert.threat_class == "tls_anomaly"
        is_valid, errors = validate_draft_alert(alert.to_dict())
        assert is_valid is True

    def test_18_valid_exfiltration_style_alert_accepted(self) -> None:
        """TEST 18: Valid exfiltration-style alert -> accepted."""
        alert = create_draft_alert(
            threat_class=ThreatClass.EXFILTRATION,
            severity=Severity.CRITICAL,
            confidence=0.95,
            source="192.168.56.102",
            destination="203.0.113.195",
            supporting_evidence={
                "outbound_bytes": 500000,
                "inbound_bytes": 0,
                "byte_ratio": 500000.0,
                "baseline_deviation": 4.5,
                "threshold_ratio": 10.0,
                "volume_floor": 50000,
            },
            detector="exfiltration_detector",
            model_version="1.0.0",
            subtype="asymmetric_outbound_transfer",
            latency_class=LatencyClass.PERIODIC,
        )
        assert alert.threat_class == "exfiltration"
        is_valid, errors = validate_draft_alert(alert.to_dict())
        assert is_valid is True

    def test_19_valid_rita_style_alert_accepted(self) -> None:
        """TEST 19: Valid RITA-style alert -> accepted."""
        alert = create_draft_alert(
            threat_class=ThreatClass.BEACONING,
            severity=Severity.HIGH,
            confidence=0.82,
            source="192.168.56.102",
            destination="198.51.100.80",
            supporting_evidence={
                "rita_beacon_score": 0.82,
                "connection_count": 48,
                "interval_mean": 60.0,
                "rita_version": "5.1.2",
            },
            detector="rita_beacon_adapter",
            model_version="5.1.2",
            subtype="c2_beaconing",
            latency_class=LatencyClass.PERIODIC,
        )
        assert alert.threat_class == "beaconing"
        is_valid, errors = validate_draft_alert(alert.to_dict())
        assert is_valid is True

    def test_20_validation_failure_is_logged(self, caplog: pytest.LogCaptureFixture) -> None:
        """TEST 20: Validation failure is logged with detector and threat class."""
        caplog.clear()
        bad_alert = {
            "alert_id": "not-a-uuid",
            "timestamp": "bad-ts",
            "flow_id": "f1",
            "threat_class": "invalid_threat",
            "severity": "high",
            "confidence": 2.0,
            "source": "1.2.3.4",
            "destination": "5.6.7.8",
            "supporting_evidence": {},
            "detector": "mock_detector",
            "model_version": "1.0.0",
            "schema_version": "1.0.0",
        }
        with caplog.at_level(logging.ERROR):
            is_valid, errors = validate_draft_alert(bad_alert)

        assert is_valid is False
        assert len(errors) > 0
        assert "DRAFT alert validation failed" in caplog.text
        assert "mock_detector" in caplog.text


# ---------------------------------------------------------------------------
# Section 20-23: Additional Semantic, Fail-Closed & Architecture Tests
# ---------------------------------------------------------------------------

class TestFailClosedAndArchitecture:

    def test_21_fail_closed_raises_and_returns_nothing(self) -> None:
        """Section 20: Invalid alert raises AlertValidationError; nothing passed downstream."""
        with pytest.raises(AlertValidationError) as exc_info:
            create_draft_alert(
                threat_class="bogus_threat",
                confidence=1.5,
                source="1.2.3.4",
                destination="5.6.7.8",
                supporting_evidence={},
                detector="test_det",
            )
        assert "DRAFT alert validation failed" in str(exc_info.value)

    def test_22_uuid_uniqueness_and_v4(self) -> None:
        """Section 21: UUIDs are distinct and strictly version 4."""
        a1 = _make_alert()
        a2 = _make_alert()
        assert a1.alert_id != a2.alert_id

        u1 = uuid.UUID(a1.alert_id)
        u2 = uuid.UUID(a2.alert_id)
        assert u1.version == 4
        assert u2.version == 4

    def test_23_timestamp_utc_iso8601_parsing(self) -> None:
        """Section 22: Timestamp exists, is UTC, ISO-8601, and parses cleanly."""
        a = _make_alert(timestamp=None)
        dt = datetime.fromisoformat(a.timestamp)
        assert dt.tzinfo is not None
        assert dt.utcoffset().total_seconds() == 0

        # Naive timestamp should be rejected by validator
        bad = a.to_dict()
        bad["timestamp"] = "2026-09-19 12:00:00"  # No timezone
        valid, errors = validate_draft_alert(bad)
        assert valid is False
        assert any("naive datetime" in e for e in errors)

    def test_24_authoritative_schema_file_is_used(self) -> None:
        """Section 23: Validator directly loads docs/04_alert_schema.json."""
        assert SCHEMA_PATH.is_file()
        schema = load_alert_schema()
        assert schema.get("title") == "UnifiedDraftAlertSchema"
        assert "threat_class" in schema.get("properties", {})
        assert "confidence" in schema.get("properties", {})

    def test_25_nan_and_inf_confidence_rejected(self) -> None:
        """Section 11: NaN, Infinity, and booleans are rejected as confidence."""
        base = _make_alert().to_dict()

        for bad_conf in [float("nan"), float("inf"), float("-inf"), True, False]:
            test_dict = dict(base)
            test_dict["confidence"] = bad_conf
            valid, errors = validate_draft_alert(test_dict)
            assert valid is False, f"Expected failure for confidence={bad_conf}"
            assert any("confidence" in e for e in errors)

    def test_26_to_dict_preserves_optional_fields(self) -> None:
        """DraftAlert to_dict includes optional fields when set, excludes when None."""
        alert = _make_alert(subtype="syn_flood", latency_class=LatencyClass.EVENT_DRIVEN)
        d = alert.to_dict()
        assert "asset_criticality" not in d
        assert "correlated_alert_ids" not in d

    def test_27_anomalous_behavior_threat_class_accepted(self) -> None:
        """Phase 5: New threat class anomalous_behavior is accepted by factory and validator."""
        alert = create_draft_alert(
            threat_class=ThreatClass.ANOMALOUS_BEHAVIOR,
            confidence=0.82,
            source="192.168.56.102",
            destination="192.168.56.254",
            supporting_evidence={"raw_anomaly_score": 0.35, "normalized_confidence": 0.82},
            detector="ai_behavioral_anomaly",
            model_version="isolation-forest-v1",
        )
        is_valid, errors = validate_draft_alert(alert.to_dict())
        assert is_valid is True, f"Validation failed: {errors}"
        assert alert.threat_class == "anomalous_behavior"

    def test_28_all_existing_threat_classes_remain_valid(self) -> None:
        """Phase 5: All existing and new threat classes in ThreatClass remain valid."""
        for name in dir(ThreatClass):
            if name.startswith("_"):
                continue
            tc_value = getattr(ThreatClass, name)
            if not isinstance(tc_value, str):
                continue
            alert = create_draft_alert(
                threat_class=tc_value,
                confidence=0.5,
                source="10.0.0.1",
                destination="10.0.0.2",
                supporting_evidence={"check": True},
                detector="test_detector",
                model_version="1.0.0",
            )
            is_valid, errors = validate_draft_alert(alert.to_dict())
            assert is_valid is True, f"Threat class '{tc_value}' failed validation: {errors}"

    def test_29_invalid_threat_classes_rejected(self) -> None:
        """Phase 5: Random unsupported threat classes fail validation."""
        for invalid_tc in ["unsupported_class", "malware_trojan", "random_attack", "apt29"]:
            with pytest.raises(AlertValidationError) as exc_info:
                create_draft_alert(
                    threat_class=invalid_tc,
                    confidence=0.5,
                    source="10.0.0.1",
                    destination="10.0.0.2",
                    supporting_evidence={"check": True},
                    detector="test_detector",
                    model_version="1.0.0",
                )
            assert "threat_class" in str(exc_info.value).lower()

    def test_30_confidence_bounds_enforced(self) -> None:
        """Phase 5: Confidence values strictly outside [0.0, 1.0] are rejected."""
        for bad_conf in [-0.01, -1.0, 1.001, 2.5]:
            with pytest.raises(AlertValidationError) as exc_info:
                create_draft_alert(
                    threat_class=ThreatClass.ANOMALOUS_BEHAVIOR,
                    confidence=bad_conf,
                    source="10.0.0.1",
                    destination="10.0.0.2",
                    supporting_evidence={"score": bad_conf},
                    detector="ai_behavioral_anomaly",
                    model_version="isolation-forest-v1",
                )
            assert "confidence" in str(exc_info.value).lower()

