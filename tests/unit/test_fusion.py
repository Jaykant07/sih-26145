"""Unit tests for OT-aware Fusion Layer (Phase 21)."""

from datetime import datetime, timezone
import pytest

from alerts.constants import LatencyClass, Severity, ThreatClass
from alerts.draft import DraftAlert, create_draft_alert
from alerts.validator import validate_draft_alert
from fusion.correlator import correlate_alerts
from fusion.criticality import resolve_asset_criticality
from fusion.engine import FusionEngine, fuse_alerts
from fusion.severity import compute_fused_severity, get_base_severity, escalate_severity
from fusion.validator import validate_incoming_alert, validate_final_alert


# ---------------------------------------------------------------------------
# Test Helpers
# ---------------------------------------------------------------------------

def _make_draft(
    threat_class: str = ThreatClass.RECONNAISSANCE,
    source: str = "10.0.0.50",
    destination: str = "192.168.56.10",
    confidence: float = 0.85,
    timestamp: str = "2026-09-19T12:00:00+00:00",
    detector: str = "test_detector",
    model_version: str = "1.0.0",
    evidence: dict = None,
    **overrides,
) -> DraftAlert:
    """Helper to create a valid DraftAlert for testing."""
    ev = evidence if evidence is not None else {"metric": 42}
    kwargs = dict(
        threat_class=threat_class,
        confidence=confidence,
        source=source,
        destination=destination,
        supporting_evidence=ev,
        detector=detector,
        model_version=model_version,
        timestamp=timestamp,
        latency_class=LatencyClass.EVENT_DRIVEN,
    )
    kwargs.update(overrides)
    return create_draft_alert(**kwargs)


# ---------------------------------------------------------------------------
# Section 28 - 40 Required Tests
# ---------------------------------------------------------------------------

class TestOTAwareFusion:

    def test_01_single_alert_accepted_base_severity_no_correlation(self):
        """TEST 1: Single alert accepted, base severity assigned, no correlation."""
        # Reconnaissance has base severity 'low'; destination 192.168.56.102 is 'standard'
        alert = _make_draft(
            threat_class=ThreatClass.RECONNAISSANCE,
            source="10.0.0.50",
            destination="192.168.56.102",
            confidence=0.72,
        )
        fused = fuse_alerts([alert])
        assert len(fused) == 1
        res = fused[0]

        assert res["confidence"] == pytest.approx(0.72)
        assert res["severity"] == Severity.LOW
        assert "correlation_id" not in res or res["correlation_id"] is None
        assert "correlated_alert_ids" not in res or not res["correlated_alert_ids"]

        # Validated against schema
        is_valid, errors = validate_draft_alert(res)
        assert is_valid is True, f"Schema errors: {errors}"

    def test_02_two_different_threat_classes_correlate_and_escalate(self):
        """TEST 2: Two different threat classes from same source in window correlate and escalate."""
        # Source 10.0.0.50 (standard), dest 192.168.56.102 (standard)
        # Alert A: Reconnaissance (base low) -> escalated by correlation -> medium
        # Alert B: Beaconing (base medium) -> escalated by correlation -> high
        a1 = _make_draft(
            threat_class=ThreatClass.RECONNAISSANCE,
            source="10.0.0.50",
            destination="192.168.56.102",
            confidence=0.65,
            timestamp="2026-09-19T12:00:00+00:00",
        )
        a2 = _make_draft(
            threat_class=ThreatClass.BEACONING,
            source="10.0.0.50",
            destination="192.168.56.102",
            confidence=0.88,
            timestamp="2026-09-19T12:02:00+00:00",  # +2 min
        )
        fused = fuse_alerts([a1, a2])
        assert len(fused) == 2

        # Same correlation ID
        assert "correlation_id" in fused[0]
        assert fused[0]["correlation_id"] is not None
        assert fused[0]["correlation_id"] == fused[1]["correlation_id"]

        # Cross-referenced correlated alert IDs
        assert fused[1]["alert_id"] in fused[0]["correlated_alert_ids"]
        assert fused[0]["alert_id"] in fused[1]["correlated_alert_ids"]

        # Confidence strictly preserved
        assert fused[0]["confidence"] == pytest.approx(0.65)
        assert fused[1]["confidence"] == pytest.approx(0.88)

        # Severity escalation verified
        assert fused[0]["severity"] == Severity.MEDIUM  # low -> medium
        assert fused[1]["severity"] == Severity.HIGH    # medium -> high

    def test_03_three_stage_scenario_scan_beacon_exfil(self):
        """TEST 3: Three-stage attack scenario (scan -> beacon -> exfil) from same source."""
        # Target: standard asset 192.168.56.102
        # Scan (low -> medium due to correlation)
        # Beacon (medium -> high due to correlation)
        # Exfiltration (high -> critical due to correlation)
        a1 = _make_draft(
            threat_class=ThreatClass.RECONNAISSANCE,
            source="192.168.56.200",
            destination="192.168.56.102",
            confidence=0.70,
            timestamp="2026-09-19T12:00:00+00:00",
        )
        a2 = _make_draft(
            threat_class=ThreatClass.BEACONING,
            source="192.168.56.200",
            destination="192.168.56.102",
            confidence=0.80,
            timestamp="2026-09-19T12:01:30+00:00",
        )
        a3 = _make_draft(
            threat_class=ThreatClass.EXFILTRATION,
            source="192.168.56.200",
            destination="192.168.56.102",
            confidence=0.95,
            timestamp="2026-09-19T12:03:00+00:00",
        )

        fused = fuse_alerts([a1, a2, a3])
        assert len(fused) == 3

        # Single correlation group shared across all three
        c_id = fused[0]["correlation_id"]
        assert c_id is not None
        assert fused[1]["correlation_id"] == c_id
        assert fused[2]["correlation_id"] == c_id

        # Confidences unchanged
        assert fused[0]["confidence"] == pytest.approx(0.70)
        assert fused[1]["confidence"] == pytest.approx(0.80)
        assert fused[2]["confidence"] == pytest.approx(0.95)

        # Severities escalated
        assert fused[0]["severity"] == Severity.MEDIUM    # low -> medium
        assert fused[1]["severity"] == Severity.HIGH      # medium -> high
        assert fused[2]["severity"] == Severity.CRITICAL  # high -> critical

    def test_04_same_threat_class_does_not_correlate(self):
        """TEST 4: Same threat class (e.g. DGA + DGA) does not trigger multi-threat correlation."""
        a1 = _make_draft(
            threat_class=ThreatClass.DGA,
            source="10.0.0.50",
            destination="192.168.56.102",
            confidence=0.85,
            timestamp="2026-09-19T12:00:00+00:00",
        )
        a2 = _make_draft(
            threat_class=ThreatClass.DGA,
            source="10.0.0.50",
            destination="192.168.56.102",
            confidence=0.90,
            timestamp="2026-09-19T12:01:00+00:00",
        )
        fused = fuse_alerts([a1, a2])
        assert len(fused) == 2

        # No correlation_id assigned
        assert fused[0].get("correlation_id") is None
        assert fused[1].get("correlation_id") is None

        # Base severities unchanged (DGA = medium)
        assert fused[0]["severity"] == Severity.MEDIUM
        assert fused[1]["severity"] == Severity.MEDIUM

    def test_05_outside_correlation_window_does_not_correlate(self):
        """TEST 5: Alerts outside the 5-minute correlation window do not correlate."""
        a1 = _make_draft(
            threat_class=ThreatClass.RECONNAISSANCE,
            source="10.0.0.50",
            destination="192.168.56.102",
            confidence=0.75,
            timestamp="2026-09-19T12:00:00+00:00",
        )
        a2 = _make_draft(
            threat_class=ThreatClass.BEACONING,
            source="10.0.0.50",
            destination="192.168.56.102",
            confidence=0.85,
            timestamp="2026-09-19T12:06:00+00:00",  # +6 minutes (> 300s)
        )
        fused = fuse_alerts([a1, a2])
        assert len(fused) == 2

        assert fused[0].get("correlation_id") is None
        assert fused[1].get("correlation_id") is None
        assert fused[0]["severity"] == Severity.LOW     # base reconnaissance
        assert fused[1]["severity"] == Severity.MEDIUM  # base beaconing

    def test_06_different_sources_do_not_correlate(self):
        """TEST 6: Alerts from different sources do not correlate even if simultaneous."""
        a1 = _make_draft(
            threat_class=ThreatClass.RECONNAISSANCE,
            source="10.0.0.50",
            destination="192.168.56.102",
            confidence=0.75,
            timestamp="2026-09-19T12:00:00+00:00",
        )
        a2 = _make_draft(
            threat_class=ThreatClass.BEACONING,
            source="10.0.0.60",  # Different source
            destination="192.168.56.102",
            confidence=0.85,
            timestamp="2026-09-19T12:01:00+00:00",
        )
        fused = fuse_alerts([a1, a2])
        assert len(fused) == 2

        assert fused[0].get("correlation_id") is None
        assert fused[1].get("correlation_id") is None

    def test_07_critical_asset_escalates_severity_once(self):
        """TEST 7: Asset marked critical escalates severity by one level; confidence untouched."""
        # Target 192.168.56.10 is PLC-01 (critical) in assets.yaml
        # Reconnaissance base = low -> critical asset -> medium
        alert = _make_draft(
            threat_class=ThreatClass.RECONNAISSANCE,
            source="10.0.0.50",
            destination="192.168.56.10",
            confidence=0.68,
        )
        fused = fuse_alerts([alert])
        assert len(fused) == 1
        res = fused[0]

        assert res["asset_criticality"] == "critical"
        assert res["severity"] == Severity.MEDIUM  # low -> medium
        assert res["confidence"] == pytest.approx(0.68)  # UNCHANGED

    def test_08_standard_asset_does_not_escalate(self):
        """TEST 8: Asset marked standard does not escalate severity."""
        # Target 192.168.56.102 is Lab Testing Workstation (standard)
        # Source 10.0.0.50 is standard
        # Reconnaissance base = low -> stays low
        alert = _make_draft(
            threat_class=ThreatClass.RECONNAISSANCE,
            source="10.0.0.50",
            destination="192.168.56.102",
            confidence=0.70,
        )
        fused = fuse_alerts([alert])
        assert len(fused) == 1
        res = fused[0]

        assert res["asset_criticality"] == "standard"
        assert res["severity"] == Severity.LOW
        assert res["confidence"] == pytest.approx(0.70)

    def test_09_unknown_asset_handled_safely(self):
        """TEST 9: IP absent from assets.yaml is classified as unknown; no rejection."""
        alert = _make_draft(
            threat_class=ThreatClass.RECONNAISSANCE,
            source="203.0.113.88",   # Unmapped external IP
            destination="198.51.100.99", # Unmapped external IP
            confidence=0.77,
        )
        fused = fuse_alerts([alert])
        assert len(fused) == 1
        res = fused[0]

        assert res["asset_criticality"] == "unknown"
        assert res["severity"] == Severity.LOW
        assert res["confidence"] == pytest.approx(0.77)

    def test_10_invalid_input_alert_rejected_fail_closed(self):
        """TEST 10: Malformed/invalid alert is rejected by fusion validator and never returned."""
        bad_alert = {
            "alert_id": "not-a-uuid",
            "threat_class": "unrecognized_threat",
            "confidence": 1.5,
            "source": "1.2.3.4",
            "destination": "5.6.7.8",
            "supporting_evidence": {},
        }
        good_alert = _make_draft(
            threat_class=ThreatClass.BEACONING,
            source="10.0.0.50",
            destination="192.168.56.102",
            confidence=0.85,
        )

        fused = fuse_alerts([bad_alert, good_alert])
        assert len(fused) == 1
        assert fused[0]["alert_id"] == good_alert.alert_id

    def test_11_confidence_preservation_exact(self):
        """TEST 11: Confidence values before and after fusion are bit-for-bit identical."""
        a1 = _make_draft(
            threat_class=ThreatClass.RECONNAISSANCE,
            confidence=0.42,
            source="10.0.0.50",
            destination="192.168.56.10",  # critical asset
        )
        a2 = _make_draft(
            threat_class=ThreatClass.BEACONING,
            confidence=0.91,
            source="10.0.0.50",
            destination="192.168.56.10",
            timestamp="2026-09-19T12:01:00+00:00",
        )

        fused = fuse_alerts([a1, a2])
        assert len(fused) == 2

        # In this scenario, both criticality (+1) and correlation (+1) escalate:
        # Reconnaissance: low -> medium (crit) -> high (corr)
        # Beaconing: medium -> high (crit) -> critical (corr)
        assert fused[0]["severity"] == Severity.HIGH
        assert fused[1]["severity"] == Severity.CRITICAL

        # BUT CONFIDENCE MUST REMAIN UNTOUCHED
        assert fused[0]["confidence"] == 0.42
        assert fused[1]["confidence"] == 0.91

    def test_12_final_schema_validation_against_official_schema(self):
        """TEST 12: Every final alert validates 100% against docs/04_alert_schema.json."""
        a1 = _make_draft(
            threat_class=ThreatClass.RECONNAISSANCE,
            source="10.0.0.50",
            destination="192.168.56.10",
        )
        a2 = _make_draft(
            threat_class=ThreatClass.BEACONING,
            source="10.0.0.50",
            destination="192.168.56.10",
            timestamp="2026-09-19T12:01:00+00:00",
        )
        fused = fuse_alerts([a1, a2])
        for alert in fused:
            is_valid, errors = validate_draft_alert(alert)
            assert is_valid is True, f"Final alert failed schema: {errors}"
            is_final_valid, f_errors = validate_final_alert(alert)
            assert is_final_valid is True, f"Final validator error: {f_errors}"

    def test_13_mixed_track_a_and_track_b_correlation(self):
        """Section 40: Track A alert (RITA beaconing) + Track B alert (custom exfil) correlate identically."""
        # Track A: RITA Beaconing (ThreatClass.BEACONING)
        track_a = _make_draft(
            threat_class=ThreatClass.BEACONING,
            source="192.168.56.102",
            destination="198.51.100.80",
            confidence=0.82,
            detector="rita_beacon_adapter",
            model_version="5.1.2",
            evidence={"rita_beacon_score": 0.82, "connection_count": 48},
            timestamp="2026-09-19T12:00:00+00:00",
        )
        # Track B: Custom Data Exfiltration (ThreatClass.EXFILTRATION)
        track_b = _make_draft(
            threat_class=ThreatClass.EXFILTRATION,
            source="192.168.56.102",
            destination="198.51.100.80",
            confidence=0.95,
            detector="exfiltration_detector",
            model_version="1.0.0",
            evidence={"byte_ratio": 500.0, "outbound_bytes": 100000},
            timestamp="2026-09-19T12:02:00+00:00",
        )

        fused = fuse_alerts([track_a, track_b])
        assert len(fused) == 2

        # Both share the same correlation_id
        assert fused[0]["correlation_id"] == fused[1]["correlation_id"]
        assert fused[0]["correlation_id"] is not None

        # Track A beaconing: base medium -> correlation -> high
        # Track B exfiltration: base high -> correlation -> critical
        assert fused[0]["severity"] == Severity.HIGH
        assert fused[1]["severity"] == Severity.CRITICAL

        # Both confidences unchanged
        assert fused[0]["confidence"] == pytest.approx(0.82)
        assert fused[1]["confidence"] == pytest.approx(0.95)

    def test_14_configurable_correlation_window(self):
        """Section 42: Correlation window is configurable and not hardcoded."""
        a1 = _make_draft(
            threat_class=ThreatClass.RECONNAISSANCE,
            source="10.0.0.50",
            destination="192.168.56.102",
            timestamp="2026-09-19T12:00:00+00:00",
        )
        a2 = _make_draft(
            threat_class=ThreatClass.BEACONING,
            source="10.0.0.50",
            destination="192.168.56.102",
            timestamp="2026-09-19T12:08:00+00:00",  # +8 minutes (480s)
        )

        # Default window (300s): should NOT correlate
        default_fused = fuse_alerts([a1, a2], correlation_window=300.0)
        assert default_fused[0].get("correlation_id") is None
        assert default_fused[1].get("correlation_id") is None

        # Extended window (600s / 10 minutes): SHOULD correlate
        extended_fused = fuse_alerts([a1, a2], correlation_window=600.0)
        assert extended_fused[0]["correlation_id"] == extended_fused[1]["correlation_id"]
        assert extended_fused[0]["correlation_id"] is not None
