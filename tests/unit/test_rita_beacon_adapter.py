"""
Unit tests for RITA C2 Beaconing Adapter (Track A — PS-26145).

Verifies native RITA v5.1.2 CSV parsing, beacon finding normalization,
threshold filtering, deduplication and material-change handling,
strobe exclusion, error resilience, and DRAFT alert schema conformance.
"""

import json
from pathlib import Path
import pytest

from alerts.constants import LatencyClass, Severity, ThreatClass
from alerts.validator import validate_draft_alert
from detectors.beaconing.rita_adapter import (
    DEFAULT_SCORE_THRESHOLD,
    MATERIAL_CHANGE_SCORE_DELTA,
    RitaBeaconAdapter,
)

# Real native RITA v5.1.2 CSV header
RITA_CSV_HEADER = (
    "Severity,Source IP,Destination IP,FQDN,Beacon Score,Strobe,Total Duration,"
    "Long Connection Score,Subdomains,C2 Over DNS Score,Threat Intel,Prevalence,"
    "First Seen,Missing Host Header,Connection Count,Total Bytes,Port:Proto:Service,Modifiers"
)

# Real native RITA finding from ps26145_beacon_fixed (0% jitter, score 0.977)
RITA_SAMPLE_FIXED_ROW = (
    'High,172.16.0.100,203.0.113.50,,0.977,false,1.784452,0,0,0,false,0.023809523809523808,'
    '59 minutes ago,false,60,46737,"8080:tcp:http",""'
)

# Real native RITA finding from ps26145_beacon_jitter (20% jitter, score 0.916)
RITA_SAMPLE_JITTER_ROW = (
    'High,172.16.0.100,203.0.113.50,,0.916,false,1.813971,0,0,0,false,0.023809523809523808,'
    '1 hour ago,false,60,49418,"8080:tcp:http",""'
)

# Second distinct beacon finding for multi-finding tests
RITA_SAMPLE_BEACON_ROW_B = (
    'Critical,10.0.1.50,198.51.100.99,,0.950,false,3.5,0,0,0,false,0.01,'
    '30 minutes ago,false,120,95000,"443:tcp:ssl",""'
)

# Real background web traffic from ps26145_beacon_fixed (score 0.603, below 0.75 threshold)
RITA_SAMPLE_BACKGROUND_ROW = (
    'Low,172.16.0.53,93.184.216.34,,0.603,false,20.90993,0,0,0,false,0.9285714285714286,'
    '57 minutes ago,false,7,43381,"443:tcp:ssl,80:tcp:http",""'
)

# Real strobe finding (Strobe == true, must be excluded from beacon alerts)
RITA_SAMPLE_STROBE_ROW = (
    'High,172.16.0.99,198.51.100.55,,0.0,true,3600.0,0,0,0,false,0.05,'
    '1 hour ago,false,90000,1048576,"80:tcp:http","strobe_impact:high"'
)


@pytest.fixture
def adapter() -> RitaBeaconAdapter:
    return RitaBeaconAdapter(score_threshold=DEFAULT_SCORE_THRESHOLD)


class TestRitaBeaconAdapterParsing:
    """Tests 1, 2, 3: Parsing valid, multiple, and malformed RITA CSV outputs."""

    def test_01_parse_valid_rita_beacon_result(self, adapter: RitaBeaconAdapter):
        """TEST 1: Parse valid RITA beacon result."""
        csv_payload = f"Viewing database: ps26145_beacon_fixed\n{RITA_CSV_HEADER}\n{RITA_SAMPLE_FIXED_ROW}\n"
        records = adapter.parse_rita_beacon_output(csv_payload)
        assert len(records) == 1
        r = records[0]
        assert r["Severity"] == "High"
        assert r["Source IP"] == "172.16.0.100"
        assert r["Destination IP"] == "203.0.113.50"
        assert r["Beacon Score"] == "0.977"
        assert r["Connection Count"] == "60"
        assert r["Port:Proto:Service"] == "8080:tcp:http"

        finding = adapter.normalize_beacon_finding(r)
        assert finding is not None
        assert finding["source"] == "172.16.0.100"
        assert finding["destination"] == "203.0.113.50"
        assert finding["destination_port"] == 8080
        assert finding["protocol"] == "tcp"
        assert finding["service"] == "http"
        assert finding["beacon_score"] == 0.977
        assert finding["connection_count"] == 60

    def test_02_parse_multiple_beacon_findings(self, adapter: RitaBeaconAdapter):
        """TEST 2: Parse multiple beacon findings."""
        csv_payload = (
            f"{RITA_CSV_HEADER}\n"
            f"{RITA_SAMPLE_FIXED_ROW}\n"
            f"{RITA_SAMPLE_BEACON_ROW_B}\n"
            f"{RITA_SAMPLE_BACKGROUND_ROW}\n"
        )
        records = adapter.parse_rita_beacon_output(csv_payload)
        assert len(records) == 3
        findings = [adapter.normalize_beacon_finding(r) for r in records]
        assert all(f is not None for f in findings)
        sources = [f["source"] for f in findings]
        assert "172.16.0.100" in sources
        assert "10.0.1.50" in sources
        assert "172.16.0.53" in sources

    def test_03_ignore_malformed_rows_safely(self, adapter: RitaBeaconAdapter):
        """TEST 3: Ignore malformed rows/records safely."""
        # Row with missing destination, non-numeric score, empty row
        malformed_csv = (
            f"{RITA_CSV_HEADER}\n"
            f",,,,\n"  # Completely blank row
            f'High,10.0.0.1,,,not_a_number,false,0,0,0,0,false,0,now,false,1,100,"80:tcp:http",""\n'
            f"{RITA_SAMPLE_FIXED_ROW}\n"
        )
        records = adapter.parse_rita_beacon_output(malformed_csv)
        assert len(records) >= 1
        valid_findings = []
        for r in records:
            f = adapter.normalize_beacon_finding(r)
            if f is not None:
                valid_findings.append(f)
        # Only the valid fixed row should normalize cleanly
        assert len(valid_findings) == 1
        assert valid_findings[0]["source"] == "172.16.0.100"


class TestRitaBeaconThresholdAndFiltering:
    """Tests 4, 5: Threshold filtering logic and strobe exclusion."""

    def test_04_score_below_threshold_no_alert(self, adapter: RitaBeaconAdapter):
        """TEST 4: Score below threshold -> no alert."""
        adapter.reset_state()
        # Background web traffic has score 0.603 < threshold 0.75
        csv_payload = f"{RITA_CSV_HEADER}\n{RITA_SAMPLE_BACKGROUND_ROW}\n"
        alerts = adapter.process_csv_text(csv_payload)
        assert len(alerts) == 0

    def test_05_score_above_threshold_produces_alert(self, adapter: RitaBeaconAdapter):
        """TEST 5: Score above threshold -> alert."""
        adapter.reset_state()
        # Fixed beacon has score 0.977 >= threshold 0.75
        csv_payload = f"{RITA_CSV_HEADER}\n{RITA_SAMPLE_FIXED_ROW}\n"
        alerts = adapter.process_csv_text(csv_payload)
        assert len(alerts) == 1
        assert alerts[0].source == "172.16.0.100"
        assert alerts[0].destination == "203.0.113.50"
        assert alerts[0].confidence == 0.977

    def test_strobe_finding_excluded(self, adapter: RitaBeaconAdapter):
        """Verify that Strobe connections are excluded from beacon detection."""
        adapter.reset_state()
        csv_payload = f"{RITA_CSV_HEADER}\n{RITA_SAMPLE_STROBE_ROW}\n"
        alerts = adapter.process_csv_text(csv_payload)
        assert len(alerts) == 0


class TestRitaBeaconAlertContract:
    """Tests 6, 7, 8: Schema compliance, threat_class, latency_class, and evidence."""

    def test_06_correct_threat_class(self, adapter: RitaBeaconAdapter):
        """TEST 6: Correct threat_class (must be 'beaconing')."""
        adapter.reset_state()
        csv_payload = f"{RITA_CSV_HEADER}\n{RITA_SAMPLE_FIXED_ROW}\n"
        alerts = adapter.process_csv_text(csv_payload)
        assert len(alerts) == 1
        alert_dict = alerts[0].to_dict()
        assert alert_dict["threat_class"] == ThreatClass.BEACONING
        assert alert_dict["threat_class"] == "beaconing"
        assert alert_dict["subtype"] == "c2_beaconing"

    def test_07_correct_latency_class(self, adapter: RitaBeaconAdapter):
        """TEST 7: Correct latency_class (must be 'periodic')."""
        adapter.reset_state()
        csv_payload = f"{RITA_CSV_HEADER}\n{RITA_SAMPLE_FIXED_ROW}\n"
        alerts = adapter.process_csv_text(csv_payload)
        assert len(alerts) == 1
        alert_dict = alerts[0].to_dict()
        assert alert_dict["latency_class"] == LatencyClass.PERIODIC
        assert alert_dict["latency_class"] == "periodic"

    def test_08_evidence_contains_actual_rita_score(self, adapter: RitaBeaconAdapter):
        """TEST 8: Evidence contains actual RITA score and native fields."""
        adapter.reset_state()
        csv_payload = f"{RITA_CSV_HEADER}\n{RITA_SAMPLE_FIXED_ROW}\n"
        alerts = adapter.process_csv_text(csv_payload)
        assert len(alerts) == 1
        evidence = alerts[0].supporting_evidence
        assert evidence["finding_type"] == "c2_beaconing"
        assert evidence["rita_beacon_score"] == 0.977
        assert evidence["connection_count"] == 60
        assert evidence["destination_port"] == 8080
        assert evidence["protocol"] == "tcp"
        assert evidence["service"] == "http"
        assert evidence["average_interval"] == "not reported in native rita view"
        assert evidence["blacklist_status"] == "disabled"
        assert evidence["threat_intel_status"] == "disabled (no external reputation queried)"
        assert "heuristic mapping" in evidence["confidence_mapping_rationale"]
        assert "deduplication_fingerprint" in evidence

    def test_alert_validates_against_schema(self, adapter: RitaBeaconAdapter):
        """Verify emitted alert passes validate_draft_alert and required JSON Schema fields."""
        adapter.reset_state()
        csv_payload = f"{RITA_CSV_HEADER}\n{RITA_SAMPLE_FIXED_ROW}\n"
        alerts = adapter.process_csv_text(csv_payload)
        assert len(alerts) == 1
        alert_dict = alerts[0].to_dict()
        is_valid, errors = validate_draft_alert(alert_dict)
        assert is_valid, f"Validation errors: {errors}"
        assert alert_dict["model_version"] == "5.1.2"
        assert alert_dict["detector"] == "rita_beacon_adapter"


class TestRitaBeaconDeduplicationAndState:
    """Tests 9, 10, 11, 12: Deduplication lifecycle and material change detection."""

    def test_09_first_cycle_finding_emits_alert(self, adapter: RitaBeaconAdapter):
        """TEST 9: First cycle finding -> alert."""
        adapter.reset_state()
        csv_payload = f"{RITA_CSV_HEADER}\n{RITA_SAMPLE_FIXED_ROW}\n"
        alerts = adapter.process_csv_text(csv_payload)
        assert len(alerts) == 1
        assert alerts[0].supporting_evidence["material_change_status"] == "new_finding"

    def test_10_same_finding_in_second_cycle_no_duplicate_alert(self, adapter: RitaBeaconAdapter):
        """TEST 10: Same finding in second cycle -> no duplicate alert."""
        adapter.reset_state()
        csv_payload = f"{RITA_CSV_HEADER}\n{RITA_SAMPLE_FIXED_ROW}\n"
        # Cycle 1
        alerts_c1 = adapter.process_csv_text(csv_payload)
        assert len(alerts_c1) == 1

        # Cycle 2: identical finding re-queried by rolling import
        alerts_c2 = adapter.process_csv_text(csv_payload)
        assert len(alerts_c2) == 0, "Duplicate finding must be suppressed"

    def test_11_cycle_lifecycle_a_then_a_plus_b(self, adapter: RitaBeaconAdapter):
        """
        TEST 11:
          Cycle 1: A
          Cycle 2: A + B
          Expected: Only B generates a new alert.
        """
        adapter.reset_state()
        csv_c1 = f"{RITA_CSV_HEADER}\n{RITA_SAMPLE_FIXED_ROW}\n"
        alerts_c1 = adapter.process_csv_text(csv_c1)
        assert len(alerts_c1) == 1
        assert alerts_c1[0].source == "172.16.0.100"

        # Cycle 2 contains finding A and new finding B
        csv_c2 = f"{RITA_CSV_HEADER}\n{RITA_SAMPLE_FIXED_ROW}\n{RITA_SAMPLE_BEACON_ROW_B}\n"
        alerts_c2 = adapter.process_csv_text(csv_c2)
        assert len(alerts_c2) == 1, "Only new finding B should emit alert"
        assert alerts_c2[0].source == "10.0.1.50"
        assert alerts_c2[0].supporting_evidence["material_change_status"] == "new_finding"

    def test_12_materially_changed_existing_finding_emits_alert(self, adapter: RitaBeaconAdapter):
        """
        TEST 12: Materially changed existing finding behaves according to documented policy:
          - Cycle 1: finding with score 0.76 (Medium severity) -> alert
          - Cycle 2: same finding escalated to score 0.95 (High severity) -> alert
          - Cycle 3: same finding with score 0.96 (score delta < 0.15, same severity) -> suppressed
        """
        adapter.reset_state()
        # Row A in Cycle 1: Moderate beacon score 0.76, Medium severity
        row_c1 = (
            'Medium,192.168.1.50,198.51.100.77,,0.760,false,1.0,0,0,0,false,0.1,'
            '10 minutes ago,false,30,10000,"8080:tcp:http",""'
        )
        csv_c1 = f"{RITA_CSV_HEADER}\n{row_c1}\n"
        alerts_c1 = adapter.process_csv_text(csv_c1)
        assert len(alerts_c1) == 1
        assert alerts_c1[0].severity == "medium"
        assert alerts_c1[0].supporting_evidence["material_change_status"] == "new_finding"

        # Row A in Cycle 2: Score escalates to 0.95 (delta = +0.19 >= 0.15) and High severity
        row_c2 = (
            'High,192.168.1.50,198.51.100.77,,0.950,false,2.0,0,0,0,false,0.1,'
            '20 minutes ago,false,60,20000,"8080:tcp:http",""'
        )
        csv_c2 = f"{RITA_CSV_HEADER}\n{row_c2}\n"
        alerts_c2 = adapter.process_csv_text(csv_c2)
        assert len(alerts_c2) == 1
        assert alerts_c2[0].severity == "high"
        assert alerts_c2[0].supporting_evidence["material_change_status"] == "materially_changed"
        assert "score increased" in alerts_c2[0].supporting_evidence["material_change_reason"]

        # Row A in Cycle 3: Score 0.96 (delta = +0.01 < 0.15, same severity High) -> suppressed
        row_c3 = (
            'High,192.168.1.50,198.51.100.77,,0.960,false,3.0,0,0,0,false,0.1,'
            '30 minutes ago,false,90,30000,"8080:tcp:http",""'
        )
        csv_c3 = f"{RITA_CSV_HEADER}\n{row_c3}\n"
        alerts_c3 = adapter.process_csv_text(csv_c3)
        assert len(alerts_c3) == 0, "Non-material change must be suppressed"


class TestRitaBeaconErrorHandling:
    """Tests 13, 14: Empty RITA result and malformed output handling."""

    def test_13_empty_rita_result_produces_zero_alerts(self, adapter: RitaBeaconAdapter):
        """TEST 13: Empty RITA result -> zero alerts."""
        adapter.reset_state()
        assert adapter.process_csv_text("") == []
        assert adapter.process_csv_text("   \n\n  ") == []
        header_only = f"Viewing database: empty_db\n{RITA_CSV_HEADER}\n"
        assert adapter.process_csv_text(header_only) == []

    def test_14_malformed_rita_output_handled_safely(self, adapter: RitaBeaconAdapter):
        """TEST 14: Malformed RITA output -> controlled error, no fabricated alerts."""
        adapter.reset_state()
        garbage = (
            "FATAL: Database connection lost\n"
            "Traceback (most recent call last):\n"
            "Segmentation fault (core dumped)\n"
        )
        records = adapter.parse_rita_beacon_output(garbage)
        assert records == []
        alerts = adapter.process_csv_text(garbage)
        assert alerts == []
