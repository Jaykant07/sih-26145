"""
Unit tests for RITA DNS Tunnelling Adapter (Track A — PS-26145).

Verifies native RITA v5.1.2 CSV parsing, C2 Over DNS finding extraction,
deterministic deduplication state, non-tunnel filtering, error handling,
and DRAFT alert schema conformance.
"""

import pytest

from alerts.constants import LatencyClass, Severity, ThreatClass
from alerts.validator import validate_draft_alert
from detectors.dns.rita_tunnel_adapter import RitaTunnelAdapter

# Real native RITA v5.1.2 CSV header
RITA_CSV_HEADER = (
    "Severity,Source IP,Destination IP,FQDN,Beacon Score,Strobe,Total Duration,"
    "Long Connection Score,Subdomains,C2 Over DNS Score,Threat Intel,Prevalence,"
    "First Seen,Missing Host Header,Connection Count,Total Bytes,Port:Proto:Service,Modifiers"
)

# Real native RITA finding with C2 Over DNS detection
RITA_SAMPLE_TUNNEL_ROW = (
    'High,10.55.100.111,88.221.81.192,dnsc.r-1x.com,0.0,false,0,0,512,0.85,false,0.01,'
    '3 days ago,false,512,65536,"53:udp:dns","c2_over_dns_direct_conn:0.15"'
)

# Second unique finding for deduplication testing
RITA_SAMPLE_TUNNEL_ROW_2 = (
    'Critical,10.55.100.222,88.221.81.193,tunnel.evil.org,0.0,false,0,0,840,0.92,false,0.005,'
    '1 day ago,false,840,1048576,"53:udp:dns",""'
)

# Pure beacon finding (C2 Over DNS Score is 0) — must be ignored as non-tunnel
RITA_SAMPLE_BEACON_ROW = (
    'Critical,172.16.0.100,203.0.113.50,beacon.target.com,0.977,false,3600,0.8,0,0,false,0.05,'
    '1 hour ago,false,60,18896,"8080:tcp:http",""'
)


@pytest.fixture
def adapter() -> RitaTunnelAdapter:
    return RitaTunnelAdapter()


class TestRitaTunnelAdapterParsing:
    def test_parse_real_native_rita_csv(self, adapter: RitaTunnelAdapter):
        csv_payload = f"Viewing database: test_db\n{RITA_CSV_HEADER}\n{RITA_SAMPLE_TUNNEL_ROW}\n"
        records = adapter.parse_csv_text(csv_payload)
        assert len(records) == 1
        r = records[0]
        assert r["Severity"] == "High"
        assert r["Source IP"] == "10.55.100.111"
        assert r["Destination IP"] == "88.221.81.192"
        assert r["FQDN"] == "dnsc.r-1x.com"
        assert r["C2 Over DNS Score"] == "0.85"
        assert r["Subdomains"] == "512"

    def test_correct_source_and_domain_extraction(self, adapter: RitaTunnelAdapter):
        csv_payload = f"{RITA_CSV_HEADER}\n{RITA_SAMPLE_TUNNEL_ROW}\n"
        records = adapter.parse_csv_text(csv_payload)
        record = records[0]
        alert = adapter.create_alert(record)
        assert alert is not None
        assert alert.source == "10.55.100.111"
        assert alert.destination == "88.221.81.192"
        assert alert.supporting_evidence["domain"] == "dnsc.r-1x.com"
        assert alert.supporting_evidence["subdomains_count"] == 512
        assert alert.supporting_evidence["c2_over_dns_score"] == 0.85

    def test_non_tunnel_finding_ignored(self, adapter: RitaTunnelAdapter):
        # A row with C2 Over DNS Score == 0 must not be treated as a tunnel finding
        csv_payload = f"{RITA_CSV_HEADER}\n{RITA_SAMPLE_BEACON_ROW}\n"
        records = adapter.parse_csv_text(csv_payload)
        assert len(records) == 1
        assert adapter.is_tunnel_finding(records[0]) is False
        alert = adapter.create_alert(records[0])
        assert alert is None

        # When processed through adapter, 0 alerts should be emitted
        alerts = adapter.process_csv_text(csv_payload)
        assert len(alerts) == 0

    def test_missing_optional_fields_handled_safely(self, adapter: RitaTunnelAdapter):
        # Row with missing/empty optional columns
        partial_row = {
            "Source IP": "192.168.1.10",
            "Destination IP": "8.8.8.8",
            "FQDN": "tunnel.example.com",
            "C2 Over DNS Score": "0.75",
        }
        assert adapter.is_tunnel_finding(partial_row) is True
        alert = adapter.create_alert(partial_row)
        assert alert is not None
        assert alert.source == "192.168.1.10"
        assert alert.destination == "8.8.8.8"
        assert alert.confidence == 0.75
        assert alert.supporting_evidence["domain"] == "tunnel.example.com"
        assert alert.supporting_evidence["subdomains_count"] == 0

    def test_malformed_output_handled_safely(self, adapter: RitaTunnelAdapter):
        # Empty string
        assert adapter.parse_csv_text("") == []
        assert adapter.process_csv_text("") == []

        # Arbitrary junk text without CSV header
        junk = "Something went completely wrong in container\nSegmentation fault\n"
        assert adapter.parse_csv_text(junk) == []
        assert adapter.process_csv_text(junk) == []

        # Non-numeric C2 Over DNS Score
        bad_score_row = {
            "Source IP": "10.0.0.1",
            "FQDN": "bad.com",
            "C2 Over DNS Score": "not-a-number",
        }
        assert adapter.is_tunnel_finding(bad_score_row) is False
        assert adapter.create_alert(bad_score_row) is None


class TestRitaTunnelDeduplication:
    def test_new_finding_deduplication_lifecycle(self, adapter: RitaTunnelAdapter):
        """
        Controlled 3-cycle deduplication lifecycle test:
          Cycle 1: Finding A -> 1 new alert
          Cycle 2: Same Finding A -> 0 new alerts
          Cycle 3: Finding A + New Finding B -> 1 new alert (only for B)
        """
        adapter.reset_state()

        csv_cycle_1 = f"{RITA_CSV_HEADER}\n{RITA_SAMPLE_TUNNEL_ROW}\n"
        alerts_c1 = adapter.process_csv_text(csv_cycle_1)
        assert len(alerts_c1) == 1
        assert alerts_c1[0].supporting_evidence["domain"] == "dnsc.r-1x.com"

        # Cycle 2: Same finding A re-queried by rolling import
        csv_cycle_2 = f"{RITA_CSV_HEADER}\n{RITA_SAMPLE_TUNNEL_ROW}\n"
        alerts_c2 = adapter.process_csv_text(csv_cycle_2)
        assert len(alerts_c2) == 0, "Expected 0 alerts on cycle 2 for duplicate finding"

        # Cycle 3: Finding A + genuinely new finding B
        csv_cycle_3 = (
            f"{RITA_CSV_HEADER}\n"
            f"{RITA_SAMPLE_TUNNEL_ROW}\n"
            f"{RITA_SAMPLE_TUNNEL_ROW_2}\n"
        )
        alerts_c3 = adapter.process_csv_text(csv_cycle_3)
        assert len(alerts_c3) == 1, "Expected exactly 1 new alert for finding B"
        assert alerts_c3[0].supporting_evidence["domain"] == "tunnel.evil.org"


class TestRitaTunnelAlertSchemaCompliance:
    def test_alert_schema_validation(self, adapter: RitaTunnelAdapter):
        csv_payload = f"{RITA_CSV_HEADER}\n{RITA_SAMPLE_TUNNEL_ROW}\n"
        records = adapter.parse_csv_text(csv_payload)
        alert = adapter.create_alert(records[0])
        assert alert is not None

        alert_dict = alert.to_dict()

        # Threat class must be schema-approved dns_tunnel
        assert alert_dict["threat_class"] == ThreatClass.DNS_TUNNEL
        assert alert_dict["threat_class"] == "dns_tunnel"

        # Subtype
        assert alert_dict["subtype"] == "c2_over_dns"

        # Latency class must be periodic
        assert alert_dict["latency_class"] == LatencyClass.PERIODIC
        assert alert_dict["latency_class"] == "periodic"

        # Confidence heuristic mapping
        assert 0.0 <= alert_dict["confidence"] <= 1.0

        # Model and detector version
        assert alert_dict["model_version"] == "5.1.2"
        assert alert_dict["detector"] == "rita_tunnel_adapter"

        # Supporting evidence
        evidence = alert_dict["supporting_evidence"]
        assert evidence["finding_type"] == "c2_over_dns"
        assert evidence["domain"] == "dnsc.r-1x.com"
        assert evidence["c2_over_dns_score"] == 0.85
        assert evidence["subdomains_count"] == 512
        assert "confidence_mapping_rationale" in evidence
        assert "deduplication_fingerprint" in evidence

        # External blacklist must not be enabled
        assert evidence["blacklist_status"] == "disabled"
        assert evidence["threat_intel_status"] == "disabled (no external reputation queried)"

        # Full validation against schema
        is_valid, errors = validate_draft_alert(alert_dict)
        assert is_valid, f"Alert validation failed: {errors}"
