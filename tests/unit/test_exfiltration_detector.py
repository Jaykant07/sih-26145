"""
Unit tests for Data Exfiltration Detector (PS-26145 — Track B).

Covers all 20 required verification scenarios:
  1. normal outbound/inbound calculation
  2. byte_ratio calculation
  3. inbound zero handling
  4. ratio below threshold -> no alert
  5. ratio above threshold but volume below floor -> no alert
  6. ratio above threshold AND volume above floor -> alert
  7. inbound-heavy download -> no alert
  8. multiple flows aggregate correctly
  9. multiple destinations remain separate
 10. multiple source hosts maintain separate baselines
 11. baseline calculation
 12. baseline_deviation calculation
 13. insufficient baseline data handled correctly
 14. internal-to-internal traffic ignored
 15. external-to-internal download ignored
 16. missing orig_bytes handled safely
 17. missing resp_bytes handled safely
 18. correct threat_class
 19. schema validation succeeds
 20. evidence contains actual byte values
"""

import json
from pathlib import Path

import pytest

from alerts.constants import LatencyClass, Severity, ThreatClass
from alerts.validator import validate_draft_alert
from detectors.exfiltration.baseline import HostExfilBaseline
from detectors.exfiltration.detector import (
    DEFAULT_RATIO_THRESHOLD,
    DEFAULT_VOLUME_FLOOR,
    ExfiltrationDetector,
)
from detectors.exfiltration.network import NetworkClassifier
from features.flow_stats import ExfilFlowWindow, build_exfil_windows
from ingest.parser import ConnRecord


def _make_conn_record(
    ts: float = 1000.0,
    uid: str = "CTest12345",
    src_ip: str = "192.168.56.102",
    src_port: int = 49152,
    dst_ip: str = "203.0.113.50",
    dst_port: int = 443,
    proto: str = "tcp",
    conn_state: str = "SF",
    orig_pkts: int = 10,
    resp_pkts: int = 10,
    orig_ip_bytes: int = 1500,
    resp_ip_bytes: int = 1500,
    orig_bytes: int | None = 1000,
    resp_bytes: int | None = 1000,
    duration: float | None = 1.0,
) -> ConnRecord:
    """Helper to construct test ConnRecord instances."""
    return ConnRecord(
        ts=ts,
        uid=uid,
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        proto=proto,
        conn_state=conn_state,
        orig_pkts=orig_pkts,
        resp_pkts=resp_pkts,
        orig_ip_bytes=orig_ip_bytes,
        resp_ip_bytes=resp_ip_bytes,
        missed_bytes=0,
        local_orig=True,
        local_resp=False,
        duration=duration,
        orig_bytes=orig_bytes,
        resp_bytes=resp_bytes,
    )


class TestByteAccountingAndWindow:
    """Tests 1, 2, 3, 8, 9, 16, 17."""

    def test_01_normal_outbound_inbound_calculation(self):
        rec = _make_conn_record(orig_bytes=50000, resp_bytes=5000)
        classifier = NetworkClassifier()
        windows = build_exfil_windows([rec], window_seconds=60.0, network_classifier=classifier)
        assert len(windows) == 1
        win = windows[0]
        assert win.outbound_bytes == 50000
        assert win.inbound_bytes == 5000

    def test_02_byte_ratio_calculation(self):
        rec = _make_conn_record(orig_bytes=100000, resp_bytes=10000)
        windows = build_exfil_windows([rec], window_seconds=60.0)
        assert len(windows) == 1
        assert pytest.approx(windows[0].byte_ratio, 0.01) == 10.0

    def test_03_inbound_zero_handling(self):
        rec = _make_conn_record(orig_bytes=80000, resp_bytes=0)
        windows = build_exfil_windows([rec], window_seconds=60.0)
        assert len(windows) == 1
        # max(0, 1) -> 1, byte_ratio = 80000 / 1 = 80000.0
        assert windows[0].byte_ratio == 80000.0

    def test_08_multiple_flows_aggregate_correctly(self):
        recs = [
            _make_conn_record(ts=10.0, orig_bytes=20000, resp_bytes=1000),
            _make_conn_record(ts=20.0, orig_bytes=35000, resp_bytes=2000),
            _make_conn_record(ts=40.0, orig_bytes=15000, resp_bytes=500),
        ]
        windows = build_exfil_windows(recs, window_seconds=60.0)
        assert len(windows) == 1
        win = windows[0]
        assert win.flow_count == 3
        assert win.outbound_bytes == 70000
        assert win.inbound_bytes == 3500
        assert pytest.approx(win.byte_ratio, 0.01) == 20.0

    def test_09_multiple_destinations_remain_separate(self):
        recs = [
            _make_conn_record(ts=10.0, dst_ip="203.0.113.10", orig_bytes=20000, resp_bytes=1000),
            _make_conn_record(ts=20.0, dst_ip="203.0.113.20", orig_bytes=30000, resp_bytes=1500),
        ]
        windows = build_exfil_windows(recs, window_seconds=60.0)
        assert len(windows) == 2
        destinations = {w.destination_ip for w in windows}
        assert destinations == {"203.0.113.10", "203.0.113.20"}

    def test_16_missing_orig_bytes_handled_safely(self):
        rec = _make_conn_record(orig_bytes=None, resp_bytes=2000)
        windows = build_exfil_windows([rec], window_seconds=60.0)
        assert len(windows) == 1
        assert windows[0].outbound_bytes == 0
        assert windows[0].inbound_bytes == 2000
        assert windows[0].byte_ratio == 0.0

    def test_17_missing_resp_bytes_handled_safely(self):
        rec = _make_conn_record(orig_bytes=50000, resp_bytes=None)
        windows = build_exfil_windows([rec], window_seconds=60.0)
        assert len(windows) == 1
        assert windows[0].outbound_bytes == 50000
        assert windows[0].inbound_bytes == 0
        assert windows[0].byte_ratio == 50000.0


class TestThresholdAndAlertLogic:
    """Tests 4, 5, 6, 7."""

    def test_04_ratio_below_threshold_no_alert(self):
        # Ratio 5.0 <= threshold 10.0
        rec = _make_conn_record(orig_bytes=100000, resp_bytes=20000)
        detector = ExfiltrationDetector(ratio_threshold=10.0, volume_floor=50000)
        alerts = detector.process_records([rec])
        assert len(alerts) == 0

    def test_05_ratio_above_threshold_but_volume_below_floor_no_alert(self):
        # Ratio 100:1 > 10.0, but volume 1000 < 50000
        rec = _make_conn_record(orig_bytes=1000, resp_bytes=10)
        detector = ExfiltrationDetector(ratio_threshold=10.0, volume_floor=50000)
        alerts = detector.process_records([rec])
        assert len(alerts) == 0

    def test_06_ratio_above_threshold_and_volume_above_floor_emits_alert(self):
        # Ratio 25:1 > 10.0 AND volume 100000 >= 50000
        rec = _make_conn_record(orig_bytes=100000, resp_bytes=4000)
        detector = ExfiltrationDetector(ratio_threshold=10.0, volume_floor=50000)
        alerts = detector.process_records([rec])
        assert len(alerts) == 1
        alert = alerts[0]
        assert alert.threat_class == ThreatClass.EXFILTRATION
        assert alert.source == "192.168.56.102"
        assert alert.destination == "203.0.113.50"

    def test_07_inbound_heavy_download_no_alert(self):
        # Large download: orig 500 B, resp 2,000,000 B (ratio 0.00025:1)
        rec = _make_conn_record(orig_bytes=500, resp_bytes=2000000)
        detector = ExfiltrationDetector(ratio_threshold=10.0, volume_floor=50000)
        alerts = detector.process_records([rec])
        assert len(alerts) == 0


class TestBaselineTracking:
    """Tests 10, 11, 12, 13."""

    def test_10_multiple_source_hosts_maintain_separate_baselines(self):
        base = HostExfilBaseline(min_observations=2)
        base.add_observation(src_ip="192.168.56.101", byte_ratio=1.5, outbound_bytes=1000)
        base.add_observation(src_ip="192.168.56.102", byte_ratio=4.0, outbound_bytes=5000)

        stats1 = base.get_host_stats("192.168.56.101")
        stats2 = base.get_host_stats("192.168.56.102")
        assert stats1["mean_ratio"] == 1.5
        assert stats2["mean_ratio"] == 4.0

    def test_11_baseline_calculation(self):
        base = HostExfilBaseline(min_observations=3)
        base.add_observation(src_ip="192.168.56.102", byte_ratio=1.0, outbound_bytes=1000)
        base.add_observation(src_ip="192.168.56.102", byte_ratio=2.0, outbound_bytes=2000)
        base.add_observation(src_ip="192.168.56.102", byte_ratio=3.0, outbound_bytes=3000)

        stats = base.get_host_stats("192.168.56.102")
        assert stats["sample_count"] == 3
        assert stats["mean_ratio"] == 2.0
        assert stats["mean_volume"] == 2000.0

    def test_12_baseline_deviation_calculation(self):
        base = HostExfilBaseline(min_observations=3)
        base.add_observation(src_ip="192.168.56.102", byte_ratio=1.0, outbound_bytes=1000)
        base.add_observation(src_ip="192.168.56.102", byte_ratio=2.0, outbound_bytes=2000)
        base.add_observation(src_ip="192.168.56.102", byte_ratio=3.0, outbound_bytes=3000)

        dev = base.calculate_deviation(src_ip="192.168.56.102", current_ratio=10.0, current_volume=80000)
        assert dev["insufficient_baseline_data"] is False
        assert dev["baseline_deviation"] > 0.0
        assert dev["ratio_multiple"] == 5.0  # 10.0 / 2.0

    def test_13_insufficient_baseline_data_handled_correctly(self):
        base = HostExfilBaseline(min_observations=5)
        base.add_observation(src_ip="192.168.56.102", byte_ratio=1.0, outbound_bytes=1000)

        dev = base.calculate_deviation(src_ip="192.168.56.102", current_ratio=50.0, current_volume=100000)
        assert dev["insufficient_baseline_data"] is True
        assert dev["baseline_deviation"] == 0.0
        assert "Insufficient baseline data" in dev["explanation"]


class TestNetworkDirectionClassification:
    """Tests 14, 15."""

    def test_14_internal_to_internal_traffic_ignored(self):
        # 192.168.56.102 -> 192.168.56.254 (both internal lab IPs)
        rec = _make_conn_record(
            src_ip="192.168.56.102",
            dst_ip="192.168.56.254",
            orig_bytes=141000000,
            resp_bytes=0,
        )
        detector = ExfiltrationDetector(ratio_threshold=10.0, volume_floor=50000)
        alerts = detector.process_records([rec])
        assert len(alerts) == 0

    def test_15_external_to_internal_download_ignored(self):
        # 203.0.113.50 (external) -> 192.168.56.102 (internal)
        rec = _make_conn_record(
            src_ip="203.0.113.50",
            dst_ip="192.168.56.102",
            orig_bytes=2000000,
            resp_bytes=1000,
        )
        detector = ExfiltrationDetector(ratio_threshold=10.0, volume_floor=50000)
        alerts = detector.process_records([rec])
        assert len(alerts) == 0


class TestAlertContractAndSchemaCompliance:
    """Tests 18, 19, 20."""

    def test_18_correct_threat_class(self):
        rec = _make_conn_record(orig_bytes=200000, resp_bytes=2000)
        detector = ExfiltrationDetector(ratio_threshold=10.0, volume_floor=50000)
        alerts = detector.process_records([rec])
        assert len(alerts) == 1
        assert alerts[0].threat_class == ThreatClass.EXFILTRATION
        assert alerts[0].threat_class == "exfiltration"

    def test_19_schema_validation_succeeds(self):
        rec = _make_conn_record(orig_bytes=200000, resp_bytes=2000)
        detector = ExfiltrationDetector(ratio_threshold=10.0, volume_floor=50000)
        alerts = detector.process_records([rec])
        assert len(alerts) == 1
        alert_dict = alerts[0].to_dict()

        is_valid, errors = validate_draft_alert(alert_dict)
        assert is_valid, f"Validation failed: {errors}"
        assert alert_dict["latency_class"] == LatencyClass.PERIODIC
        assert alert_dict["model_version"] == "1.0.0"

    def test_20_evidence_contains_actual_byte_values(self):
        rec = _make_conn_record(orig_bytes=123456, resp_bytes=1234)
        detector = ExfiltrationDetector(ratio_threshold=10.0, volume_floor=50000)
        alerts = detector.process_records([rec])
        assert len(alerts) == 1
        ev = alerts[0].supporting_evidence
        assert ev["outbound_bytes"] == 123456
        assert ev["inbound_bytes"] == 1234
        assert pytest.approx(ev["byte_ratio"], 0.01) == 100.045
        assert ev["volume_floor"] == 50000
        assert ev["ratio_threshold"] == 10.0
        assert "uninspected" in ev["payload_inspection_status"].lower()
        assert "asymmetry" in ev["alert_description"].lower()
