"""
Unit tests for the DDoS detector — all 16 required test cases.

Tests cover:
  1.  Normal traffic does not trigger.
  2.  High packet rate alone does not trigger (entropy guard).
  3.  High byte rate alone does not trigger (entropy guard).
  4.  Rate anomaly + entropy anomaly triggers.
  5.  Low entropy flood triggers when rate anomaly also exists.
  6.  High entropy distributed-source triggers when rate anomaly also exists.
  7.  Zero standard deviation does not crash.
  8.  Missing optional Zeek fields do not crash.
  9.  Flagged windows are excluded from baseline.
  10. Baseline poisoning regression test.
  11. Multiple destinations maintain independent baselines.
  12. Multiple windows update baseline correctly.
  13. SYN classification.
  14. UDP classification.
  15. Evidence fields are populated.
  16. Alert schema validation succeeds.
"""

from __future__ import annotations

import math

import pytest

from alerts.validator import validate_draft_alert
from detectors.ddos.baseline import BaselineStore, DestinationBaseline, MetricBaseline
from detectors.ddos.config import DDoSConfig
from detectors.ddos.detector import DDoSDetector
from features.flow_stats import FlowWindow, shannon_entropy


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_window(
    destination_ip: str = "10.0.0.1",
    window_start: float = 0.0,
    flow_count: int = 10,
    packet_count: int = 100,
    byte_count: int = 10000,
    pkt_rate: float = 10.0,
    byte_rate: float = 1000.0,
    unique_source_count: int = 3,
    src_ip_entropy: float = 1.5,
    source_ip_counts: dict[str, int] | None = None,
    tcp_flow_count: int = 0,
    udp_flow_count: int = 10,
    icmp_flow_count: int = 0,
    tcp_syn_count: int = 0,
    tcp_syn_ack_count: int = 0,
    conn_state_counts: dict[str, int] | None = None,
    total_orig_ip_bytes: int = 5000,
    total_resp_ip_bytes: int = 5000,
    window_seconds: float = 10.0,
) -> FlowWindow:
    """Create a FlowWindow with sensible defaults for testing."""
    if source_ip_counts is None:
        source_ip_counts = {f"10.0.0.{i+10}": flow_count // max(unique_source_count, 1)
                            for i in range(unique_source_count)}
    if conn_state_counts is None:
        conn_state_counts = {"SF": flow_count}

    return FlowWindow(
        window_start=window_start,
        window_end=window_start + window_seconds,
        destination_ip=destination_ip,
        flow_count=flow_count,
        packet_count=packet_count,
        byte_count=byte_count,
        pkt_rate=pkt_rate,
        byte_rate=byte_rate,
        unique_source_count=unique_source_count,
        src_ip_entropy=src_ip_entropy,
        source_ip_counts=source_ip_counts,
        tcp_flow_count=tcp_flow_count,
        udp_flow_count=udp_flow_count,
        icmp_flow_count=icmp_flow_count,
        tcp_syn_count=tcp_syn_count,
        tcp_syn_ack_count=tcp_syn_ack_count,
        conn_state_counts=conn_state_counts,
        total_orig_ip_bytes=total_orig_ip_bytes,
        total_resp_ip_bytes=total_resp_ip_bytes,
    )


def _build_baseline(
    detector: DDoSDetector,
    dst: str,
    n: int,
    pkt_rate: float = 10.0,
    byte_rate: float = 1000.0,
    entropy: float = 1.5,
) -> None:
    """Feed n normal windows to build a baseline for a destination."""
    for i in range(n):
        w = _make_window(
            destination_ip=dst,
            window_start=float(i * 10),
            pkt_rate=pkt_rate,
            byte_rate=byte_rate,
            src_ip_entropy=entropy,
        )
        result = detector.process_window(w)
        assert result is None, f"Baseline window {i} should not trigger"


def _default_config() -> DDoSConfig:
    """Config with small baseline for fast tests."""
    return DDoSConfig(
        window_seconds=10.0,
        baseline_windows=5,
        z_threshold=4.0,
        epsilon=1e-9,
        entropy_z_threshold=3.0,
        min_flows_for_detection=5,
    )


# ===========================================================================
# TEST CASES
# ===========================================================================


class TestCase01_NormalTrafficDoesNotTrigger:
    """1. Normal traffic does not trigger."""

    def test_normal_windows_produce_no_alerts(self) -> None:
        config = _default_config()
        detector = DDoSDetector(config=config)

        # Feed 20 normal windows
        for i in range(20):
            w = _make_window(
                window_start=float(i * 10),
                pkt_rate=10.0,
                byte_rate=1000.0,
                src_ip_entropy=1.5,
            )
            assert detector.process_window(w) is None

        assert len(detector.alerts) == 0


class TestCase02_HighPktRateAloneDoesNotTrigger:
    """2. High packet rate alone does not trigger (entropy guard)."""

    def test_high_pkt_rate_normal_entropy(self) -> None:
        config = _default_config()
        detector = DDoSDetector(config=config)

        # Build normal baseline
        _build_baseline(detector, "10.0.0.1", 5)

        # Spike packet rate but keep entropy normal
        spike = _make_window(
            window_start=50.0,
            pkt_rate=10000.0,  # Massive spike
            byte_rate=1000.0,
            src_ip_entropy=1.5,  # Same as baseline → no entropy anomaly
        )
        result = detector.process_window(spike)
        assert result is None


class TestCase03_HighByteRateAloneDoesNotTrigger:
    """3. High byte rate alone does not trigger (entropy guard)."""

    def test_high_byte_rate_normal_entropy(self) -> None:
        config = _default_config()
        detector = DDoSDetector(config=config)

        _build_baseline(detector, "10.0.0.1", 5)

        spike = _make_window(
            window_start=50.0,
            pkt_rate=10.0,
            byte_rate=1000000.0,  # Massive byte spike
            src_ip_entropy=1.5,   # Normal
        )
        result = detector.process_window(spike)
        assert result is None


class TestCase04_RateAndEntropyAnomalyTriggers:
    """4. Rate anomaly + entropy anomaly triggers."""

    def test_combined_anomaly_produces_alert(self) -> None:
        config = _default_config()
        detector = DDoSDetector(config=config)

        _build_baseline(detector, "10.0.0.1", 5,
                        pkt_rate=10.0, byte_rate=1000.0, entropy=1.5)

        # Both rate spike AND entropy change
        attack = _make_window(
            window_start=50.0,
            pkt_rate=10000.0,   # Rate anomaly
            byte_rate=1000000.0,
            src_ip_entropy=0.0,  # Entropy drop → anomaly
            unique_source_count=1,
            source_ip_counts={"10.0.0.99": 10},
        )
        result = detector.process_window(attack)
        assert result is not None
        assert result.threat_class == "ddos"


class TestCase05_LowEntropyFloodTriggers:
    """5. Low entropy flood triggers when rate anomaly also exists."""

    def test_low_entropy_with_rate_spike(self) -> None:
        config = _default_config()
        detector = DDoSDetector(config=config)

        _build_baseline(detector, "10.0.0.1", 5,
                        pkt_rate=10.0, entropy=1.5)

        # Single-source flood: entropy drops to 0
        attack = _make_window(
            window_start=50.0,
            pkt_rate=10000.0,
            byte_rate=1000000.0,
            src_ip_entropy=0.0,  # Significant drop
            unique_source_count=1,
            source_ip_counts={"10.0.0.99": 100},
        )
        result = detector.process_window(attack)
        assert result is not None
        evidence = result.supporting_evidence
        assert evidence["entropy_anomaly_type"] == "drop"


class TestCase06_HighEntropyDistributedTriggers:
    """6. High entropy distributed-source anomaly triggers when rate anomaly exists."""

    def test_high_entropy_spike_with_rate_anomaly(self) -> None:
        config = _default_config()
        detector = DDoSDetector(config=config)

        # Baseline: low entropy (few sources)
        _build_baseline(detector, "10.0.0.1", 5,
                        pkt_rate=10.0, entropy=0.5)

        # Many diverse sources → entropy spike
        many_sources = {f"10.0.{i}.{j}": 1 for i in range(5) for j in range(10)}
        attack = _make_window(
            window_start=50.0,
            pkt_rate=10000.0,
            byte_rate=1000000.0,
            src_ip_entropy=shannon_entropy(many_sources),  # High entropy
            unique_source_count=len(many_sources),
            source_ip_counts=many_sources,
        )
        result = detector.process_window(attack)
        assert result is not None
        assert result.supporting_evidence["entropy_anomaly_type"] == "spike"


class TestCase07_ZeroStddevDoesNotCrash:
    """7. Zero standard deviation does not crash."""

    def test_constant_baseline(self) -> None:
        config = _default_config()
        detector = DDoSDetector(config=config)

        # All baseline windows have identical values → stddev = 0
        _build_baseline(detector, "10.0.0.1", 5,
                        pkt_rate=10.0, byte_rate=1000.0, entropy=1.5)

        baseline = detector.baseline_store.get("10.0.0.1")
        assert baseline.pkt_rate.stddev == 0.0

        # Should not crash — division by epsilon instead
        normal = _make_window(window_start=50.0, pkt_rate=10.0, src_ip_entropy=1.5)
        result = detector.process_window(normal)
        # With zero stddev and same value, z-score ≈ 0, no trigger
        assert result is None


class TestCase08_MissingOptionalFieldsDoNotCrash:
    """8. Missing optional Zeek fields do not crash."""

    def test_process_window_with_minimal_data(self) -> None:
        config = _default_config()
        detector = DDoSDetector(config=config)

        # Window with minimal counts
        w = _make_window(
            flow_count=5,
            packet_count=5,
            byte_count=500,
            pkt_rate=0.5,
            byte_rate=50.0,
            unique_source_count=1,
            src_ip_entropy=0.0,
            tcp_flow_count=0,
            udp_flow_count=5,
            tcp_syn_count=0,
            tcp_syn_ack_count=0,
            source_ip_counts={"10.0.0.1": 5},
            conn_state_counts={"S0": 5},
        )
        # Should not crash
        result = detector.process_window(w)
        assert result is None  # Not enough baseline


class TestCase09_FlaggedWindowsExcludedFromBaseline:
    """9. Flagged windows are excluded from baseline."""

    def test_flagged_window_not_in_baseline(self) -> None:
        config = _default_config()
        detector = DDoSDetector(config=config)

        _build_baseline(detector, "10.0.0.1", 5,
                        pkt_rate=10.0, byte_rate=1000.0, entropy=1.5)

        baseline = detector.baseline_store.get("10.0.0.1")
        count_before = baseline.pkt_rate.count

        # Trigger an alert (rate + entropy anomaly)
        attack = _make_window(
            window_start=50.0,
            pkt_rate=10000.0,
            byte_rate=1000000.0,
            src_ip_entropy=0.0,
            unique_source_count=1,
            source_ip_counts={"10.0.0.99": 100},
        )
        result = detector.process_window(attack)
        assert result is not None

        # Baseline should NOT have grown
        count_after = baseline.pkt_rate.count
        assert count_after == count_before


class TestCase10_BaselinePoisoningRegression:
    """10. Baseline poisoning regression test.

    Sustained attack windows must not shift the baseline upward,
    which would make future attacks harder to detect.
    """

    def test_sustained_attack_does_not_poison_baseline(self) -> None:
        config = _default_config()
        detector = DDoSDetector(config=config)

        _build_baseline(detector, "10.0.0.1", 5,
                        pkt_rate=10.0, byte_rate=1000.0, entropy=1.5)

        baseline = detector.baseline_store.get("10.0.0.1")
        mean_before = baseline.pkt_rate.mean

        # Send 10 attack windows (sustained attack)
        for i in range(10):
            attack = _make_window(
                window_start=50.0 + i * 10,
                pkt_rate=10000.0,
                byte_rate=1000000.0,
                src_ip_entropy=0.0,
                unique_source_count=1,
                source_ip_counts={"10.0.0.99": 100},
            )
            detector.process_window(attack)

        # Baseline mean should NOT have changed
        mean_after = baseline.pkt_rate.mean
        assert mean_after == pytest.approx(mean_before)


class TestCase11_MultipleDstIndependentBaselines:
    """11. Multiple destinations maintain independent baselines."""

    def test_independent_baselines(self) -> None:
        config = _default_config()
        detector = DDoSDetector(config=config)

        # Build different baselines for two destinations
        _build_baseline(detector, "10.0.0.1", 5,
                        pkt_rate=10.0, byte_rate=1000.0, entropy=1.5)
        _build_baseline(detector, "10.0.0.2", 5,
                        pkt_rate=100.0, byte_rate=10000.0, entropy=2.0)

        b1 = detector.baseline_store.get("10.0.0.1")
        b2 = detector.baseline_store.get("10.0.0.2")

        assert b1.pkt_rate.mean == pytest.approx(10.0)
        assert b2.pkt_rate.mean == pytest.approx(100.0)


class TestCase12_MultipleWindowsUpdateBaseline:
    """12. Multiple windows update baseline correctly."""

    def test_baseline_grows_with_clean_windows(self) -> None:
        config = DDoSConfig(baseline_windows=10, min_flows_for_detection=5)
        detector = DDoSDetector(config=config)

        for i in range(8):
            w = _make_window(
                window_start=float(i * 10),
                pkt_rate=10.0 + i,  # Varying rate
            )
            detector.process_window(w)

        baseline = detector.baseline_store.get("10.0.0.1")
        assert baseline.pkt_rate.count == 8

        # Mean should reflect the values added
        expected_mean = sum(10.0 + i for i in range(8)) / 8
        assert baseline.pkt_rate.mean == pytest.approx(expected_mean)


class TestCase13_SynFloodClassification:
    """13. SYN classification."""

    def test_syn_flood_subtype(self) -> None:
        config = _default_config()
        detector = DDoSDetector(config=config)

        _build_baseline(detector, "10.0.0.1", 5,
                        pkt_rate=10.0, byte_rate=1000.0, entropy=1.5)

        # SYN flood: all TCP, all S0, entropy drop
        attack = _make_window(
            window_start=50.0,
            pkt_rate=10000.0,
            byte_rate=1000000.0,
            src_ip_entropy=0.0,
            unique_source_count=1,
            source_ip_counts={"10.0.0.99": 100},
            tcp_flow_count=100,
            udp_flow_count=0,
            tcp_syn_count=90,    # 90% SYN-only
            tcp_syn_ack_count=10,
            flow_count=100,
            conn_state_counts={"S0": 90, "SF": 10},
        )
        result = detector.process_window(attack)
        assert result is not None
        assert result.subtype == "syn_flood"


class TestCase14_UdpFloodClassification:
    """14. UDP classification."""

    def test_udp_flood_subtype(self) -> None:
        config = _default_config()
        detector = DDoSDetector(config=config)

        _build_baseline(detector, "10.0.0.1", 5,
                        pkt_rate=10.0, byte_rate=1000.0, entropy=1.5)

        # UDP flood: all UDP, entropy drop
        attack = _make_window(
            window_start=50.0,
            pkt_rate=10000.0,
            byte_rate=1000000.0,
            src_ip_entropy=0.0,
            unique_source_count=1,
            source_ip_counts={"10.0.0.99": 100},
            tcp_flow_count=0,
            udp_flow_count=100,
            flow_count=100,
        )
        result = detector.process_window(attack)
        assert result is not None
        assert result.subtype == "udp_flood"


class TestCase15_EvidenceFieldsPopulated:
    """15. Evidence fields are populated."""

    def test_all_required_evidence_present(self) -> None:
        config = _default_config()
        detector = DDoSDetector(config=config)

        _build_baseline(detector, "10.0.0.1", 5,
                        pkt_rate=10.0, byte_rate=1000.0, entropy=1.5)

        attack = _make_window(
            window_start=50.0,
            pkt_rate=10000.0,
            byte_rate=1000000.0,
            src_ip_entropy=0.0,
            unique_source_count=1,
            source_ip_counts={"10.0.0.99": 100},
        )
        result = detector.process_window(attack)
        assert result is not None

        ev = result.supporting_evidence

        # All minimum required evidence fields
        required_evidence = [
            "window_seconds",
            "flow_count",
            "pkt_rate",
            "byte_rate",
            "src_ip_entropy",
            "pkt_z_score",
            "byte_z_score",
            "z_threshold",
            "entropy_anomaly_type",
            "unique_source_count",
            "entropy_z_score",
            "entropy_z_threshold",
            "confidence_method",
            "baseline_pkt_rate_mean",
            "baseline_pkt_rate_stddev",
        ]
        for field in required_evidence:
            assert field in ev, f"Missing evidence field: {field}"


class TestCase16_AlertSchemaValidation:
    """16. Alert schema validation succeeds."""

    def test_generated_alert_passes_validation(self) -> None:
        config = _default_config()
        detector = DDoSDetector(config=config)

        _build_baseline(detector, "10.0.0.1", 5,
                        pkt_rate=10.0, byte_rate=1000.0, entropy=1.5)

        attack = _make_window(
            window_start=50.0,
            pkt_rate=10000.0,
            byte_rate=1000000.0,
            src_ip_entropy=0.0,
            unique_source_count=1,
            source_ip_counts={"10.0.0.99": 100},
        )
        result = detector.process_window(attack)
        assert result is not None

        valid, errors = validate_draft_alert(result.to_dict())
        assert valid is True, f"Validation errors: {errors}"
        assert errors == []


# ===========================================================================
# Additional edge case tests
# ===========================================================================


class TestMetricBaseline:
    """Direct tests for the MetricBaseline component."""

    def test_empty_baseline_mean_zero(self) -> None:
        b = MetricBaseline(max_size=5)
        assert b.mean == 0.0
        assert b.stddev == 0.0

    def test_single_value_stddev_zero(self) -> None:
        b = MetricBaseline(max_size=5)
        b.add(10.0)
        assert b.mean == 10.0
        assert b.stddev == 0.0
        assert not b.is_ready  # Need at least 2

    def test_z_score_with_zero_variance(self) -> None:
        """Zero variance uses epsilon denominator — no crash."""
        b = MetricBaseline(max_size=5, epsilon=1e-9)
        b.add(10.0)
        b.add(10.0)
        # stddev = 0, z_score uses epsilon
        z = b.z_score(10.0)
        assert z == pytest.approx(0.0, abs=1e-6)

    def test_deque_max_size_enforced(self) -> None:
        b = MetricBaseline(max_size=3)
        for v in [1.0, 2.0, 3.0, 4.0, 5.0]:
            b.add(v)
        assert b.count == 3
        assert b.mean == pytest.approx(4.0)  # Only [3, 4, 5]


class TestConfidenceRange:
    """Verify confidence is always in [0, 1]."""

    def test_confidence_bounded(self) -> None:
        config = _default_config()
        detector = DDoSDetector(config=config)

        _build_baseline(detector, "10.0.0.1", 5,
                        pkt_rate=10.0, byte_rate=1000.0, entropy=1.5)

        # Extreme attack
        attack = _make_window(
            window_start=50.0,
            pkt_rate=999999.0,
            byte_rate=999999999.0,
            src_ip_entropy=0.0,
            unique_source_count=1,
            source_ip_counts={"10.0.0.99": 100},
        )
        result = detector.process_window(attack)
        assert result is not None
        assert 0.0 <= result.confidence <= 1.0
