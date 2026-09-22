"""Unit tests for features.flow_stats — flow window aggregation."""

import math

import pytest

from features.flow_stats import FlowWindow, build_flow_windows, shannon_entropy
from ingest.parser import ConnRecord


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_conn(
    ts: float = 100.0,
    src_ip: str = "10.0.0.1",
    dst_ip: str = "10.0.0.2",
    proto: str = "tcp",
    conn_state: str = "SF",
    orig_pkts: int = 5,
    resp_pkts: int = 3,
    orig_ip_bytes: int = 500,
    resp_ip_bytes: int = 300,
    **kwargs,
) -> ConnRecord:
    defaults = dict(
        ts=ts,
        uid="C123",
        src_ip=src_ip,
        src_port=12345,
        dst_ip=dst_ip,
        dst_port=80,
        proto=proto,
        conn_state=conn_state,
        orig_pkts=orig_pkts,
        resp_pkts=resp_pkts,
        orig_ip_bytes=orig_ip_bytes,
        resp_ip_bytes=resp_ip_bytes,
        missed_bytes=0,
        local_orig=True,
        local_resp=True,
    )
    defaults.update(kwargs)
    return ConnRecord(**defaults)


# ---------------------------------------------------------------------------
# Shannon entropy tests
# ---------------------------------------------------------------------------

class TestShannonEntropy:

    def test_empty_dict(self) -> None:
        assert shannon_entropy({}) == 0.0

    def test_single_source(self) -> None:
        assert shannon_entropy({"a": 10}) == 0.0

    def test_two_equal_sources(self) -> None:
        """Two equal sources → 1 bit of entropy."""
        assert shannon_entropy({"a": 5, "b": 5}) == pytest.approx(1.0)

    def test_four_equal_sources(self) -> None:
        """Four equal sources → 2 bits of entropy."""
        assert shannon_entropy({"a": 1, "b": 1, "c": 1, "d": 1}) == pytest.approx(2.0)

    def test_skewed_distribution(self) -> None:
        """One dominant source → low entropy."""
        e = shannon_entropy({"a": 100, "b": 1})
        assert e > 0.0
        assert e < 1.0

    def test_zero_count_ignored(self) -> None:
        result = shannon_entropy({"a": 5, "b": 0})
        assert result == 0.0  # Single non-zero source


# ---------------------------------------------------------------------------
# Flow window tests
# ---------------------------------------------------------------------------

class TestBuildFlowWindows:

    def test_single_record_single_window(self) -> None:
        records = [_make_conn(ts=5.0)]
        windows = build_flow_windows(records, window_seconds=10.0)
        assert len(windows) == 1
        w = windows[0]
        assert w.window_start == 0.0
        assert w.window_end == 10.0
        assert w.flow_count == 1
        assert w.packet_count == 8  # 5 + 3
        assert w.byte_count == 800  # 500 + 300
        assert w.pkt_rate == pytest.approx(0.8)
        assert w.byte_rate == pytest.approx(80.0)
        assert w.unique_source_count == 1

    def test_two_records_same_window(self) -> None:
        records = [
            _make_conn(ts=1.0, src_ip="10.0.0.1"),
            _make_conn(ts=5.0, src_ip="10.0.0.2"),
        ]
        windows = build_flow_windows(records, window_seconds=10.0)
        assert len(windows) == 1
        assert windows[0].flow_count == 2
        assert windows[0].unique_source_count == 2

    def test_records_split_across_windows(self) -> None:
        records = [
            _make_conn(ts=5.0),
            _make_conn(ts=15.0),
        ]
        windows = build_flow_windows(records, window_seconds=10.0)
        assert len(windows) == 2
        assert windows[0].window_start == 0.0
        assert windows[1].window_start == 10.0

    def test_multiple_destinations(self) -> None:
        records = [
            _make_conn(ts=1.0, dst_ip="10.0.0.2"),
            _make_conn(ts=1.0, dst_ip="10.0.0.3"),
        ]
        windows = build_flow_windows(records, window_seconds=10.0)
        assert len(windows) == 2
        dest_ips = {w.destination_ip for w in windows}
        assert dest_ips == {"10.0.0.2", "10.0.0.3"}

    def test_syn_count(self) -> None:
        """S0 connections should be counted as SYN-only."""
        records = [
            _make_conn(ts=1.0, proto="tcp", conn_state="S0"),
            _make_conn(ts=2.0, proto="tcp", conn_state="S0"),
            _make_conn(ts=3.0, proto="tcp", conn_state="SF"),
        ]
        windows = build_flow_windows(records, window_seconds=10.0)
        assert len(windows) == 1
        assert windows[0].tcp_syn_count == 2
        assert windows[0].tcp_syn_ack_count == 1

    def test_udp_and_icmp_counts(self) -> None:
        records = [
            _make_conn(ts=1.0, proto="udp"),
            _make_conn(ts=2.0, proto="udp"),
            _make_conn(ts=3.0, proto="icmp"),
        ]
        windows = build_flow_windows(records, window_seconds=10.0)
        assert windows[0].udp_flow_count == 2
        assert windows[0].icmp_flow_count == 1
        assert windows[0].tcp_flow_count == 0

    def test_entropy_multiple_sources(self) -> None:
        """Multiple sources should produce non-zero entropy."""
        records = [
            _make_conn(ts=1.0, src_ip=f"10.0.0.{i}")
            for i in range(4)
        ]
        windows = build_flow_windows(records, window_seconds=10.0)
        assert windows[0].src_ip_entropy == pytest.approx(2.0)  # 4 equal sources

    def test_invalid_window_seconds(self) -> None:
        with pytest.raises(ValueError, match="positive"):
            build_flow_windows([], window_seconds=0)

    def test_directional_bytes(self) -> None:
        records = [_make_conn(ts=1.0, orig_ip_bytes=100, resp_ip_bytes=5000)]
        windows = build_flow_windows(records, window_seconds=10.0)
        assert windows[0].total_orig_ip_bytes == 100
        assert windows[0].total_resp_ip_bytes == 5000

    def test_window_boundary_5s_tumbling(self) -> None:
        """
        Mandatory boundary test for 5.0-second tumbling windows:
          - 4.999 -> first window [0.0, 5.0)
          - 5.000 -> second window [5.0, 10.0)
          - 5.001 -> second window [5.0, 10.0)
        """
        recs = [
            _make_conn(ts=4.999, dst_ip="10.0.0.5"),
            _make_conn(ts=5.000, dst_ip="10.0.0.5"),
            _make_conn(ts=5.001, dst_ip="10.0.0.5"),
        ]
        windows = build_flow_windows(recs, window_seconds=5.0)
        assert len(windows) == 2

        # First window [0.0, 5.0) contains ts=4.999
        w1 = windows[0]
        assert w1.window_start == 0.0
        assert w1.window_end == 5.0
        assert w1.flow_count == 1

        # Second window [5.0, 10.0) contains ts=5.000 and ts=5.001
        w2 = windows[1]
        assert w2.window_start == 5.0
        assert w2.window_end == 10.0
        assert w2.flow_count == 2

    def test_hand_computed_source_entropy(self) -> None:
        """
        Hand-computed flow test (Section 26):
          window: 5.0s, destination: 10.0.0.5
          flows:
            192.168.1.1 -> 10.0.0.5 (count 2)
            192.168.1.2 -> 10.0.0.5 (count 1)
          Distribution:
            p1 = 2/3, p2 = 1/3
          Expected entropy:
            H = -(2/3 * log2(2/3) + 1/3 * log2(1/3))
              = -(-0.389975 - 0.528321) = 0.918295834...
        """
        recs = [
            _make_conn(ts=1.0, src_ip="192.168.1.1", dst_ip="10.0.0.5"),
            _make_conn(ts=2.0, src_ip="192.168.1.1", dst_ip="10.0.0.5"),
            _make_conn(ts=3.0, src_ip="192.168.1.2", dst_ip="10.0.0.5"),
        ]
        windows = build_flow_windows(recs, window_seconds=5.0)
        assert len(windows) == 1
        win = windows[0]

        hand_computed_entropy = -( (2/3) * math.log2(2/3) + (1/3) * math.log2(1/3) )
        assert pytest.approx(win.src_ip_entropy, rel=1e-5) == hand_computed_entropy
        assert round(win.src_ip_entropy, 4) == round(hand_computed_entropy, 4)

    def test_flow_window_convenience_properties_and_dict(self) -> None:
        rec = _make_conn(ts=1.0, src_ip="192.168.1.1", dst_ip="10.0.0.5", orig_pkts=10, resp_pkts=5, orig_ip_bytes=1000, resp_ip_bytes=500)
        windows = build_flow_windows([rec], window_seconds=5.0)
        win = windows[0]

        assert win.destination == "10.0.0.5"
        assert win.total_packets == 15
        assert win.total_bytes == 1500
        assert win.distinct_source_ips == 1
        assert win.distinct_src_ips == 1

        d = win.to_dict()
        assert d["destination"] == "10.0.0.5"
        assert d["total_packets"] == 15
        assert d["total_bytes"] == 1500
        assert d["window_start"] == 0.0
        assert d["window_end"] == 5.0

    def test_streaming_aggregator_boundary_crossing_preserves_event(self) -> None:
        """
        Section 8: Window close behavior.
        When a new event crosses the boundary:
          1. finalize previous window
          2. calculate statistics
          3. emit feature records
          4. initialize new window
          5. process new event (do NOT discard crossing event)
        """
        from features.flow_stats import FlowWindowAggregator

        agg = FlowWindowAggregator(window_seconds=5.0)

        # Event 1 & 2 in [0.0, 5.0)
        emitted_1 = agg.add_record(_make_conn(ts=1.0, src_ip="10.0.0.1", dst_ip="10.0.0.5"))
        assert len(emitted_1) == 0

        emitted_2 = agg.add_record(_make_conn(ts=4.5, src_ip="10.0.0.2", dst_ip="10.0.0.5"))
        assert len(emitted_2) == 0

        # Event 3 at ts=5.2 crosses the boundary into [5.0, 10.0)
        emitted_3 = agg.add_record(_make_conn(ts=5.2, src_ip="10.0.0.3", dst_ip="10.0.0.5"))
        assert len(emitted_3) == 1
        w_prev = emitted_3[0]
        assert w_prev.window_start == 0.0
        assert w_prev.window_end == 5.0
        assert w_prev.flow_count == 2
        assert w_prev.unique_source_count == 2

        # Flush should yield the second window containing the crossing event at 5.2
        emitted_final = agg.flush()
        assert len(emitted_final) == 1
        w_curr = emitted_final[0]
        assert w_curr.window_start == 5.0
        assert w_curr.window_end == 10.0
        assert w_curr.flow_count == 1
        assert "10.0.0.3" in w_curr.source_ip_counts


class TestExtractFlowFeatures:
    """Unit tests for extract_flow_features in features.flow_stats."""

    def test_extract_flow_features_normal(self) -> None:
        from features.flow_stats import extract_flow_features

        rec = _make_conn(
            duration=2.0,
            orig_bytes=1000,
            resp_bytes=500,
            orig_pkts=10,
            resp_pkts=5,
            orig_ip_bytes=1400,
            resp_ip_bytes=700,
            proto="tcp",
            conn_state="SF",
            missed_bytes=0,
        )
        feats = extract_flow_features(rec)
        assert feats.duration == 2.0
        assert feats.orig_bytes == 1000
        assert feats.resp_bytes == 500
        assert feats.orig_pkts == 10
        assert feats.resp_pkts == 5
        assert feats.total_bytes == 2100
        assert feats.total_pkts == 15
        assert feats.byte_rate == pytest.approx(1050.0)
        assert feats.packet_rate == pytest.approx(7.5)
        assert feats.byte_ratio == pytest.approx(1400.0 / 700.0)
        assert feats.packet_ratio == pytest.approx(10.0 / 5.0)
        assert feats.proto == "tcp"
        assert feats.conn_state == "SF"
        assert feats.missed_bytes == 0

    def test_extract_flow_features_missing_optional(self) -> None:
        from features.flow_stats import extract_flow_features

        rec = _make_conn(
            duration=None,
            orig_bytes=None,
            resp_bytes=None,
            orig_pkts=1,
            resp_pkts=0,
            orig_ip_bytes=60,
            resp_ip_bytes=0,
        )
        feats = extract_flow_features(rec)
        assert feats.duration == 0.0
        assert feats.orig_bytes == 0
        assert feats.resp_bytes == 0
        assert feats.byte_rate == 0.0
        assert feats.packet_rate == 0.0
        assert feats.byte_ratio == 60.0  # 60 / max(0, 1) = 60.0
        assert feats.packet_ratio == 1.0  # 1 / max(0, 1) = 1.0

    def test_extract_flow_features_nan_inf_duration(self) -> None:
        from features.flow_stats import extract_flow_features

        rec_nan = _make_conn(duration=float("nan"))
        assert extract_flow_features(rec_nan).duration == 0.0

        rec_inf = _make_conn(duration=float("inf"))
        assert extract_flow_features(rec_inf).duration == 0.0

        rec_neg = _make_conn(duration=-5.0)
        assert extract_flow_features(rec_neg).duration == 0.0

    def test_extract_flow_features_to_dict(self) -> None:
        from features.flow_stats import extract_flow_features

        rec = _make_conn()
        d = extract_flow_features(rec).to_dict()
        assert isinstance(d, dict)
        assert "duration" in d
        assert "total_bytes" in d
        assert "byte_rate" in d
        assert "packet_rate" in d
        assert "proto" in d
        assert "conn_state" in d


