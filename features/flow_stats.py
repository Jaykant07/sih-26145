"""
Flow statistics and window aggregation for PS-26145.

Groups Zeek ConnRecord objects into configurable time windows per
destination IP and computes aggregate statistics for downstream
detectors (DDoS, exfiltration, etc.).

Phase 12 placeholder — implemented minimally for Phase 16 (DDoS).
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable

from ingest.parser import ConnRecord


# ---------------------------------------------------------------------------
# Shannon entropy
# ---------------------------------------------------------------------------

def shannon_entropy(counts: dict[str, int]) -> float:
    """
    Calculate Shannon entropy from a frequency distribution.

    H = -sum(p_i * log2(p_i))

    Args:
        counts: Mapping from category labels to their frequency counts.

    Returns:
        Shannon entropy in bits.  Returns 0.0 for empty dicts,
        single-element dicts, or dicts with all-zero values.
    """
    total = sum(counts.values())
    if total <= 0:
        return 0.0

    entropy = 0.0
    for count in counts.values():
        if count <= 0:
            continue
        p = count / total
        entropy -= p * math.log2(p)

    return entropy


DEFAULT_WINDOW_SECONDS: float = 5.0


# ---------------------------------------------------------------------------
# FlowWindow dataclass
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FlowWindow:
    """Aggregated flow statistics for one destination IP in one time window."""

    window_start: float
    window_end: float
    destination_ip: str

    # Volume metrics
    flow_count: int
    packet_count: int   # sum(orig_pkts + resp_pkts)
    byte_count: int     # sum(orig_ip_bytes + resp_ip_bytes)

    # Rates (per second over window duration)
    pkt_rate: float
    byte_rate: float

    # Source diversity
    unique_source_count: int
    src_ip_entropy: float               # Shannon entropy of source IP distribution
    source_ip_counts: dict[str, int]    # {src_ip: flow_count}

    # Protocol breakdown
    tcp_flow_count: int
    udp_flow_count: int
    icmp_flow_count: int

    # TCP-specific
    tcp_syn_count: int      # SYN-only connections (S0, REJ, etc.)
    tcp_syn_ack_count: int  # Connections with handshake completion

    # Connection state distribution
    conn_state_counts: dict[str, int]

    # Directional bytes (for reflection/amplification analysis)
    total_orig_ip_bytes: int
    total_resp_ip_bytes: int

    # Total payload bytes (sum(orig_bytes + resp_bytes) when available)
    total_payload_bytes: int = 0

    @property
    def destination(self) -> str:
        """Alias for destination_ip."""
        return self.destination_ip

    @property
    def total_packets(self) -> int:
        """Alias for packet_count."""
        return self.packet_count

    @property
    def total_bytes(self) -> int:
        """Alias for byte_count."""
        return self.byte_count

    @property
    def distinct_source_ips(self) -> int:
        """Alias for unique_source_count."""
        return self.unique_source_count

    @property
    def distinct_src_ips(self) -> int:
        """Alias for unique_source_count."""
        return self.unique_source_count

    def to_dict(self) -> dict[str, Any]:
        """Convert flow window features to a dictionary record."""
        return {
            "window_start": self.window_start,
            "window_end": self.window_end,
            "destination": self.destination_ip,
            "flow_count": self.flow_count,
            "total_packets": self.packet_count,
            "total_bytes": self.byte_count,
            "total_payload_bytes": self.total_payload_bytes,
            "pkt_rate": self.pkt_rate,
            "byte_rate": self.byte_rate,
            "src_ip_entropy": self.src_ip_entropy,
            "distinct_src_ips": self.unique_source_count,
            "unique_source_count": self.unique_source_count,
            "source_ip_counts": dict(self.source_ip_counts),
            "tcp_flow_count": self.tcp_flow_count,
            "udp_flow_count": self.udp_flow_count,
            "icmp_flow_count": self.icmp_flow_count,
            "tcp_syn_count": self.tcp_syn_count,
            "tcp_syn_ack_count": self.tcp_syn_ack_count,
            "conn_state_counts": dict(self.conn_state_counts),
            "total_orig_ip_bytes": self.total_orig_ip_bytes,
            "total_resp_ip_bytes": self.total_resp_ip_bytes,
        }


# ---------------------------------------------------------------------------
# Connection-state classification helpers
# ---------------------------------------------------------------------------

# States indicating SYN sent but no handshake completion
_SYN_ONLY_STATES = frozenset({"S0", "REJ", "RSTOS0", "RSTRH"})

# States indicating handshake completed (at least partially)
_SYN_ACK_STATES = frozenset({"SF", "S1", "S2", "S3", "RSTO", "RSTR", "SH", "SHR", "OTH"})


def _is_syn_only(record: ConnRecord) -> bool:
    """Check if a TCP connection is SYN-only (no handshake completion)."""
    if record.proto != "tcp":
        return False
    return record.conn_state in _SYN_ONLY_STATES


def _is_syn_ack(record: ConnRecord) -> bool:
    """Check if a TCP connection completed (or partially completed) the handshake."""
    if record.proto != "tcp":
        return False
    return record.conn_state in _SYN_ACK_STATES


def _build_single_flow_window(
    recs: list[ConnRecord],
    dst_ip: str,
    window_start: float,
    window_end: float,
    window_seconds: float,
) -> FlowWindow:
    """Internal helper to construct a single FlowWindow from a list of records."""
    flow_count = len(recs)
    packet_count = sum((r.orig_pkts or 0) + (r.resp_pkts or 0) for r in recs)

    total_orig = sum(r.orig_ip_bytes or 0 for r in recs)
    total_resp = sum(r.resp_ip_bytes or 0 for r in recs)
    byte_count = total_orig + total_resp

    total_payload = sum((r.orig_bytes or 0) + (r.resp_bytes or 0) for r in recs)

    pkt_rate = packet_count / window_seconds
    byte_rate = byte_count / window_seconds

    # Source IP distribution
    src_counts: dict[str, int] = defaultdict(int)
    for r in recs:
        src_counts[r.src_ip] += 1
    source_ip_counts = dict(src_counts)
    unique_source_count = len(source_ip_counts)
    src_entropy = shannon_entropy(source_ip_counts)

    # Protocol breakdown
    tcp_count = sum(1 for r in recs if r.proto == "tcp")
    udp_count = sum(1 for r in recs if r.proto == "udp")
    icmp_count = sum(1 for r in recs if r.proto == "icmp")

    # TCP analysis
    syn_count = sum(1 for r in recs if _is_syn_only(r))
    syn_ack_count = sum(1 for r in recs if _is_syn_ack(r))

    # Connection state distribution
    state_counts: dict[str, int] = defaultdict(int)
    for r in recs:
        state_counts[r.conn_state] += 1

    return FlowWindow(
        window_start=window_start,
        window_end=window_end,
        destination_ip=dst_ip,
        flow_count=flow_count,
        packet_count=packet_count,
        byte_count=byte_count,
        pkt_rate=pkt_rate,
        byte_rate=byte_rate,
        unique_source_count=unique_source_count,
        src_ip_entropy=src_entropy,
        source_ip_counts=source_ip_counts,
        tcp_flow_count=tcp_count,
        udp_flow_count=udp_count,
        icmp_flow_count=icmp_count,
        tcp_syn_count=syn_count,
        tcp_syn_ack_count=syn_ack_count,
        conn_state_counts=dict(state_counts),
        total_orig_ip_bytes=total_orig,
        total_resp_ip_bytes=total_resp,
        total_payload_bytes=total_payload,
    )


# ---------------------------------------------------------------------------
# Window builder
# ---------------------------------------------------------------------------

def build_flow_windows(
    records: Iterable[ConnRecord],
    window_seconds: float = DEFAULT_WINDOW_SECONDS,
) -> list[FlowWindow]:
    """
    Group ConnRecords into tumbling time windows by destination IP and compute
    aggregate statistics.

    Records are assigned to windows based on ``floor(ts / window_seconds) * window_seconds``.
    Windows are returned sorted by ``(window_start, destination_ip)``.

    Args:
        records: Iterable of ConnRecord objects (need not be pre-sorted).
        window_seconds: Window duration in seconds.  Must be > 0. Defaults to 5.0.

    Returns:
        List of :class:`FlowWindow` objects.

    Raises:
        ValueError: If ``window_seconds <= 0``.
    """
    if window_seconds <= 0:
        raise ValueError(f"window_seconds must be positive, got {window_seconds}")

    # Bucket records by (window_id, destination_ip)
    buckets: dict[tuple[int, str], list[ConnRecord]] = defaultdict(list)

    for rec in records:
        window_id = int(math.floor(rec.ts / window_seconds))
        buckets[(window_id, rec.dst_ip)].append(rec)

    windows: list[FlowWindow] = []

    for (window_id, dst_ip), recs in sorted(buckets.items()):
        window_start = window_id * window_seconds
        window_end = window_start + window_seconds
        win = _build_single_flow_window(
            recs=recs,
            dst_ip=dst_ip,
            window_start=window_start,
            window_end=window_end,
            window_seconds=window_seconds,
        )
        windows.append(win)

    return windows


# ---------------------------------------------------------------------------
# Streaming Window Aggregator
# ---------------------------------------------------------------------------

class FlowWindowAggregator:
    """
    Streaming tumbling-window aggregator for flow statistics.

    Maintains active buckets for the current tumbling window. When an incoming
    record's timestamp crosses the window boundary:
      1. Finalizes preceding window(s).
      2. Computes rates and source-IP Shannon entropy.
      3. Emits finalized FlowWindow records.
      4. Initializes the new window and ingests the crossing record without loss.
    """

    def __init__(self, window_seconds: float = DEFAULT_WINDOW_SECONDS) -> None:
        if window_seconds <= 0:
            raise ValueError(f"window_seconds must be positive, got {window_seconds}")
        self.window_seconds = window_seconds
        self._current_window_id: Optional[int] = None
        self._active_buckets: dict[str, list[ConnRecord]] = defaultdict(list)

    def add_record(self, record: ConnRecord) -> list[FlowWindow]:
        """
        Ingest a single ConnRecord. Returns any FlowWindows finalized by
        a window boundary crossing. The incoming record is always retained.
        """
        rec_window_id = int(math.floor(record.ts / self.window_seconds))
        emitted: list[FlowWindow] = []

        if self._current_window_id is not None and rec_window_id > self._current_window_id:
            # Finalize previous window
            emitted = self._finalize_current()
            self._current_window_id = rec_window_id
        elif self._current_window_id is None:
            self._current_window_id = rec_window_id

        # Ingest into active bucket for this destination
        self._active_buckets[record.dst_ip].append(record)
        return emitted

    def flush(self) -> list[FlowWindow]:
        """Finalize and return all remaining active windows."""
        return self._finalize_current()

    def _finalize_current(self) -> list[FlowWindow]:
        if self._current_window_id is None or not self._active_buckets:
            self._active_buckets.clear()
            return []

        window_start = self._current_window_id * self.window_seconds
        window_end = window_start + self.window_seconds
        windows: list[FlowWindow] = []

        for dst_ip, recs in sorted(self._active_buckets.items()):
            win = _build_single_flow_window(
                recs=recs,
                dst_ip=dst_ip,
                window_start=window_start,
                window_end=window_end,
                window_seconds=self.window_seconds,
            )
            windows.append(win)

        self._active_buckets.clear()
        return windows



# ---------------------------------------------------------------------------
# Exfiltration Flow Window
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ExfilFlowWindow:
    """
    Aggregated flow statistics for one (source, destination) pair in one time window.
    Designed for exfiltration detection (PS-26145 Track B).
    """

    window_start: float
    window_end: float
    source_ip: str
    destination_ip: str
    flow_count: int
    outbound_bytes: int    # sum(orig_bytes or 0)
    inbound_bytes: int     # sum(resp_bytes or 0)
    orig_pkts: int         # sum(orig_pkts or 0)
    resp_pkts: int         # sum(resp_pkts or 0)
    byte_ratio: float      # outbound_bytes / max(inbound_bytes, 1)
    duration_sum: float    # sum(duration or 0.0)


def build_exfil_windows(
    records: Iterable[ConnRecord],
    window_seconds: float = 60.0,
    network_classifier: Optional[Any] = None,
) -> list[ExfilFlowWindow]:
    """
    Group ConnRecords into time windows by (source_ip, destination_ip)
    and compute outbound vs inbound payload byte statistics for exfiltration analysis.

    If network_classifier is provided, only records satisfying
    network_classifier.is_internal_to_external(src_ip, dst_ip) are included.

    Args:
        records: Iterable of ConnRecord objects.
        window_seconds: Window duration in seconds. Must be > 0.
        network_classifier: Optional NetworkClassifier instance.

    Returns:
        List of ExfilFlowWindow objects sorted by (window_start, source_ip, destination_ip).

    Raises:
        ValueError: If window_seconds <= 0.
    """
    if window_seconds <= 0:
        raise ValueError(f"window_seconds must be positive, got {window_seconds}")

    # Bucket records by (window_id, src_ip, dst_ip)
    buckets: dict[tuple[int, str, str], list[ConnRecord]] = defaultdict(list)

    for rec in records:
        if network_classifier is not None:
            if not network_classifier.is_internal_to_external(rec.src_ip, rec.dst_ip):
                continue

        window_id = int(rec.ts // window_seconds)
        buckets[(window_id, rec.src_ip, rec.dst_ip)].append(rec)

    windows: list[ExfilFlowWindow] = []

    for (window_id, src_ip, dst_ip), recs in sorted(buckets.items()):
        window_start = window_id * window_seconds
        window_end = window_start + window_seconds

        flow_count = len(recs)
        outbound_bytes = sum(r.orig_bytes or 0 for r in recs)
        inbound_bytes = sum(r.resp_bytes or 0 for r in recs)
        orig_pkts = sum(r.orig_pkts or 0 for r in recs)
        resp_pkts = sum(r.resp_pkts or 0 for r in recs)
        duration_sum = sum(r.duration or 0.0 for r in recs)

        byte_ratio = outbound_bytes / max(inbound_bytes, 1)

        windows.append(
            ExfilFlowWindow(
                window_start=window_start,
                window_end=window_end,
                source_ip=src_ip,
                destination_ip=dst_ip,
                flow_count=flow_count,
                outbound_bytes=outbound_bytes,
                inbound_bytes=inbound_bytes,
                orig_pkts=orig_pkts,
                resp_pkts=resp_pkts,
                byte_ratio=byte_ratio,
                duration_sum=duration_sum,
            )
        )

    return windows


# ---------------------------------------------------------------------------
# Per-Flow Canonical Feature Extraction (PS-26145 Shared Feature Layer)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FlowRecordFeatures:
    """Canonical behavioral flow features extracted from a single ConnRecord."""

    duration: float
    orig_bytes: int
    resp_bytes: int
    orig_pkts: int
    resp_pkts: int
    orig_ip_bytes: int
    resp_ip_bytes: int
    total_bytes: int
    total_pkts: int
    byte_rate: float
    packet_rate: float
    byte_ratio: float
    packet_ratio: float
    proto: str
    conn_state: str
    missed_bytes: int

    def to_dict(self) -> dict[str, Any]:
        """Serialize features to dictionary."""
        return {
            "duration": self.duration,
            "orig_bytes": self.orig_bytes,
            "resp_bytes": self.resp_bytes,
            "orig_pkts": self.orig_pkts,
            "resp_pkts": self.resp_pkts,
            "orig_ip_bytes": self.orig_ip_bytes,
            "resp_ip_bytes": self.resp_ip_bytes,
            "total_bytes": self.total_bytes,
            "total_pkts": self.total_pkts,
            "byte_rate": self.byte_rate,
            "packet_rate": self.packet_rate,
            "byte_ratio": self.byte_ratio,
            "packet_ratio": self.packet_ratio,
            "proto": self.proto,
            "conn_state": self.conn_state,
            "missed_bytes": self.missed_bytes,
        }


def extract_flow_features(record: ConnRecord) -> FlowRecordFeatures:
    """
    Extract canonical behavioral flow features from a single ConnRecord.

    Reuses validated feature mathematics (rates, directional ratios, byte aggregations)
    without leakage-prone identifiers (IPs, UIDs, timestamps, ports).
    """
    dur_raw = record.duration
    duration = (
        float(dur_raw)
        if (dur_raw is not None and not math.isnan(dur_raw) and not math.isinf(dur_raw) and dur_raw > 0.0)
        else 0.0
    )

    orig_b = int(record.orig_bytes or 0)
    resp_b = int(record.resp_bytes or 0)
    orig_p = int(record.orig_pkts or 0)
    resp_p = int(record.resp_pkts or 0)
    orig_ip_b = int(record.orig_ip_bytes or 0)
    resp_ip_b = int(record.resp_ip_bytes or 0)

    total_b = orig_ip_b + resp_ip_b
    total_p = orig_p + resp_p

    byte_rate = (total_b / max(duration, 0.001)) if duration > 0.0 else 0.0
    packet_rate = (total_p / max(duration, 0.001)) if duration > 0.0 else 0.0

    # Directional ratios (safe from ZeroDivisionError)
    byte_ratio = float(orig_ip_b) / float(max(resp_ip_b, 1))
    packet_ratio = float(orig_p) / float(max(resp_p, 1))

    proto = str(record.proto or "unknown").lower()
    conn_state = str(record.conn_state or "unknown").upper()
    missed = int(record.missed_bytes or 0)

    return FlowRecordFeatures(
        duration=duration,
        orig_bytes=orig_b,
        resp_bytes=resp_b,
        orig_pkts=orig_p,
        resp_pkts=resp_p,
        orig_ip_bytes=orig_ip_b,
        resp_ip_bytes=resp_ip_b,
        total_bytes=total_b,
        total_pkts=total_p,
        byte_rate=byte_rate,
        packet_rate=packet_rate,
        byte_ratio=byte_ratio,
        packet_ratio=packet_ratio,
        proto=proto,
        conn_state=conn_state,
        missed_bytes=missed,
    )


