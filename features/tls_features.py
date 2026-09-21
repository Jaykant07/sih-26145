"""
TLS Metadata Feature Extraction Layer for PS-26145 (Track B).

Joins Zeek ssl.log and conn.log on connection UID (ssl.uid == conn.uid),
extracts TLS handshake metadata (JA3, JA3S, cipher, version, server_name),
and computes connection-level behavioral features strictly from passive
layer-4 packet and byte counters.
Zero payload inspection or decryption is ever performed.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("tls_features")

EPSILON: float = 1e-6


def parse_zeek_json_lines(log_content: str) -> list[dict[str, Any]]:
    """
    Parse Zeek JSON log content into a list of record dictionaries.
    Skips comment lines (#), blank lines, and malformed JSON rows safely.
    """
    records: list[dict[str, Any]] = []
    for line in log_content.splitlines():
        line_str = line.strip()
        if not line_str or line_str.startswith("#"):
            continue
        try:
            rec = json.loads(line_str)
            if isinstance(rec, dict):
                records.append(rec)
        except json.JSONDecodeError:
            logger.debug("Skipping malformed JSON log line: %s", line_str[:60])
            continue
    return records


def parse_zeek_log_file(file_path: str | Path) -> list[dict[str, Any]]:
    """Read and parse a Zeek JSON log file."""
    p = Path(file_path)
    if not p.exists():
        logger.warning("Log file does not exist: %s", p)
        return []
    with open(p, "r", encoding="utf-8", errors="replace") as f:
        return parse_zeek_json_lines(f.read())


@dataclass(frozen=True)
class TLSFeatureRecord:
    """
    Feature record for a joined TLS session.
    Operates strictly on handshake metadata and connection-level flow counters.
    """

    uid: str
    timestamp: float
    source: str
    destination: str
    orig_port: int
    resp_port: int
    proto: str
    service: str
    version: str
    cipher: str
    server_name: str
    established: bool
    ja3: Optional[str]
    ja3s: Optional[str]
    ssl_history: str
    orig_bytes: int
    resp_bytes: int
    orig_pkts: int
    resp_pkts: int
    mean_packet_size: float
    byte_ratio: float
    packet_count: int
    duration: float

    def to_dict(self) -> dict[str, Any]:
        """Convert TLS feature record to dictionary."""
        return {
            "uid": self.uid,
            "timestamp": self.timestamp,
            "source": self.source,
            "destination": self.destination,
            "orig_port": self.orig_port,
            "resp_port": self.resp_port,
            "proto": self.proto,
            "service": self.service,
            "version": self.version,
            "cipher": self.cipher,
            "server_name": self.server_name,
            "established": self.established,
            "ja3": self.ja3,
            "ja3s": self.ja3s,
            "ssl_history": self.ssl_history,
            "orig_bytes": self.orig_bytes,
            "resp_bytes": self.resp_bytes,
            "orig_pkts": self.orig_pkts,
            "resp_pkts": self.resp_pkts,
            "mean_packet_size": self.mean_packet_size,
            "byte_ratio": self.byte_ratio,
            "packet_count": self.packet_count,
            "duration": self.duration,
        }


def extract_tls_connection_features(
    ssl_record: dict[str, Any],
    conn_record: dict[str, Any],
) -> dict[str, Any]:
    """
    Extract TLS metadata and compute behavioral features from joined records.

    Behavioral Features:
      1. mean_packet_size = (orig_bytes + resp_bytes) / max(orig_pkts + resp_pkts, 1)
      2. byte_ratio = orig_bytes / max(resp_bytes, EPSILON)
      3. packet_count = orig_pkts + resp_pkts
      4. duration = max(0.0, float(conn.duration or 0.0))
    """
    # Safe extraction of numeric counters
    try:
        orig_bytes = int(conn_record.get("orig_bytes") or 0)
    except (ValueError, TypeError):
        orig_bytes = 0

    try:
        resp_bytes = int(conn_record.get("resp_bytes") or 0)
    except (ValueError, TypeError):
        resp_bytes = 0

    try:
        orig_pkts = int(conn_record.get("orig_pkts") or 0)
    except (ValueError, TypeError):
        orig_pkts = 0

    try:
        resp_pkts = int(conn_record.get("resp_pkts") or 0)
    except (ValueError, TypeError):
        resp_pkts = 0

    try:
        duration = max(0.0, float(conn_record.get("duration") or 0.0))
    except (ValueError, TypeError):
        duration = 0.0

    total_bytes = orig_bytes + resp_bytes
    total_pkts = orig_pkts + resp_pkts

    # 1. Mean packet size
    mean_pkt_size = float(total_bytes) / float(max(total_pkts, 1))

    # 2. Byte ratio: originator upload vs responder download
    denominator = float(resp_bytes) if resp_bytes > 0 else EPSILON
    byte_ratio = float(orig_bytes) / denominator

    # 3. Packet count
    packet_count = total_pkts

    # 4. Duration
    conn_duration = duration

    # Extract source and destination endpoints
    src_ip = conn_record.get("id.orig_h") or ssl_record.get("id.orig_h") or "0.0.0.0"
    dst_ip = conn_record.get("id.resp_h") or ssl_record.get("id.resp_h") or "0.0.0.0"
    src_port = conn_record.get("id.orig_p") or ssl_record.get("id.orig_p") or 0
    dst_port = conn_record.get("id.resp_p") or ssl_record.get("id.resp_p") or 443

    uid = ssl_record.get("uid") or conn_record.get("uid") or ""

    return {
        "uid": uid,
        "timestamp": ssl_record.get("ts") or conn_record.get("ts") or 0.0,
        "source": str(src_ip),
        "destination": str(dst_ip),
        "orig_port": int(src_port),
        "resp_port": int(dst_port),
        "proto": conn_record.get("proto", "tcp"),
        "service": conn_record.get("service", "ssl"),
        # TLS Handshake Metadata
        "version": ssl_record.get("version", ""),
        "cipher": ssl_record.get("cipher", ""),
        "server_name": ssl_record.get("server_name", ""),
        "established": ssl_record.get("established", False),
        "ja3": ssl_record.get("ja3"),
        "ja3s": ssl_record.get("ja3s"),
        "ssl_history": ssl_record.get("ssl_history", ""),
        # Raw counters
        "orig_bytes": orig_bytes,
        "resp_bytes": resp_bytes,
        "orig_pkts": orig_pkts,
        "resp_pkts": resp_pkts,
        # Required Behavioral Features
        "mean_packet_size": round(mean_pkt_size, 4),
        "byte_ratio": round(byte_ratio, 4),
        "packet_count": packet_count,
        "duration": round(conn_duration, 4),
    }


def join_ssl_and_conn_records(
    ssl_records: list[dict[str, Any]],
    conn_records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Join ssl.log and conn.log records on exact connection UID:
        ssl.log.uid == conn.log.uid

    Handling constraints:
      - Records missing 'uid' are safely discarded.
      - Unmatched UIDs are ignored (join preserves only paired connections).
      - Duplicate UIDs are handled deterministically by preserving the first occurrence.
      - Never fabricates conn or ssl records when join fails.
    """
    # Index conn records by UID (first occurrence wins for duplicates)
    conn_by_uid: dict[str, dict[str, Any]] = {}
    for conn in conn_records:
        uid = conn.get("uid")
        if not uid or not isinstance(uid, str) or not uid.strip():
            continue
        uid_clean = uid.strip()
        if uid_clean not in conn_by_uid:
            conn_by_uid[uid_clean] = conn

    # Join against ssl records
    joined_features: list[dict[str, Any]] = []
    seen_ssl_uids: set[str] = set()

    for ssl in ssl_records:
        uid = ssl.get("uid")
        if not uid or not isinstance(uid, str) or not uid.strip():
            continue
        uid_clean = uid.strip()
        # Enforce deterministic deduplication on UID
        if uid_clean in seen_ssl_uids:
            continue
        seen_ssl_uids.add(uid_clean)

        conn = conn_by_uid.get(uid_clean)
        if conn is None:
            # Unmatched UID — do not fabricate a conn record
            logger.debug("Unmatched SSL UID: %s (no corresponding conn.log record)", uid_clean)
            continue

        feat = extract_tls_connection_features(ssl, conn)
        joined_features.append(feat)

    return joined_features


def extract_features_from_files(
    ssl_log_path: str | Path,
    conn_log_path: str | Path,
) -> list[dict[str, Any]]:
    """Load and join features directly from ssl.log and conn.log paths."""
    ssl_records = parse_zeek_log_file(ssl_log_path)
    conn_records = parse_zeek_log_file(conn_log_path)
    return join_ssl_and_conn_records(ssl_records, conn_records)


__all__ = [
    "EPSILON",
    "TLSFeatureRecord",
    "parse_zeek_json_lines",
    "parse_zeek_log_file",
    "extract_tls_connection_features",
    "join_ssl_and_conn_records",
    "extract_features_from_files",
]
