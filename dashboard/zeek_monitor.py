"""dashboard/zeek_monitor.py
Zeek log file reader for live traffic monitoring.

Reads existing Zeek JSON log files and computes traffic metrics.
Does NOT start Zeek, inject packets, or generate any traffic.
All values come from actual log data.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Default paths to check for Zeek logs
DEFAULT_ZEEK_LOG_DIRS: list[Path] = [
    Path("/opt/zeek/logs/current"),
    Path("zeek_output"),
    Path("data/zeek_logs"),
]


@dataclass
class ZeekLogStatus:
    """Status of Zeek log availability."""
    available: bool = False
    log_dir: Optional[Path] = None
    mode: str = "offline"  # 'live' or 'recorded' or 'offline'
    conn_log: bool = False
    dns_log: bool = False
    ssl_log: bool = False
    status_message: str = "Not configured"


@dataclass
class TrafficMetrics:
    """Computed traffic metrics from Zeek logs."""
    total_connections: int = 0
    total_packets: int = 0
    total_bytes: int = 0
    active_hosts: int = 0
    dns_queries: int = 0
    tls_sessions: int = 0
    protocols: dict[str, int] = field(default_factory=dict)
    top_sources: list[dict[str, Any]] = field(default_factory=list)
    top_destinations: list[dict[str, Any]] = field(default_factory=list)
    recent_connections: list[dict[str, Any]] = field(default_factory=list)
    timeseries: list[dict[str, Any]] = field(default_factory=list)


def find_zeek_log_dir() -> ZeekLogStatus:
    """Discover available Zeek log directory."""
    status = ZeekLogStatus()

    for log_dir in DEFAULT_ZEEK_LOG_DIRS:
        resolved = Path(log_dir)
        if not resolved.is_dir():
            continue

        conn_exists = (resolved / "conn.log").is_file()
        dns_exists = (resolved / "dns.log").is_file()
        ssl_exists = (resolved / "ssl.log").is_file()

        if conn_exists or dns_exists or ssl_exists:
            status.available = True
            status.log_dir = resolved
            status.conn_log = conn_exists
            status.dns_log = dns_exists
            status.ssl_log = ssl_exists

            # Check if this looks like a live Zeek instance
            if str(resolved).startswith("/opt/zeek"):
                status.mode = "live"
                status.status_message = f"Live Zeek logs at {resolved}"
            else:
                status.mode = "recorded"
                status.status_message = f"Recorded Zeek logs at {resolved}"
            break

    if not status.available:
        status.status_message = "No Zeek log directory found"

    return status


def _read_json_log(log_path: Path, max_lines: int = 5000) -> list[dict[str, Any]]:
    """Read a Zeek JSON log file, returning parsed records."""
    records: list[dict[str, Any]] = []
    if not log_path.is_file():
        return records

    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f):
                if i >= max_lines:
                    break
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        logger.warning("Failed to read Zeek log %s: %s", log_path, e)

    return records


def compute_traffic_metrics(log_dir: Path, max_lines: int = 5000) -> TrafficMetrics:
    """Compute traffic metrics from Zeek log files in the given directory."""
    metrics = TrafficMetrics()

    # --- conn.log ---
    conn_path = log_dir / "conn.log"
    conn_records = _read_json_log(conn_path, max_lines)

    if conn_records:
        all_hosts: set[str] = set()
        source_bytes: dict[str, int] = {}
        source_conns: dict[str, int] = {}
        dest_bytes: dict[str, int] = {}
        dest_conns: dict[str, int] = {}
        proto_counts: dict[str, int] = {}
        ts_buckets: dict[int, int] = {}  # epoch_second -> byte_count

        for rec in conn_records:
            orig_h = rec.get("id.orig_h", "")
            resp_h = rec.get("id.resp_h", "")
            proto = rec.get("proto", "unknown").upper()
            service = rec.get("service", "")
            orig_bytes = int(rec.get("orig_bytes") or 0)
            resp_bytes = int(rec.get("resp_bytes") or 0)
            orig_pkts = int(rec.get("orig_pkts") or 0)
            resp_pkts = int(rec.get("resp_pkts") or 0)
            ts = rec.get("ts", 0)

            total_bytes = orig_bytes + resp_bytes
            total_pkts = orig_pkts + resp_pkts

            metrics.total_connections += 1
            metrics.total_packets += total_pkts
            metrics.total_bytes += total_bytes

            if orig_h:
                all_hosts.add(orig_h)
                source_bytes[orig_h] = source_bytes.get(orig_h, 0) + total_bytes
                source_conns[orig_h] = source_conns.get(orig_h, 0) + 1
            if resp_h:
                all_hosts.add(resp_h)
                dest_bytes[resp_h] = dest_bytes.get(resp_h, 0) + total_bytes
                dest_conns[resp_h] = dest_conns.get(resp_h, 0) + 1

            # Protocol counting: prefer service if available
            proto_label = service.upper() if service else proto
            proto_counts[proto_label] = proto_counts.get(proto_label, 0) + 1

            # Timeseries bucketing (10-second buckets)
            if ts:
                bucket = int(float(ts)) // 10 * 10
                ts_buckets[bucket] = ts_buckets.get(bucket, 0) + total_bytes

        metrics.active_hosts = len(all_hosts)
        metrics.protocols = dict(sorted(proto_counts.items(), key=lambda x: -x[1]))

        # Top sources (by connection count)
        metrics.top_sources = [
            {"ip": ip, "connections": source_conns[ip], "bytes": source_bytes.get(ip, 0)}
            for ip in sorted(source_conns, key=lambda x: -source_conns[x])[:10]
        ]

        # Top destinations (by connection count)
        metrics.top_destinations = [
            {"ip": ip, "connections": dest_conns[ip], "bytes": dest_bytes.get(ip, 0)}
            for ip in sorted(dest_conns, key=lambda x: -dest_conns[x])[:10]
        ]

        # Recent connections (last 20)
        recent = sorted(conn_records, key=lambda x: float(x.get("ts", 0)), reverse=True)[:20]
        for rec in recent:
            from datetime import datetime, timezone
            ts_val = float(rec.get("ts", 0))
            ts_str = datetime.fromtimestamp(ts_val, tz=timezone.utc).strftime("%H:%M:%S") if ts_val else "N/A"
            metrics.recent_connections.append({
                "time": ts_str,
                "source": rec.get("id.orig_h", ""),
                "destination": rec.get("id.resp_h", ""),
                "protocol": (rec.get("service") or rec.get("proto", "")).upper(),
                "port": rec.get("id.resp_p", ""),
                "bytes": int(rec.get("orig_bytes") or 0) + int(rec.get("resp_bytes") or 0),
            })

        # Timeseries
        if ts_buckets:
            from datetime import datetime, timezone
            for bucket_ts in sorted(ts_buckets.keys()):
                ts_str = datetime.fromtimestamp(bucket_ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
                metrics.timeseries.append({
                    "timestamp": ts_str,
                    "bytes_per_interval": ts_buckets[bucket_ts],
                })

    # --- dns.log ---
    dns_path = log_dir / "dns.log"
    dns_records = _read_json_log(dns_path, max_lines)
    metrics.dns_queries = len(dns_records)
    if dns_records and "DNS" not in metrics.protocols:
        metrics.protocols["DNS"] = metrics.protocols.get("DNS", 0) + len(dns_records)

    # --- ssl.log ---
    ssl_path = log_dir / "ssl.log"
    ssl_records = _read_json_log(ssl_path, max_lines)
    metrics.tls_sessions = len(ssl_records)

    return metrics
