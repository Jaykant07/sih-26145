"""
Zeek conn.log JSON parser for PS-26145.

Minimal shared parser that reads Zeek JSON conn.log files and yields
typed ConnRecord objects. Handles missing optional fields safely.

Phase 11 placeholder — implemented minimally for Phase 16 (DDoS).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ConnRecord:
    """
    Single Zeek conn.log record with safe defaults for optional fields.

    Field availability verified against actual zeek_output/conn.log:
      100%:  ts, uid, id.orig_h/p, id.resp_h/p, proto, conn_state,
             orig_pkts, resp_pkts, orig_ip_bytes, resp_ip_bytes,
             missed_bytes, local_orig, local_resp
      98.6%: history
      90.6%: service
      45.1%: duration, orig_bytes, resp_bytes
    """

    # Always present (verified 100%)
    ts: float
    uid: str
    src_ip: str           # id.orig_h
    src_port: int         # id.orig_p
    dst_ip: str           # id.resp_h
    dst_port: int         # id.resp_p
    proto: str            # tcp / udp / icmp
    conn_state: str       # S0, SF, SHR, RSTR, OTH, etc.
    orig_pkts: int
    resp_pkts: int
    orig_ip_bytes: int    # Always present — primary byte metric
    resp_ip_bytes: int    # Always present — primary byte metric
    missed_bytes: int
    local_orig: bool
    local_resp: bool

    # Sometimes missing — must never be assumed present
    duration: Optional[float] = None      # 45.1%
    orig_bytes: Optional[int] = None      # 45.1%
    resp_bytes: Optional[int] = None      # 45.1%
    service: Optional[str] = None         # 90.6%
    history: Optional[str] = None         # 98.6%


def _safe_optional_float(raw: dict, key: str) -> Optional[float]:
    """Extract an optional float field, returning None if absent, null, or unset."""
    val = raw.get(key)
    if val is None or val == "-" or val == "(empty)":
        return None
    return float(val)


def _safe_optional_int(raw: dict, key: str) -> Optional[int]:
    """Extract an optional int field, returning None if absent, null, or unset."""
    val = raw.get(key)
    if val is None or val == "-" or val == "(empty)":
        return None
    return int(val)


def _safe_optional_str(raw: dict, key: str) -> Optional[str]:
    """Extract an optional string field, returning None if absent, null, or unset."""
    val = raw.get(key)
    if val is None or val == "-" or val == "(empty)":
        return None
    return str(val)


def _parse_record(raw: dict) -> ConnRecord:
    """Parse a single dict into a ConnRecord.

    Raises KeyError or ValueError for missing/malformed required fields.
    """
    return ConnRecord(
        ts=float(raw["ts"]),
        uid=str(raw["uid"]),
        src_ip=str(raw["id.orig_h"]),
        src_port=int(raw["id.orig_p"]),
        dst_ip=str(raw["id.resp_h"]),
        dst_port=int(raw["id.resp_p"]),
        proto=str(raw.get("proto", "unknown")),
        conn_state=str(raw.get("conn_state", "")),
        orig_pkts=int(raw.get("orig_pkts", 0) or 0),
        resp_pkts=int(raw.get("resp_pkts", 0) or 0),
        orig_ip_bytes=int(raw.get("orig_ip_bytes", 0) or 0),
        resp_ip_bytes=int(raw.get("resp_ip_bytes", 0) or 0),
        missed_bytes=int(raw.get("missed_bytes", 0) or 0),
        local_orig=bool(raw.get("local_orig", False) in (True, "T", "true", "True", 1)),
        local_resp=bool(raw.get("local_resp", False) in (True, "T", "true", "True", 1)),
        duration=_safe_optional_float(raw, "duration"),
        orig_bytes=_safe_optional_int(raw, "orig_bytes"),
        resp_bytes=_safe_optional_int(raw, "resp_bytes"),
        service=_safe_optional_str(raw, "service"),
        history=_safe_optional_str(raw, "history"),
    )


def parse_conn_log(path: str | Path) -> Iterator[ConnRecord]:
    """
    Parse a Zeek conn.log (supports both JSON format and standard Zeek TSV format).

    Yields ConnRecord objects. Skips malformed lines with a warning log.

    Args:
        path: Path to the Zeek conn.log file.

    Yields:
        ConnRecord for each valid log line.
    """
    path = Path(path)
    line_num = 0
    tsv_fields: list[str] = []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line_num += 1
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("#"):
                if stripped.startswith("#fields\t"):
                    tsv_fields = stripped.split("\t")[1:]
                elif stripped.startswith("#fields "):
                    tsv_fields = stripped.split()[1:]
                continue
            try:
                if stripped.startswith("{"):
                    raw = json.loads(stripped)
                elif tsv_fields:
                    parts = stripped.split("\t")
                    if len(parts) == len(tsv_fields):
                        raw = {k: None if v == "-" else v for k, v in zip(tsv_fields, parts)}
                    else:
                        continue
                else:
                    continue
                yield _parse_record(raw)
            except (json.JSONDecodeError, KeyError, ValueError, TypeError) as exc:
                logger.warning(
                    "Skipping malformed line %d in %s: %s", line_num, path, exc
                )
                continue
