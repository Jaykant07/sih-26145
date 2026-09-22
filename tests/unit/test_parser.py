"""Unit tests for ingest.parser — Zeek conn.log JSON parser."""

import json
import tempfile
from pathlib import Path

import pytest

from ingest.parser import ConnRecord, parse_conn_log


def _write_log(lines: list[str], tmp_path: Path) -> Path:
    """Write lines to a temporary conn.log file."""
    p = tmp_path / "conn.log"
    p.write_text("\n".join(lines) + "\n")
    return p


# -- Valid record fixtures ---------------------------------------------------

FULL_RECORD = {
    "ts": 1739882511.578,
    "uid": "CJKKw14fBdqjscVcd3",
    "id.orig_h": "172.16.0.51",
    "id.orig_p": 52124,
    "id.resp_h": "172.16.0.81",
    "id.resp_p": 443,
    "proto": "tcp",
    "service": "ssl",
    "duration": 0.001195,
    "orig_bytes": 212,
    "resp_bytes": 0,
    "conn_state": "RSTR",
    "local_orig": True,
    "local_resp": True,
    "missed_bytes": 0,
    "history": "ShADr",
    "orig_pkts": 3,
    "orig_ip_bytes": 344,
    "resp_pkts": 2,
    "resp_ip_bytes": 92,
}

MINIMAL_RECORD = {
    "ts": 1739882511.578,
    "uid": "C123",
    "id.orig_h": "10.0.0.1",
    "id.orig_p": 12345,
    "id.resp_h": "10.0.0.2",
    "id.resp_p": 80,
    "proto": "tcp",
    "conn_state": "S0",
    "orig_pkts": 1,
    "orig_ip_bytes": 60,
    "resp_pkts": 0,
    "resp_ip_bytes": 0,
    "missed_bytes": 0,
    "local_orig": True,
    "local_resp": True,
    # duration, orig_bytes, resp_bytes, service, history all missing
}


class TestConnRecordParsing:
    """Test ConnRecord creation from JSON dicts."""

    def test_full_record_parses_correctly(self, tmp_path: Path) -> None:
        p = _write_log([json.dumps(FULL_RECORD)], tmp_path)
        records = list(parse_conn_log(p))
        assert len(records) == 1
        r = records[0]
        assert r.ts == pytest.approx(1739882511.578)
        assert r.src_ip == "172.16.0.51"
        assert r.dst_ip == "172.16.0.81"
        assert r.dst_port == 443
        assert r.proto == "tcp"
        assert r.conn_state == "RSTR"
        assert r.orig_pkts == 3
        assert r.resp_pkts == 2
        assert r.orig_ip_bytes == 344
        assert r.resp_ip_bytes == 92
        assert r.duration == pytest.approx(0.001195)
        assert r.service == "ssl"
        assert r.history == "ShADr"

    def test_minimal_record_missing_optional_fields(self, tmp_path: Path) -> None:
        """Missing optional fields should default to None."""
        p = _write_log([json.dumps(MINIMAL_RECORD)], tmp_path)
        records = list(parse_conn_log(p))
        assert len(records) == 1
        r = records[0]
        assert r.duration is None
        assert r.orig_bytes is None
        assert r.resp_bytes is None
        assert r.service is None
        assert r.history is None
        assert r.src_ip == "10.0.0.1"
        assert r.orig_pkts == 1

    def test_malformed_json_skipped(self, tmp_path: Path) -> None:
        """Malformed lines should be skipped, not crash."""
        lines = [
            json.dumps(FULL_RECORD),
            "THIS IS NOT JSON",
            json.dumps(MINIMAL_RECORD),
        ]
        p = _write_log(lines, tmp_path)
        records = list(parse_conn_log(p))
        assert len(records) == 2

    def test_empty_lines_and_comments_skipped(self, tmp_path: Path) -> None:
        lines = [
            "",
            "# This is a comment",
            json.dumps(FULL_RECORD),
            "   ",
        ]
        p = _write_log(lines, tmp_path)
        records = list(parse_conn_log(p))
        assert len(records) == 1

    def test_missing_required_field_skips_line(self, tmp_path: Path) -> None:
        """Missing a required field (e.g. ts) should skip the line."""
        bad_record = dict(FULL_RECORD)
        del bad_record["ts"]
        p = _write_log([json.dumps(bad_record)], tmp_path)
        records = list(parse_conn_log(p))
        assert len(records) == 0

    def test_null_optional_fields_handled(self, tmp_path: Path) -> None:
        """Explicit null values for optional fields should map to None."""
        record = dict(FULL_RECORD)
        record["duration"] = None
        record["service"] = None
        record["history"] = None
        p = _write_log([json.dumps(record)], tmp_path)
        records = list(parse_conn_log(p))
        assert len(records) == 1
        r = records[0]
        assert r.duration is None
        assert r.service is None
        assert r.history is None

    def test_empty_file(self, tmp_path: Path) -> None:
        p = tmp_path / "empty.log"
        p.write_text("")
        assert list(parse_conn_log(p)) == []

    def test_tsv_zeek_format_parsed(self, tmp_path: Path) -> None:
        """Standard Zeek tab-delimited conn.log is parsed correctly."""
        lines = [
            "#separator \\x09",
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes",
            "1789640570.35\tCtest123\t192.168.56.102\t33740\t192.168.56.254\t5201\ttcp\t-\t30.39\t1000\t500\tSF\tT\tT\t0\tShADa\t15\t1500\t12\t1200",
        ]
        p = _write_log(lines, tmp_path)
        records = list(parse_conn_log(p))
        assert len(records) == 1
        r = records[0]
        assert r.uid == "Ctest123"
        assert r.src_ip == "192.168.56.102"
        assert r.dst_port == 5201
        assert r.service is None  # '-' converted to None
        assert r.duration == pytest.approx(30.39)
        assert r.orig_bytes == 1000
        assert r.conn_state == "SF"
        assert r.local_orig is True

