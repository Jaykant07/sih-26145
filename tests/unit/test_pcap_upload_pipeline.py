"""tests/unit/test_pcap_upload_pipeline.py
Unit and integration tests for the PCAP upload ingestion pipeline.

Verifies:
  1. Safe handling of empty file (0 bytes).
  2. Safe handling of non-PCAP file with .pcap extension.
  3. Safe handling of corrupted/truncated PCAP file.
  4. End-to-end ingestion of canonical recon-001-tcp-port-scan.pcap producing
     identical reconnaissance alerts as direct-file test path.
"""

from __future__ import annotations

import shutil
from pathlib import Path
import pytest

from alerts.constants import ThreatClass
from ingest.pcap_pipeline import (
    PCAPProcessingError,
    PCAPValidationError,
    process_pcap_upload,
    validate_pcap_header,
)
from storage.sqlite_store import get_alerts, init_db


@pytest.fixture
def temp_db(tmp_path: Path) -> Path:
    """Create an isolated test SQLite database."""
    db_file = tmp_path / "test_alerts.db"
    init_db(db_file)
    return db_file


class TestPCAPUploadPipeline:
    """Test suite for PCAP ingestion, input validation, and detector execution."""

    def test_01_empty_file_rejected(self, tmp_path: Path, temp_db: Path) -> None:
        """Test 1: Empty file (0 bytes) is rejected safely without database pollution."""
        empty_pcap = tmp_path / "empty_traffic.pcap"
        empty_pcap.write_bytes(b"")

        # Validation must fail with clear descriptive error
        with pytest.raises(PCAPValidationError) as exc_info:
            validate_pcap_header(empty_pcap)
        assert "empty" in str(exc_info.value).lower()

        # Ingestion pipeline must fail safely before touching database
        with pytest.raises(PCAPValidationError):
            process_pcap_upload(
                pcap_data=empty_pcap,
                original_filename="empty_traffic.pcap",
                db_path=temp_db,
            )

        # Database must have 0 alerts
        stored = get_alerts(temp_db)
        assert len(stored) == 0

    def test_02_non_pcap_file_rejected(self, tmp_path: Path, temp_db: Path) -> None:
        """Test 2: Non-PCAP text file with .pcap extension is rejected without DB corruption."""
        fake_pcap = tmp_path / "not_a_capture.pcap"
        fake_pcap.write_text("This is an ordinary text file pretending to be a pcap.\n[Log entry]\n")

        with pytest.raises(PCAPValidationError) as exc_info:
            validate_pcap_header(fake_pcap)
        assert "magic" in str(exc_info.value).lower() or "invalid pcap" in str(exc_info.value).lower()

        with pytest.raises(PCAPValidationError):
            process_pcap_upload(
                pcap_data=fake_pcap,
                original_filename="not_a_capture.pcap",
                db_path=temp_db,
            )

        stored = get_alerts(temp_db)
        assert len(stored) == 0

    def test_03_corrupted_truncated_pcap_rejected(self, tmp_path: Path, temp_db: Path) -> None:
        """Test 3: Truncated PCAP header (<24 bytes) is rejected safely."""
        corrupted_pcap = tmp_path / "corrupted_short.pcap"
        # Magic bytes for libpcap followed by incomplete header (only 8 bytes total)
        corrupted_pcap.write_bytes(b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00")

        with pytest.raises(PCAPValidationError) as exc_info:
            validate_pcap_header(corrupted_pcap)
        assert "corrupted" in str(exc_info.value).lower() or "less than standard header" in str(exc_info.value).lower()

        with pytest.raises(PCAPValidationError):
            process_pcap_upload(
                pcap_data=corrupted_pcap,
                original_filename="corrupted_short.pcap",
                db_path=temp_db,
            )

        stored = get_alerts(temp_db)
        assert len(stored) == 0

    def test_04_canonical_recon_pcap_end_to_end(self, temp_db: Path) -> None:
        """
        Test 4: End-to-end ingestion of canonical recon-001-tcp-port-scan.pcap.
        Confirms it produces the exact same reconnaissance alerts as direct-file test path.
        """
        canonical_pcap = Path("data/raw/reconnaissance/recon-001-tcp-port-scan.pcap")
        assert canonical_pcap.exists(), "Canonical recon-001 PCAP must exist in data/raw"

        progress_events = []

        def on_progress(stage: str, msg: str, pct: float) -> None:
            progress_events.append((stage, pct))

        result = process_pcap_upload(
            pcap_data=canonical_pcap,
            original_filename="recon-001-tcp-port-scan.pcap",
            db_path=temp_db,
            progress_callback=on_progress,
        )

        # 1. Pipeline success and progress check
        assert result["success"] is True
        assert len(progress_events) >= 5
        assert result["fused_alerts_count"] >= 1
        assert "reconnaissance" in result["threat_breakdown"]

        # 2. Upload isolation verification
        upload_dir = Path(result["upload_dir"])
        assert upload_dir.exists()
        assert (upload_dir / "metadata.json").exists()
        assert (upload_dir / "alerts.json").exists()
        assert (upload_dir / "zeek" / "notice.log").exists()

        # Clean isolation from canonical data
        assert "artifacts/uploads" in str(upload_dir)
        assert not str(upload_dir).startswith("data/raw")

        # 3. Database persistence verification
        stored_alerts = get_alerts(temp_db)
        assert len(stored_alerts) == result["fused_alerts_count"]

        # 4. Compare with canonical alert attributes
        recon_alert = next(a for a in stored_alerts if a["threat_class"] == ThreatClass.RECONNAISSANCE)
        assert recon_alert["source"] == "192.168.56.102"
        assert recon_alert["destination"] == "192.168.56.254"
        assert recon_alert["subtype"] == "port_scan"
        assert recon_alert["detector"] == "zeek_scan_adapter"

        # 5. Verify non-canonical provenance tagging
        evidence = recon_alert.get("supporting_evidence", {})
        assert evidence.get("source_type") == "upload"
        assert evidence.get("canonical") is False
        assert evidence.get("upload_id") == result["upload_id"]
        assert evidence.get("source_pcap") == "recon-001-tcp-port-scan.pcap"

        # Cleanup temporary uploaded artifacts after test
        shutil.rmtree(upload_dir, ignore_errors=True)
