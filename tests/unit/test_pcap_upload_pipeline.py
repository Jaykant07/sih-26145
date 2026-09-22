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
    delete_pcap_analysis,
    process_pcap_upload,
    validate_pcap_header,
)
from storage.sqlite_store import (
    get_alerts,
    get_kpi_summary,
    get_pcap_analyses,
    get_pcap_analysis_by_id,
    init_db,
    insert_alert,
)


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

        # 5. Verify non-canonical provenance tagging and pcap_id
        evidence = recon_alert.get("supporting_evidence", {})
        assert evidence.get("source_type") == "upload"
        assert evidence.get("canonical") is False
        assert evidence.get("upload_id") == result["upload_id"]
        assert recon_alert["pcap_id"] == result["pcap_id"]
        assert evidence.get("source_pcap") == "recon-001-tcp-port-scan.pcap"

        # Cleanup temporary uploaded artifacts after test
        shutil.rmtree(upload_dir, ignore_errors=True)

    def test_05_pcap_lifecycle_and_scoped_deletion(self, temp_db: Path) -> None:
        """
        Test 5: Full PCAP lifecycle: upload -> record creation -> pcap-scoped alerts -> deletion.
        Confirms delete removes only that PCAP and its artifacts while leaving others intact.
        """
        canonical_pcap = Path("data/raw/reconnaissance/recon-001-tcp-port-scan.pcap")
        result = process_pcap_upload(
            pcap_data=canonical_pcap,
            original_filename="recon-001-tcp-port-scan.pcap",
            db_path=temp_db,
        )

        pcap_id = result["pcap_id"]
        upload_dir = Path(result["upload_dir"])

        # 1. Verify pcap_analyses record created
        meta = get_pcap_analysis_by_id(pcap_id, temp_db)
        assert meta is not None
        assert meta["pcap_id"] == pcap_id
        assert meta["status"] == "completed"
        assert meta["filename"] == "recon-001-tcp-port-scan.pcap"
        assert meta["connections_count"] > 0
        assert meta["alerts_count"] == result["fused_alerts_count"]

        # 2. Verify pcap-scoped alerts retrieval
        pcap_alerts = get_alerts(temp_db, pcap_id=pcap_id)
        assert len(pcap_alerts) == result["fused_alerts_count"]
        for a in pcap_alerts:
            assert a["pcap_id"] == pcap_id

        # 3. Perform scoped deletion
        del_result = delete_pcap_analysis(pcap_id, db_path=temp_db)
        assert del_result["success"] is True
        assert del_result["deleted_alerts"] == result["fused_alerts_count"]
        assert del_result["deleted_analyses"] == 1

        # 4. Verify directory is deleted from filesystem
        assert not upload_dir.exists()

        # 5. Verify database records are deleted
        assert get_pcap_analysis_by_id(pcap_id, temp_db) is None
        assert len(get_alerts(temp_db, pcap_id=pcap_id)) == 0

    def test_06_overview_isolation(self, temp_db: Path) -> None:
        """
        Test 6: Overview isolation test.
        Seeded canonical demo alerts (pcap_id=None) must remain independent
        from uploaded PCAP alerts (pcap_id=<uuid>).
        """
        # Insert 1 canonical demo alert (pcap_id=None)
        canonical_demo_alert = {
            "alert_id": "demo-baseline-001",
            "timestamp": "2026-09-22T00:00:00Z",
            "flow_id": "flow-demo-1",
            "threat_class": "ddos",
            "severity": "critical",
            "confidence": 0.95,
            "source": "10.0.0.99",
            "destination": "10.0.0.1",
            "detector": "ddos_detector",
            "model_version": "1.0.0",
            "schema_version": "1.0.0",
            "supporting_evidence": {"canonical": True},
        }
        insert_alert(canonical_demo_alert, temp_db)

        # Overview query before upload
        overview_kpis_before = get_kpi_summary(temp_db, canonical_only=True)
        assert overview_kpis_before["total_alerts"] == 1

        # Ingest an uploaded PCAP
        canonical_pcap = Path("data/raw/reconnaissance/recon-001-tcp-port-scan.pcap")
        result = process_pcap_upload(
            pcap_data=canonical_pcap,
            original_filename="recon-001-tcp-port-scan.pcap",
            db_path=temp_db,
        )
        pcap_id = result["pcap_id"]

        # Overview query after upload: MUST STILL BE EXACTLY 1!
        overview_kpis_after = get_kpi_summary(temp_db, canonical_only=True)
        assert overview_kpis_after["total_alerts"] == 1, "Uploaded PCAP must NOT pollute canonical Overview!"

        overview_alerts = get_alerts(temp_db, canonical_only=True)
        assert len(overview_alerts) == 1
        assert overview_alerts[0]["alert_id"] == "demo-baseline-001"

        # PCAP page query: sees only its own alerts
        pcap_alerts = get_alerts(temp_db, pcap_id=pcap_id)
        assert len(pcap_alerts) == result["fused_alerts_count"]
        for a in pcap_alerts:
            assert a["pcap_id"] == pcap_id

        # Clean up
        delete_pcap_analysis(pcap_id, db_path=temp_db)

        # Overview still has its 1 demo alert
        assert get_kpi_summary(temp_db, canonical_only=True)["total_alerts"] == 1

    def test_07_multiple_pcaps_isolation(self, temp_db: Path) -> None:
        """
        Test 7: Multiple PCAPs isolation and deletion independence.
        PCAP A results belong only to A; PCAP B results belong only to B.
        Deleting B does not affect A.
        """
        recon_pcap = Path("data/raw/reconnaissance/recon-001-tcp-port-scan.pcap")
        scan_pcap = Path("data/pcap/scan_test.pcap")

        # Ingest PCAP A
        res_a = process_pcap_upload(pcap_data=recon_pcap, original_filename="recon-A.pcap", db_path=temp_db)
        id_a = res_a["pcap_id"]

        # Ingest PCAP B
        res_b = process_pcap_upload(pcap_data=scan_pcap, original_filename="scan-B.pcap", db_path=temp_db)
        id_b = res_b["pcap_id"]

        assert id_a != id_b

        # Verify A results belong only to A
        alerts_a = get_alerts(temp_db, pcap_id=id_a)
        assert len(alerts_a) == res_a["fused_alerts_count"]
        for a in alerts_a:
            assert a["pcap_id"] == id_a

        # Verify B results belong only to B
        alerts_b = get_alerts(temp_db, pcap_id=id_b)
        assert len(alerts_b) == res_b["fused_alerts_count"]
        for b in alerts_b:
            assert b["pcap_id"] == id_b

        # Delete B
        del_b = delete_pcap_analysis(id_b, db_path=temp_db)
        assert del_b["success"] is True

        # Verify B is gone, but A remains completely intact
        assert get_pcap_analysis_by_id(id_b, temp_db) is None
        assert len(get_alerts(temp_db, pcap_id=id_b)) == 0

        assert get_pcap_analysis_by_id(id_a, temp_db) is not None
        assert len(get_alerts(temp_db, pcap_id=id_a)) == res_a["fused_alerts_count"]

        # Clean up A
        delete_pcap_analysis(id_a, db_path=temp_db)

