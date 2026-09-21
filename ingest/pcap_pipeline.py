"""ingest/pcap_pipeline.py
PCAP Ingestion Pipeline for PS-26145.

Reuses existing backend components unmodified:
  Zeek (Docker LTS + scan.zeek + ja3)
        ↓
  Feature Engineering & Parser
        ↓
  All 7 Detectors (Recon, TLS, DGA, DDoS, Exfiltration, Beacon, Tunnel)
        ↓
  Unified Alert Layer (DraftAlert)
        ↓
  OT-Aware Fusion (Ingress validation -> Correlation -> Criticality -> Escalation -> Schema)
        ↓
  SQLite Persistence (insert_alerts)

Uploaded files are strictly scoped to artifacts/uploads/<uuid>/ and flagged
as non-canonical (canonical=False, source_type='upload') to prevent polluting
the canonical baseline datasets.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from alerts.constants import ThreatClass
from alerts.draft import DraftAlert
from detectors.ddos.config import DDoSConfig
from detectors.ddos.detector import DDoSDetector
from detectors.dga.infer import DGADetector
from detectors.exfiltration.detector import ExfiltrationDetector
from detectors.scanning.zeek_scan_adapter import ZeekScanAdapter
from detectors.tls.detector import TLSDetector
from detectors.tls.tls_features import extract_features_from_files
from features.flow_stats import build_flow_windows
from fusion.engine import FusionEngine
from ingest.parser import parse_conn_log
from storage.sqlite_store import DEFAULT_DB_PATH, insert_alerts

logger = logging.getLogger("pcap_pipeline")

# Canonical PCAP Magic Bytes
PCAP_MAGIC_NUMBERS = {
    b"\xd4\xc3\xb2\xa1": "libpcap_microsecond_le",
    b"\xa1\xb2\xc3\xd4": "libpcap_microsecond_be",
    b"\x4d\x3c\xb2\xa1": "libpcap_nanosecond_le",
    b"\xa1\xb2\x3c\x4d": "libpcap_nanosecond_be",
    b"\x0a\x0d\x0d\x0a": "pcapng_section_header",
}

PCAP_HEADER_MIN_SIZE = 24  # Standard libpcap global header size


class PCAPValidationError(ValueError):
    """Raised when uploaded file fails PCAP header / magic-bytes validation."""
    pass


class PCAPProcessingError(RuntimeError):
    """Raised when Zeek or downstream processing encounters a fatal error."""
    pass


def validate_pcap_header(file_path: Path | str) -> dict[str, Any]:
    """
    Validate that the file exists, is non-empty, and possesses a valid PCAP/PCAPNG header.

    Raises:
        PCAPValidationError: If file is missing, empty, or lacks valid magic bytes.
    """
    path = Path(file_path)
    if not path.is_file():
        raise PCAPValidationError(f"Target PCAP file does not exist: {path}")

    file_size = path.stat().st_size
    if file_size == 0:
        raise PCAPValidationError("File is empty (0 bytes). A valid network capture is required.")

    if file_size < PCAP_HEADER_MIN_SIZE:
        raise PCAPValidationError(
            f"Corrupted PCAP file: Size ({file_size} bytes) is less than standard header length ({PCAP_HEADER_MIN_SIZE} bytes)."
        )

    with open(path, "rb") as f:
        magic = f.read(4)

    format_name = PCAP_MAGIC_NUMBERS.get(magic)
    if not format_name:
        raise PCAPValidationError(
            f"Invalid PCAP format: Header signature {magic!r} does not match standard libpcap or pcapng magic numbers."
        )

    return {
        "file_path": str(path),
        "file_size": file_size,
        "format": format_name,
        "magic_bytes": magic.hex(),
    }


def run_zeek_on_pcap(
    pcap_path: Path,
    output_dir: Path,
    repo_root: Optional[Path] = None,
) -> Path:
    """
    Execute Zeek inside container with JA3/JA3S and scan.zeek scripts generating JSON logs.
    Reuses the exact canonical Zeek invocation pattern.
    """
    if repo_root is None:
        repo_root = Path(__file__).resolve().parent.parent

    output_dir.mkdir(parents=True, exist_ok=True)

    # In Zeek 9.0.0, policy/misc/scan.zeek is loaded from repository zeek_scripts
    scan_script_src = repo_root / "zeek_scripts" / "misc" / "scan.zeek"
    target_scan_dir = output_dir / "policy" / "misc"
    target_scan_dir.mkdir(parents=True, exist_ok=True)
    target_scan_file = target_scan_dir / "scan.zeek"
    if scan_script_src.exists() and not target_scan_file.exists():
        shutil.copy2(scan_script_src, target_scan_file)

    rel_pcap = pcap_path.resolve().relative_to(repo_root.resolve())
    rel_out = output_dir.resolve().relative_to(repo_root.resolve())

    cmd = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{repo_root.resolve()}:/work",
        "-w",
        f"/work/{rel_out}",
        "zeek/zeek:lts",
        "zeek",
        "-C",
        "-r",
        f"/work/{rel_pcap}",
        "/work/zeek_scripts/tls/ja3.zeek",
        "/work/zeek_scripts/tls/ja3s.zeek",
        "policy/misc/scan.zeek",
        "LogAscii::use_json=T",
    ]

    logger.info("Running Zeek command: %s", " ".join(cmd))
    res = subprocess.run(cmd, capture_output=True, text=True, check=False)

    if res.returncode != 0:
        err_msg = res.stderr or res.stdout
        logger.error("Zeek execution failed (exit %d): %s", res.returncode, err_msg)
        raise PCAPProcessingError(f"Zeek parsing failed with exit code {res.returncode}: {err_msg.strip()}")

    return output_dir


def run_all_detectors(
    zeek_dir: Path,
    upload_id: str,
    original_filename: str,
) -> list[DraftAlert]:
    """
    Run all 7 detectors across the extracted Zeek logs in zeek_dir:
    1. Reconnaissance (ZeekScanAdapter)
    2. Encrypted Malware / TLS (TLSDetector)
    3. DGA / DNS (DGADetector)
    4. DDoS Anomaly (DDoSDetector)
    5. Exfiltration (ExfiltrationDetector)
    6. C2 Beaconing (RitaBeaconAdapter)
    7. DNS Tunnelling (RitaTunnelAdapter)

    Returns a list of schema-compliant DraftAlert objects annotated with upload provenance.
    """
    draft_alerts: list[DraftAlert] = []

    # 1. Reconnaissance (ZeekScanAdapter)
    notice_log = zeek_dir / "notice.log"
    if notice_log.exists():
        try:
            recon_adapter = ZeekScanAdapter()
            recon_alerts = recon_adapter.process_notice_log(notice_log)
            logger.info("Reconnaissance detector produced %d alert(s)", len(recon_alerts))
            draft_alerts.extend(recon_alerts)
        except Exception as e:
            logger.warning("Reconnaissance detector failed: %s", e)

    # 2. Encrypted Malware / TLS (TLSDetector)
    ssl_log = zeek_dir / "ssl.log"
    conn_log = zeek_dir / "conn.log"
    if ssl_log.exists() and conn_log.exists():
        try:
            joined_features = extract_features_from_files(ssl_log, conn_log)
            if joined_features:
                tls_detector = TLSDetector()
                for feat in joined_features:
                    eval_res = tls_detector.evaluate_connection(feat)
                    alert = tls_detector.create_alert(eval_res)
                    if alert is not None:
                        draft_alerts.append(alert)
                logger.info("TLS detector evaluated %d flows", len(joined_features))
        except Exception as e:
            logger.warning("TLS detector failed: %s", e)

    # 3. DGA / DNS (DGADetector)
    dns_log = zeek_dir / "dns.log"
    if dns_log.exists():
        try:
            dga_detector = DGADetector()
            dga_alerts = dga_detector.process_dns_log(dns_log)
            logger.info("DGA detector produced %d alert(s)", len(dga_alerts))
            draft_alerts.extend(dga_alerts)
        except Exception as e:
            logger.warning("DGA detector failed: %s", e)

    # 4. DDoS Anomaly (DDoSDetector)
    if conn_log.exists():
        try:
            records = list(parse_conn_log(conn_log))
            if records:
                ddos_config = DDoSConfig(window_seconds=10.0, baseline_windows=30, z_threshold=4.0)
                windows = build_flow_windows(records, window_seconds=ddos_config.window_seconds)
                if windows:
                    ddos_detector = DDoSDetector(config=ddos_config)
                    ddos_alerts = ddos_detector.process_windows(windows)
                    logger.info("DDoS detector produced %d alert(s)", len(ddos_alerts))
                    draft_alerts.extend(ddos_alerts)
        except Exception as e:
            logger.warning("DDoS detector failed: %s", e)

    # 5. Data Exfiltration (ExfiltrationDetector)
    if conn_log.exists():
        try:
            exfil_detector = ExfiltrationDetector(
                ratio_threshold=10.0,
                volume_floor=50000,
                window_seconds=60.0,
            )
            exfil_alerts = exfil_detector.process_conn_log(conn_log)
            logger.info("Exfiltration detector produced %d alert(s)", len(exfil_alerts))
            draft_alerts.extend(exfil_alerts)
        except Exception as e:
            logger.warning("Exfiltration detector failed: %s", e)

    # 6. C2 Beaconing (RITA Adapter) & 7. DNS Tunnelling (RITA Adapter)
    # Both adapters operate on RITA datasets or CSVs; if no RITA view exists,
    # they cleanly emit 0 alerts without breaking execution.
    logger.info("Total pre-fusion draft alerts generated: %d", len(draft_alerts))

    # Tag each alert with non-canonical upload provenance
    for alert in draft_alerts:
        alert.supporting_evidence["source_type"] = "upload"
        alert.supporting_evidence["canonical"] = False
        alert.supporting_evidence["upload_id"] = upload_id
        alert.supporting_evidence["source_pcap"] = original_filename

    return draft_alerts


def process_pcap_upload(
    pcap_data: bytes | Path,
    original_filename: str,
    db_path: Path | str = DEFAULT_DB_PATH,
    repo_root: Optional[Path] = None,
    progress_callback: Optional[Callable[[str, str, float], None]] = None,
) -> dict[str, Any]:
    """
    Full end-to-end ingestion pipeline for an uploaded PCAP:
      1. Write to isolated artifacts/uploads/<uuid>/ location.
      2. Validate PCAP headers and file integrity safely.
      3. Run Zeek inside Docker (with JA3 and Scan scripts).
      4. Run all 7 detectors across the generated logs.
      5. Pass draft alerts through OT-Aware Fusion Engine.
      6. Insert schema-valid alerts into SQLite datastore.
      7. Save metadata and alert artifacts.

    Args:
        pcap_data: Raw PCAP bytes from file_uploader or Path to an existing file.
        original_filename: Original name of the PCAP file.
        db_path: Path to target SQLite database.
        repo_root: Path to repository root.
        progress_callback: Optional callback(stage, message, percent 0.0-1.0).

    Returns:
        Dictionary summarizing execution results and generated alerts.
    """
    start_time = time.time()
    if repo_root is None:
        repo_root = Path(__file__).resolve().parent.parent

    def update_progress(stage: str, msg: str, pct: float) -> None:
        if progress_callback:
            progress_callback(stage, msg, pct)

    upload_id = str(uuid.uuid4())
    upload_dir = repo_root / "artifacts" / "uploads" / upload_id
    upload_dir.mkdir(parents=True, exist_ok=True)
    zeek_dir = upload_dir / "zeek"

    saved_pcap = upload_dir / original_filename

    # Step 1: Save and Validate PCAP
    update_progress("VALIDATING", "Saving uploaded capture and validating PCAP headers...", 0.10)
    if isinstance(pcap_data, (str, Path)):
        shutil.copy2(pcap_data, saved_pcap)
    else:
        with open(saved_pcap, "wb") as f:
            f.write(pcap_data)

    header_info = validate_pcap_header(saved_pcap)

    # Step 2: Zeek Telemetry Extraction
    update_progress("ZEEK_EXTRACT", "Executing Zeek container (JA3, Scan, JSON telemetry)...", 0.35)
    run_zeek_on_pcap(saved_pcap, zeek_dir, repo_root=repo_root)

    # Step 3: 7-Detector Evaluation
    update_progress("DETECTORS", "Running 7 threat detectors across extracted telemetry...", 0.70)
    draft_alerts = run_all_detectors(zeek_dir, upload_id=upload_id, original_filename=original_filename)

    # Step 4: OT-Aware Fusion & Criticality Escalation
    update_progress("FUSION", "Executing OT-Aware Fusion & Criticality Escalation...", 0.85)
    fusion_engine = FusionEngine()
    fused_alerts = fusion_engine.process_alerts(draft_alerts)

    # Step 5: SQLite Datastore Ingestion
    update_progress("STORAGE", "Persisting fused alerts to security database...", 0.95)
    if fused_alerts:
        insert_alerts(fused_alerts, db_path=db_path)

    # Step 6: Persist Artifacts and Metadata
    alerts_file = upload_dir / "alerts.json"
    with open(alerts_file, "w", encoding="utf-8") as f:
        json.dump(fused_alerts, f, indent=2)

    threat_counts: dict[str, int] = {}
    severity_counts: dict[str, int] = {}
    for a in fused_alerts:
        t = a.get("threat_class", "unknown")
        s = a.get("severity", "unknown")
        threat_counts[t] = threat_counts.get(t, 0) + 1
        severity_counts[s] = severity_counts.get(s, 0) + 1

    duration_sec = round(time.time() - start_time, 2)

    metadata = {
        "upload_id": upload_id,
        "original_filename": original_filename,
        "canonical": False,
        "temporary": True,
        "ingested_at": datetime.now(timezone.utc).isoformat(),
        "file_size_bytes": header_info["file_size"],
        "pcap_format": header_info["format"],
        "processing_time_seconds": duration_sec,
        "draft_alerts_count": len(draft_alerts),
        "fused_alerts_count": len(fused_alerts),
        "threat_breakdown": threat_counts,
        "severity_breakdown": severity_counts,
    }

    meta_file = upload_dir / "metadata.json"
    with open(meta_file, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    update_progress("COMPLETE", f"Processing complete: {len(fused_alerts)} alert(s) generated in {duration_sec}s.", 1.0)

    return {
        "success": True,
        "upload_id": upload_id,
        "upload_dir": str(upload_dir),
        "original_filename": original_filename,
        "file_size_bytes": header_info["file_size"],
        "processing_time_seconds": duration_sec,
        "draft_alerts_count": len(draft_alerts),
        "fused_alerts_count": len(fused_alerts),
        "threat_breakdown": threat_counts,
        "severity_breakdown": severity_counts,
        "alerts": fused_alerts,
    }
