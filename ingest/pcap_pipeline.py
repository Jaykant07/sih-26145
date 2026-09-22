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
from storage.sqlite_store import (
    DEFAULT_DB_PATH,
    delete_pcap_analysis_records,
    insert_alerts,
    insert_pcap_analysis,
    update_pcap_analysis,
)

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


def extract_zeek_stats(zeek_dir: Path) -> dict[str, int]:
    """Extract standard telemetry metrics from extracted Zeek logs."""
    stats = {
        "connections_count": 0,
        "dns_queries_count": 0,
        "tls_sessions_count": 0,
        "unique_hosts_count": 0,
        "packets_count": 0,
    }
    conn_file = zeek_dir / "conn.log"
    unique_hosts = set()
    if conn_file.exists():
        with open(conn_file, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.startswith("#"):
                    continue
                stats["connections_count"] += 1
                try:
                    row = json.loads(line)
                    orig = row.get("id.orig_h")
                    resp = row.get("id.resp_h")
                    if orig:
                        unique_hosts.add(orig)
                    if resp:
                        unique_hosts.add(resp)
                    stats["packets_count"] += (row.get("orig_pkts") or 0) + (row.get("resp_pkts") or 0)
                except Exception:
                    pass
    stats["unique_hosts_count"] = len(unique_hosts)

    dns_file = zeek_dir / "dns.log"
    if dns_file.exists():
        with open(dns_file, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if not line.startswith("#"):
                    stats["dns_queries_count"] += 1

    ssl_file = zeek_dir / "ssl.log"
    if ssl_file.exists():
        with open(ssl_file, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if not line.startswith("#"):
                    stats["tls_sessions_count"] += 1

    return stats


def run_all_detectors(
    zeek_dir: Path,
    upload_id: str,
    original_filename: str,
) -> tuple[list[DraftAlert], dict[str, Any]]:
    """
    Run all 7 detectors across the extracted Zeek logs in zeek_dir:
    1. Reconnaissance (ZeekScanAdapter)
    2. Encrypted Malware / TLS (TLSDetector)
    3. DGA / DNS (DGADetector)
    4. DDoS Anomaly (DDoSDetector)
    5. Exfiltration (ExfiltrationDetector)
    6. C2 Beaconing (RitaBeaconAdapter)
    7. DNS Tunnelling (RitaTunnelAdapter)

    Returns a tuple of (draft_alerts, detector_summaries).
    """
    draft_alerts: list[DraftAlert] = []
    pcap_id = upload_id

    recon_count = 0
    tls_count = 0
    dga_count = 0
    ddos_count = 0
    exfil_count = 0
    beacon_count = 0
    tunnel_count = 0

    # 1. Reconnaissance (ZeekScanAdapter)
    notice_log = zeek_dir / "notice.log"
    if notice_log.exists():
        try:
            recon_adapter = ZeekScanAdapter()
            recon_alerts = recon_adapter.process_notice_log(notice_log)
            recon_count = len(recon_alerts)
            logger.info("Reconnaissance detector produced %d alert(s)", recon_count)
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
                        tls_count += 1
                logger.info("TLS detector evaluated %d flows, produced %d alert(s)", len(joined_features), tls_count)
        except Exception as e:
            logger.warning("TLS detector failed: %s", e)

    # 3. DGA / DNS (DGADetector)
    dns_log = zeek_dir / "dns.log"
    if dns_log.exists():
        try:
            dga_detector = DGADetector()
            dga_alerts = dga_detector.process_dns_log(dns_log)
            dga_count = len(dga_alerts)
            logger.info("DGA detector produced %d alert(s)", dga_count)
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
                    ddos_count = len(ddos_alerts)
                    logger.info("DDoS detector produced %d alert(s)", ddos_count)
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
            exfil_count = len(exfil_alerts)
            logger.info("Exfiltration detector produced %d alert(s)", exfil_count)
            draft_alerts.extend(exfil_alerts)
        except Exception as e:
            logger.warning("Exfiltration detector failed: %s", e)

    # 8. AI Behavioral Anomaly (Isolation Forest)
    anomaly_count = 0
    if conn_log.exists():
        try:
            from detectors.anomaly import get_anomaly_detector
            anomaly_detector = get_anomaly_detector()
            conn_records = list(parse_conn_log(conn_log))

            anomaly_alerts = anomaly_detector.predict(conn_records, pcap_id=pcap_id)
            anomaly_count = len(anomaly_alerts)
            logger.info("AI Anomaly detector produced %d alert(s)", anomaly_count)
            draft_alerts.extend(anomaly_alerts)
        except Exception as e:
            logger.warning("AI Anomaly detector failed: %s", e)

    logger.info("Total pre-fusion draft alerts generated: %d", len(draft_alerts))

    # Tag each alert with non-canonical upload provenance and pcap_id
    for alert in draft_alerts:
        alert.supporting_evidence["source_type"] = "upload"
        alert.supporting_evidence["canonical"] = False
        alert.supporting_evidence["upload_id"] = pcap_id
        alert.supporting_evidence["pcap_id"] = pcap_id
        alert.supporting_evidence["source_pcap"] = original_filename

    detector_summaries: dict[str, dict[str, Any]] = {
        "ddos": {
            "name": "DDoS",
            "engine": "Custom detector",
            "status": "triggered" if ddos_count > 0 else "clear",
            "alerts_count": ddos_count,
            "description": "Volumetric anomaly & SYN/UDP flood detection",
        },
        "reconnaissance": {
            "name": "Reconnaissance",
            "engine": "Zeek Scan",
            "status": "triggered" if recon_count > 0 else "clear",
            "alerts_count": recon_count,
            "description": "Port scan & address sweep heuristics via notice.log",
        },
        "dga": {
            "name": "DGA / DNS",
            "engine": "Random Forest",
            "status": "triggered" if dga_count > 0 else "clear",
            "alerts_count": dga_count,
            "description": "Domain Generation Algorithm query inference",
        },
        "dns_tunnel": {
            "name": "DNS Tunnelling",
            "engine": "RITA",
            "status": "triggered" if tunnel_count > 0 else "clear",
            "alerts_count": tunnel_count,
            "description": "Covert channel & exfiltration via DNS queries",
        },
        "beaconing": {
            "name": "C2 Beaconing",
            "engine": "RITA",
            "status": "triggered" if beacon_count > 0 else "clear",
            "alerts_count": beacon_count,
            "description": "Periodic command & control connection intervals",
        },
        "tls_anomaly": {
            "name": "Encrypted Malware / TLS",
            "engine": "JA3 + behavioral",
            "status": "triggered" if tls_count > 0 else "clear",
            "alerts_count": tls_count,
            "description": "Suspicious JA3 fingerprints & asymmetric flow ratios",
        },
        "exfiltration": {
            "name": "Exfiltration",
            "engine": "Custom detector",
            "status": "triggered" if exfil_count > 0 else "clear",
            "alerts_count": exfil_count,
            "description": "Outbound/inbound data transfer asymmetry detection",
        },
        "anomalous_behavior": {
            "name": "AI Behavioral Anomaly",
            "engine": "Isolation Forest",
            "status": "triggered" if anomaly_count > 0 else "clear",
            "alerts_count": anomaly_count,
            "description": "Unsupervised flow-level behavioral outlier detection",
        },
    }

    return draft_alerts, detector_summaries


def process_pcap_upload(
    pcap_data: bytes | Path,
    original_filename: str,
    db_path: Path | str = DEFAULT_DB_PATH,
    repo_root: Optional[Path] = None,
    progress_callback: Optional[Callable[[str, str, float], None]] = None,
) -> dict[str, Any]:
    """
    Full end-to-end ingestion pipeline for an uploaded PCAP:
      1. Write to isolated artifacts/uploads/<pcap_id>/ location.
      2. Validate PCAP headers and file integrity safely.
      3. Run Zeek inside Docker (with JA3 and Scan scripts).
      4. Run all 7 detectors across the generated logs.
      5. Pass draft alerts through OT-Aware Fusion Engine.
      6. Insert schema-valid alerts into SQLite datastore scoped to pcap_id.
      7. Save metadata and alert artifacts.

    Returns:
        Dictionary summarizing execution results, detector results, and generated alerts.
    """
    start_time = time.time()
    start_iso = datetime.now(timezone.utc).isoformat()
    if repo_root is None:
        repo_root = Path(__file__).resolve().parent.parent

    def update_progress(stage: str, msg: str, pct: float) -> None:
        if progress_callback:
            progress_callback(stage, msg, pct)

    pcap_id = str(uuid.uuid4())
    upload_dir = repo_root / "artifacts" / "uploads" / pcap_id
    upload_dir.mkdir(parents=True, exist_ok=True)
    zeek_dir = upload_dir / "zeek"

    saved_pcap = upload_dir / original_filename

    # Step 1: Save and Validate PCAP
    update_progress("VALIDATING", "Saving uploaded capture and validating PCAP headers...", 0.10)
    try:
        if isinstance(pcap_data, (str, Path)):
            shutil.copy2(pcap_data, saved_pcap)
        else:
            with open(saved_pcap, "wb") as f:
                f.write(pcap_data)

        header_info = validate_pcap_header(saved_pcap)
    except Exception as ve:
        # If validation fails, clean up the temporary directory to avoid leaving corrupted artifacts
        shutil.rmtree(upload_dir, ignore_errors=True)
        raise

    # Initialize tracking record in pcap_analyses table
    pcap_record = {
        "pcap_id": pcap_id,
        "filename": original_filename,
        "file_size_bytes": header_info["file_size"],
        "pcap_format": header_info["format"],
        "upload_timestamp": start_iso,
        "analysis_start_time": start_iso,
        "status": "processing",
        "artifact_dir": str(upload_dir),
    }
    insert_pcap_analysis(pcap_record, db_path=db_path)

    try:
        # Step 2: Zeek Telemetry Extraction
        update_progress("ZEEK_EXTRACT", "Executing Zeek container (JA3, Scan, JSON telemetry)...", 0.30)
        run_zeek_on_pcap(saved_pcap, zeek_dir, repo_root=repo_root)

        # Step 3: Extract Zeek Telemetry Metrics
        update_progress("FEATURE_EXTRACT", "Parsing protocol telemetry and extracting network features...", 0.50)
        zeek_stats = extract_zeek_stats(zeek_dir)

        # Step 4: 7-Detector Evaluation
        update_progress("DETECTORS", "Running 7 threat detectors across extracted telemetry...", 0.70)
        draft_alerts, detector_summaries = run_all_detectors(zeek_dir, upload_id=pcap_id, original_filename=original_filename)

        # Step 5: OT-Aware Fusion & Criticality Escalation
        update_progress("FUSION", "Executing OT-Aware Fusion & Criticality Escalation...", 0.85)
        fusion_engine = FusionEngine()
        fused_alerts = fusion_engine.process_alerts(draft_alerts)

        # Ensure all fused alerts carry pcap_id
        for a in fused_alerts:
            a["pcap_id"] = pcap_id
            if "supporting_evidence" in a and isinstance(a["supporting_evidence"], dict):
                a["supporting_evidence"]["pcap_id"] = pcap_id
                a["supporting_evidence"]["upload_id"] = pcap_id

        # Step 6: SQLite Datastore Ingestion (Scoped to pcap_id)
        update_progress("STORAGE", "Persisting scoped alerts to security database...", 0.95)
        if fused_alerts:
            insert_alerts(fused_alerts, db_path=db_path, pcap_id=pcap_id)

        # Step 7: Persist Artifacts and Metadata
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
        end_iso = datetime.now(timezone.utc).isoformat()

        metadata = {
            "pcap_id": pcap_id,
            "upload_id": pcap_id,
            "original_filename": original_filename,
            "canonical": False,
            "temporary": True,
            "ingested_at": start_iso,
            "analysis_end_time": end_iso,
            "file_size_bytes": header_info["file_size"],
            "pcap_format": header_info["format"],
            "processing_time_seconds": duration_sec,
            "draft_alerts_count": len(draft_alerts),
            "fused_alerts_count": len(fused_alerts),
            "threat_breakdown": threat_counts,
            "severity_breakdown": severity_counts,
            "telemetry_stats": zeek_stats,
            "detector_results": detector_summaries,
        }

        meta_file = upload_dir / "metadata.json"
        with open(meta_file, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)

        # Update database session record to completed
        update_pcap_analysis(
            pcap_id,
            {
                "status": "completed",
                "analysis_end_time": end_iso,
                "duration_seconds": duration_sec,
                "connections_count": zeek_stats["connections_count"],
                "dns_queries_count": zeek_stats["dns_queries_count"],
                "tls_sessions_count": zeek_stats["tls_sessions_count"],
                "unique_hosts_count": zeek_stats["unique_hosts_count"],
                "packets_count": zeek_stats["packets_count"],
                "alerts_count": len(fused_alerts),
                "threat_breakdown": threat_counts,
                "severity_breakdown": severity_counts,
                "detector_results": detector_summaries,
            },
            db_path=db_path,
        )

        update_progress("COMPLETE", f"Processing complete: {len(fused_alerts)} alert(s) generated in {duration_sec}s.", 1.0)

        return {
            "success": True,
            "pcap_id": pcap_id,
            "upload_id": pcap_id,
            "upload_dir": str(upload_dir),
            "original_filename": original_filename,
            "file_size_bytes": header_info["file_size"],
            "processing_time_seconds": duration_sec,
            "draft_alerts_count": len(draft_alerts),
            "fused_alerts_count": len(fused_alerts),
            "threat_breakdown": threat_counts,
            "severity_breakdown": severity_counts,
            "detector_results": detector_summaries,
            "telemetry_stats": zeek_stats,
            "alerts": fused_alerts,
        }

    except Exception as e:
        end_iso = datetime.now(timezone.utc).isoformat()
        duration_sec = round(time.time() - start_time, 2)
        update_pcap_analysis(
            pcap_id,
            {
                "status": "failed",
                "error_message": str(e),
                "analysis_end_time": end_iso,
                "duration_seconds": duration_sec,
            },
            db_path=db_path,
        )
        raise


def delete_pcap_analysis(
    pcap_id: str,
    db_path: Path | str = DEFAULT_DB_PATH,
    repo_root: Optional[Path] = None,
) -> dict[str, Any]:
    """
    Safely and transactionally delete an uploaded PCAP and all associated derived artifacts:
      1. Validates pcap_id against path traversal attacks.
      2. Deletes pcap_id rows from SQLite database (alerts and pcap_analyses).
      3. Deletes artifacts/uploads/<pcap_id> directory safely.
      4. Does NOT delete canonical datasets, demo alerts, or other uploads.

    Returns:
        Summary dict of deleted rows and artifacts.
    """
    if repo_root is None:
        repo_root = Path(__file__).resolve().parent.parent

    clean_id = str(pcap_id).strip()
    if not clean_id or "/" in clean_id or "\\" in clean_id or ".." in clean_id:
        raise ValueError(f"Invalid pcap_id: {pcap_id!r}")

    upload_dir = (repo_root / "artifacts" / "uploads" / clean_id).resolve()
    base_uploads = (repo_root / "artifacts" / "uploads").resolve()

    # Safety check: target must reside strictly inside artifacts/uploads
    if not str(upload_dir).startswith(str(base_uploads)) or upload_dir == base_uploads:
        raise ValueError(f"Refusing to delete directory outside artifacts/uploads: {upload_dir}")

    # 1. Transactional SQLite deletion
    deleted_alerts, deleted_analyses = delete_pcap_analysis_records(clean_id, db_path=db_path)

    # 2. Filesystem deletion
    dir_deleted = False
    if upload_dir.exists() and upload_dir.is_dir():
        shutil.rmtree(upload_dir, ignore_errors=False)
        dir_deleted = True

    return {
        "success": True,
        "pcap_id": clean_id,
        "deleted_alerts": deleted_alerts,
        "deleted_analyses": deleted_analyses,
        "deleted_directory": str(upload_dir) if dir_deleted else None,
    }

