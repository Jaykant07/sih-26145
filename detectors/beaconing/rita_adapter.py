"""
RITA C2 Beaconing Adapter for PS-26145.

Open-Source Attribution:
    C2 beaconing detection integrates RITA's beacon-scoring; our contribution
    is fusion, OT-asset-criticality scoring, and unified alert handling.
    RITA = detection engine (v5.1.2, GPL-3.0, Active Countermeasures)
    rita_adapter.py = integration, deduplication, and translation layer

    This adapter adheres to Track A (Reused Components): detection of periodic
    connection beaconing is executed entirely by RITA. The adapter does NOT
    independently compute interval deltas, coefficient of variation, entropy,
    or custom periodicity scores, which would duplicate RITA's detection logic.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import logging
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

repo_root = Path(__file__).resolve().parent.parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from alerts.constants import LatencyClass, Severity, ThreatClass
from alerts.draft import DraftAlert, create_draft_alert
from alerts.validator import validate_draft_alert

logger = logging.getLogger("rita_beacon_adapter")

DETECTOR_NAME = "rita_beacon_adapter"
MODEL_VERSION = "5.1.2"
RITA_VERSION = "v5.1.2"
SCHEMA_VERSION = "1.0.0"
DEFAULT_DOCKER_COMPOSE = Path("rita/docker-compose.yml")
DEFAULT_SCORE_THRESHOLD = 0.75
MATERIAL_CHANGE_SCORE_DELTA = 0.15

# Severity hierarchy for material change escalation checks
_SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class RitaBeaconAdapter:
    """
    Production adapter that interfaces with RITA v5.1.2, ingests native
    view results, filters for C2 beaconing based on lab-tuned thresholds,
    applies new-finding and material-change state deduplication,
    and emits schema-compliant DRAFT alerts.
    """

    def __init__(
        self,
        score_threshold: float = DEFAULT_SCORE_THRESHOLD,
        detector_name: str = DETECTOR_NAME,
        model_version: str = MODEL_VERSION,
        docker_compose_path: str | Path = DEFAULT_DOCKER_COMPOSE,
    ) -> None:
        self.score_threshold = score_threshold
        self.detector_name = detector_name
        self.model_version = model_version
        self.rita_version = RITA_VERSION
        self.docker_compose_path = Path(docker_compose_path)

        # In-memory deduplication state: fingerprint -> last observed finding dict
        # Stored finding dict includes: 'beacon_score', 'severity', 'first_seen_cycle', 'last_alerted_cycle'
        self._seen_findings: dict[str, dict[str, Any]] = {}

    def reset_state(self) -> None:
        """Clear deduplication state (primarily for test isolation)."""
        self._seen_findings.clear()

    @property
    def seen_fingerprints(self) -> set[str]:
        """Return the set of observed finding fingerprints."""
        return set(self._seen_findings.keys())

    # -----------------------------------------------------------------------
    # 1. RITA Invocation
    # -----------------------------------------------------------------------

    def run_rita_beacon_analysis(
        self,
        database: str,
        output_path: Optional[str | Path] = None,
    ) -> str:
        """
        Execute 'rita view --stdout <database>' inside the RITA container stack
        using safe subprocess argument vectors.

        Args:
            database: Target ClickHouse database name (e.g. 'ps26145_beacon_fixed').
            output_path: Optional destination to write the raw CSV stdout.

        Returns:
            The raw stdout string captured from RITA.

        Raises:
            RuntimeError: If docker compose command fails.
        """
        cmd = [
            "docker",
            "compose",
            "-f",
            str(self.docker_compose_path),
            "run",
            "--rm",
            "rita",
            "view",
            "--stdout",
            database,
        ]
        logger.info("Executing RITA view command: %s", " ".join(cmd))
        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
            )
            raw_stdout = res.stdout
        except subprocess.CalledProcessError as e:
            err_msg = f"RITA command failed with exit code {e.returncode}: {e.stderr}"
            logger.error(err_msg)
            raise RuntimeError(err_msg) from e

        if output_path:
            out_file = Path(output_path)
            out_file.parent.mkdir(parents=True, exist_ok=True)
            with open(out_file, "w", encoding="utf-8") as f:
                f.write(raw_stdout)
            logger.info("Saved raw RITA output to %s", out_file)

        return raw_stdout

    # -----------------------------------------------------------------------
    # 2. Output Parsing
    # -----------------------------------------------------------------------

    def parse_rita_beacon_output(self, csv_text: str) -> list[dict[str, str]]:
        """
        Parse raw RITA view stdout into a list of row dictionaries.

        Skips informational banner lines (e.g. 'Viewing database: ...')
        and handles empty or malformed inputs safely.
        """
        rows: list[dict[str, str]] = []
        if not csv_text or not csv_text.strip():
            return rows

        lines = [line.strip() for line in csv_text.splitlines() if line.strip()]
        header_idx = -1
        for idx, line in enumerate(lines):
            if line.startswith("Severity,Source IP"):
                header_idx = idx
                break

        if header_idx == -1:
            logger.debug("No valid RITA CSV header found in output.")
            return rows

        csv_payload = "\n".join(lines[header_idx:])
        try:
            reader = csv.DictReader(io.StringIO(csv_payload))
            for row in reader:
                if not row:
                    continue
                clean_row = {
                    (k.strip() if k else ""): (v.strip() if v else "")
                    for k, v in row.items()
                    if k is not None
                }
                rows.append(clean_row)
        except Exception as e:
            logger.warning("Error parsing CSV payload: %s", e)
            return []

        return rows

    # -----------------------------------------------------------------------
    # 3. Finding Normalization
    # -----------------------------------------------------------------------

    def normalize_beacon_finding(self, record: dict[str, str]) -> Optional[dict[str, Any]]:
        """
        Convert raw CSV string fields into a structured, typed finding dict.

        Returns None if essential identifiers or score cannot be extracted.
        """
        src = record.get("Source IP", "").strip()
        dst = record.get("Destination IP", "").strip()
        if not src or not dst:
            return None

        # Parse Beacon Score
        score_str = record.get("Beacon Score", "").strip()
        try:
            beacon_score = float(score_str)
        except (ValueError, TypeError):
            return None

        # Parse Strobe
        strobe_raw = record.get("Strobe", "false").strip().lower()
        is_strobe = strobe_raw in ("true", "1", "t", "yes")

        # Parse Connection Count
        try:
            conn_count = int(record.get("Connection Count", "0").strip())
        except (ValueError, TypeError):
            conn_count = 0

        # Parse Total Bytes
        try:
            total_bytes = int(record.get("Total Bytes", "0").strip())
        except (ValueError, TypeError):
            total_bytes = 0

        # Parse Total Duration
        try:
            total_duration = float(record.get("Total Duration", "0.0").strip())
        except (ValueError, TypeError):
            total_duration = 0.0

        # Parse Port:Proto:Service (e.g. "8080:tcp:http" or "53:udp:dns")
        port_proto_svc = record.get("Port:Proto:Service", "").strip()
        dst_port: Optional[int] = None
        proto = "tcp"
        service = ""

        if port_proto_svc:
            # If multiple comma-separated, take the first
            first_entry = port_proto_svc.split(",")[0].strip()
            parts = first_entry.split(":")
            if len(parts) >= 1:
                try:
                    dst_port = int(parts[0])
                except ValueError:
                    dst_port = None
            if len(parts) >= 2:
                proto = parts[1].strip()
            if len(parts) >= 3:
                service = parts[2].strip()

        # Severity
        native_sev = record.get("Severity", "None").strip()
        normalized_sev = self._map_severity(native_sev, beacon_score)

        return {
            "source": src,
            "destination": dst,
            "fqdn": record.get("FQDN", "").strip(),
            "destination_port": dst_port,
            "protocol": proto,
            "service": service,
            "port_proto_service": port_proto_svc,
            "beacon_score": beacon_score,
            "is_strobe": is_strobe,
            "connection_count": conn_count,
            "total_bytes": total_bytes,
            "total_duration": total_duration,
            "first_seen": record.get("First Seen", "").strip(),
            "prevalence": record.get("Prevalence", "").strip(),
            "modifiers": record.get("Modifiers", "").strip(),
            "native_severity": native_sev,
            "severity": normalized_sev,
            "raw_record": record,
        }

    def _map_severity(self, native_severity: str, score: float) -> str:
        """Map RITA native severity to schema-approved Severity enum."""
        sev = native_severity.strip().lower()
        if sev == "critical":
            return Severity.CRITICAL
        elif sev == "high":
            return Severity.HIGH
        elif sev == "medium":
            return Severity.MEDIUM
        elif sev == "low":
            return Severity.LOW
        elif sev in ("none", "info"):
            if score >= 0.85:
                return Severity.HIGH
            elif score >= 0.70:
                return Severity.MEDIUM
            return Severity.INFO
        return Severity.MEDIUM

    # -----------------------------------------------------------------------
    # 4. Threshold & Candidate Filtering
    # -----------------------------------------------------------------------

    def is_beacon_candidate(self, finding: dict[str, Any]) -> bool:
        """
        Check if a finding represents a candidate beacon.

        Per design:
        - Strobe connections (Strobe == True) are high-frequency chatty connections
          (>= 86,400 conns) where beacon analysis is skipped by RITA. They must be excluded.
        - Beacon Score must be strictly positive (> 0.0).
        """
        if finding["is_strobe"]:
            return False
        return finding["beacon_score"] > 0.0

    def filter_beacon_findings(
        self,
        findings: list[dict[str, Any]],
        threshold: Optional[float] = None,
    ) -> list[dict[str, Any]]:
        """
        Filter findings to those exceeding the beacon score threshold.
        """
        t = threshold if threshold is not None else self.score_threshold
        qualified: list[dict[str, Any]] = []
        for f in findings:
            if not self.is_beacon_candidate(f):
                continue
            if f["beacon_score"] >= t:
                qualified.append(f)
            else:
                logger.debug(
                    "Suppressed finding %s -> %s: score %.3f below threshold %.3f",
                    f["source"],
                    f["destination"],
                    f["beacon_score"],
                    t,
                )
        return qualified

    # -----------------------------------------------------------------------
    # 5. Stable Finding Identity & Deduplication
    # -----------------------------------------------------------------------

    def compute_fingerprint(self, finding: dict[str, Any]) -> str:
        """
        Derive a deterministic, stable deduplication fingerprint.

        Uses stable connection identity: source, destination, destination port, service.
        Deliberately omits volatile metrics like timestamp, current connection count,
        or current score.
        """
        src = finding["source"]
        dst = finding["destination"]
        port = finding["destination_port"] if finding["destination_port"] is not None else "any"
        svc = finding["service"] or "unknown"
        return f"beacon_{src}_{dst}_{port}_{svc}"

    def deduplicate_beacon_findings(
        self,
        findings: list[dict[str, Any]],
    ) -> list[tuple[dict[str, Any], str]]:
        """
        Apply stateful deduplication and material-change detection across polling cycles.

        Returns:
            List of tuples: (finding, change_status)
            where change_status is either "new_finding" or "materially_changed".
            Findings with no material change are suppressed and omitted.

        Material Change Policy:
            An existing finding is considered materially changed if:
            1. Severity level escalated (e.g. Low/Medium -> High/Critical), OR
            2. Beacon score increased by >= MATERIAL_CHANGE_SCORE_DELTA (0.15).
        """
        alerts_to_emit: list[tuple[dict[str, Any], str]] = []

        for f in findings:
            fp = self.compute_fingerprint(f)
            prev = self._seen_findings.get(fp)

            if prev is None:
                # Case 1: Brand new beacon finding
                self._seen_findings[fp] = {
                    "beacon_score": f["beacon_score"],
                    "severity": f["severity"],
                    "first_seen_timestamp": datetime.now(timezone.utc).isoformat(),
                    "total_cycles_seen": 1,
                }
                alerts_to_emit.append((f, "new_finding"))
                logger.info(
                    "New beacon detected: %s (score: %.3f, sev: %s)",
                    fp,
                    f["beacon_score"],
                    f["severity"],
                )
            else:
                # Case 2: Finding was already seen in a prior cycle
                prev["total_cycles_seen"] += 1
                prev_score = prev["beacon_score"]
                prev_sev = prev["severity"]

                # Check severity escalation
                curr_sev_rank = _SEVERITY_ORDER.get(f["severity"], 0)
                prev_sev_rank = _SEVERITY_ORDER.get(prev_sev, 0)
                sev_escalated = curr_sev_rank > prev_sev_rank

                # Check significant score increase
                score_increased = (f["beacon_score"] - prev_score) >= MATERIAL_CHANGE_SCORE_DELTA

                if sev_escalated or score_increased:
                    # Case 3: Material change detected
                    change_reason = []
                    if sev_escalated:
                        change_reason.append(f"severity escalated {prev_sev} -> {f['severity']}")
                    if score_increased:
                        change_reason.append(
                            f"score increased {prev_score:.3f} -> {f['beacon_score']:.3f}"
                        )
                    reason_str = "; ".join(change_reason)

                    # Update stored baseline
                    prev["beacon_score"] = f["beacon_score"]
                    prev["severity"] = f["severity"]

                    f["material_change_reason"] = reason_str
                    alerts_to_emit.append((f, "materially_changed"))
                    logger.info("Material change for beacon %s: %s", fp, reason_str)
                else:
                    # Ongoing continuation without material change -> suppress
                    logger.debug(
                        "Suppressed duplicate beacon finding %s (score %.3f -> %.3f)",
                        fp,
                        prev_score,
                        f["beacon_score"],
                    )

        return alerts_to_emit

    # -----------------------------------------------------------------------
    # 6. Unified Alert Construction
    # -----------------------------------------------------------------------

    def build_beacon_alert(
        self,
        finding: dict[str, Any],
        change_status: str = "new_finding",
        cycle_timestamp: Optional[str] = None,
        database: str = "unknown",
    ) -> DraftAlert:
        """
        Construct a schema-compliant DRAFT alert from a qualified beacon finding.

        Schema requirements:
            - threat_class: "beaconing" (valid schema enum)
            - subtype: "c2_beaconing"
            - latency_class: "periodic" (valid schema enum)
            - model_version: "5.1.2"
            - confidence: bounded float in [0.0, 1.0] (mapped heuristically)
        """
        ts = cycle_timestamp or datetime.now(timezone.utc).isoformat()
        fp = self.compute_fingerprint(finding)

        # Bounded confidence: RITA score clipped to [0.0, 1.0]
        confidence = max(0.0, min(1.0, round(float(finding["beacon_score"]), 4)))

        evidence: dict[str, Any] = {
            "finding_type": "c2_beaconing",
            "rita_beacon_score": finding["beacon_score"],
            "rita_native_severity": finding["native_severity"],
            "connection_count": finding["connection_count"],
            "total_bytes": finding["total_bytes"],
            "total_duration_seconds": finding["total_duration"],
            "port_proto_service": finding["port_proto_service"],
            "destination_port": finding["destination_port"],
            "protocol": finding["protocol"],
            "service": finding["service"],
            "first_seen": finding["first_seen"],
            "prevalence": finding["prevalence"],
            "modifiers": finding["modifiers"],
            "strobe_flag": finding["is_strobe"],
            # Average interval is not reported in RITA v5.1.2 view output
            "average_interval": "not reported in native rita view",
            "deduplication_fingerprint": fp,
            "material_change_status": change_status,
            "score_threshold": self.score_threshold,
            "confidence_mapping_rationale": (
                "heuristic mapping from native RITA beacon score; not a calibrated probability"
            ),
            "threat_intel_status": "disabled (no external reputation queried)",
            "blacklist_status": "disabled",
            "rita_version": self.rita_version,
            "rita_database": database,
            "attribution": (
                "C2 beaconing detection integrates RITA's beacon-scoring; "
                "our contribution is fusion, OT-asset-criticality scoring, and unified alert handling."
            ),
        }

        if "material_change_reason" in finding:
            evidence["material_change_reason"] = finding["material_change_reason"]

        return create_draft_alert(
            timestamp=ts,
            flow_id=fp,
            threat_class=ThreatClass.BEACONING,
            severity=finding["severity"],
            confidence=confidence,
            source=finding["source"],
            destination=finding["destination"],
            supporting_evidence=evidence,
            detector=self.detector_name,
            model_version=self.model_version,
            subtype="c2_beaconing",
            latency_class=LatencyClass.PERIODIC,
        )

    # -----------------------------------------------------------------------
    # 7. End-to-End Processing Methods
    # -----------------------------------------------------------------------

    def process_csv_text(
        self,
        csv_text: str,
        cycle_timestamp: Optional[str] = None,
        database: str = "manual_eval",
    ) -> list[DraftAlert]:
        """
        Process a complete RITA view CSV string:
        parse -> normalize -> threshold filter -> deduplicate -> build alerts.
        """
        raw_rows = self.parse_rita_beacon_output(csv_text)
        findings: list[dict[str, Any]] = []
        for r in raw_rows:
            f = self.normalize_beacon_finding(r)
            if f is not None:
                findings.append(f)

        qualified = self.filter_beacon_findings(findings)
        deduped = self.deduplicate_beacon_findings(qualified)

        alerts: list[DraftAlert] = []
        for finding, change_status in deduped:
            alert = self.build_beacon_alert(
                finding,
                change_status=change_status,
                cycle_timestamp=cycle_timestamp,
                database=database,
            )
            alerts.append(alert)

        return alerts

    def process_csv_file(
        self,
        csv_file_path: str | Path,
        cycle_timestamp: Optional[str] = None,
        database: str = "file_eval",
    ) -> list[DraftAlert]:
        """Read and process a saved RITA CSV file."""
        p = Path(csv_file_path)
        if not p.exists():
            logger.error("File not found: %s", p)
            return []
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        return self.process_csv_text(content, cycle_timestamp=cycle_timestamp, database=database)

    def run(
        self,
        database: str,
        csv_file: Optional[str | Path] = None,
        output_alerts: Optional[str | Path] = None,
        results_path: Optional[str | Path] = None,
    ) -> dict[str, Any]:
        """
        Execute full evaluation cycle:
        If csv_file provided, use it; otherwise invoke RITA container.
        """
        if csv_file and Path(csv_file).exists():
            with open(csv_file, "r", encoding="utf-8", errors="replace") as f:
                csv_payload = f.read()
        else:
            csv_payload = self.run_rita_beacon_analysis(database)

        raw_rows = self.parse_rita_beacon_output(csv_payload)
        all_findings: list[dict[str, Any]] = []
        for r in raw_rows:
            f = self.normalize_beacon_finding(r)
            if f is not None:
                all_findings.append(f)

        candidates = [f for f in all_findings if self.is_beacon_candidate(f)]
        qualified = self.filter_beacon_findings(candidates)
        deduped = self.deduplicate_beacon_findings(qualified)

        alerts: list[DraftAlert] = []
        for finding, change_status in deduped:
            alert = self.build_beacon_alert(
                finding,
                change_status=change_status,
                database=database,
            )
            # Validate alert against schema validator
            is_valid, val_errs = validate_draft_alert(alert.to_dict())
            if not is_valid:
                logger.error("Alert validation error: %s", val_errs)
            alerts.append(alert)

        results = {
            "detector": self.detector_name,
            "model_version": self.model_version,
            "rita_version": self.rita_version,
            "threat_class": ThreatClass.BEACONING,
            "subtype": "c2_beaconing",
            "latency_class": LatencyClass.PERIODIC,
            "database": database,
            "score_threshold": self.score_threshold,
            "total_rita_records": len(raw_rows),
            "beacon_candidates": len(candidates),
            "qualified_above_threshold": len(qualified),
            "new_alerts_emitted": len(alerts),
            "total_deduplicated_seen": len(self._seen_findings),
            "alerts": [a.to_dict() for a in alerts],
        }

        if output_alerts:
            p_alerts = Path(output_alerts)
            p_alerts.parent.mkdir(parents=True, exist_ok=True)
            with open(p_alerts, "w", encoding="utf-8") as f:
                json.dump([a.to_dict() for a in alerts], f, indent=2)

        if results_path:
            p_res = Path(results_path)
            p_res.parent.mkdir(parents=True, exist_ok=True)
            with open(p_res, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2)

        return results


def main() -> None:
    parser = argparse.ArgumentParser(description="RITA C2 Beaconing Detector Adapter")
    parser.add_argument("--database", "-d", type=str, help="RITA database to view")
    parser.add_argument("--csv", type=str, help="Path to pre-captured RITA CSV stdout file")
    parser.add_argument(
        "--threshold",
        "-t",
        type=float,
        default=DEFAULT_SCORE_THRESHOLD,
        help="Beacon score threshold (default: 0.75)",
    )
    parser.add_argument("--out-alerts", type=str, help="JSON output file for emitted alerts")
    parser.add_argument("--out-results", type=str, help="JSON output file for execution summary")
    args = parser.parse_args()

    adapter = RitaBeaconAdapter(score_threshold=args.threshold)
    if not args.database and not args.csv:
        parser.error("Must specify either --database or --csv")

    db = args.database or "eval_db"
    res = adapter.run(
        database=db,
        csv_file=args.csv,
        output_alerts=args.out_alerts,
        results_path=args.out_results,
    )
    print(
        f"Evaluated {db}: Total RITA rows: {res['total_rita_records']}, "
        f"Candidates: {res['beacon_candidates']}, "
        f"Above threshold ({args.threshold}): {res['qualified_above_threshold']}, "
        f"Emitted alerts: {res['new_alerts_emitted']}"
    )


if __name__ == "__main__":
    main()
