"""
RITA DNS Tunnelling Adapter for PS-26145.

Open-Source Attribution:
    DNS tunnelling detection integrates RITA's DNS analysis (C2 Over DNS);
    our contribution is output normalization, deduplication, and unified
    alert handling.
    RITA = detection engine (v5.1.2, GPL-3.0, Active Countermeasures)
    rita_tunnel_adapter.py = integration, deduplication, and translation layer

    This adapter adheres to Track A (Reused Components): detection of C2 over
    DNS / DNS tunnelling patterns is executed entirely by RITA. The adapter
    does NOT independently compute subdomain entropy, TXT record thresholds,
    or custom tunnel scores, which would duplicate RITA's detection logic.
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

logger = logging.getLogger("rita_tunnel_adapter")

DETECTOR_NAME = "rita_tunnel_adapter"
MODEL_VERSION = "5.1.2"
RITA_VERSION = "v5.1.2"
SCHEMA_VERSION = "1.0.0"
DEFAULT_DOCKER_COMPOSE = Path("rita/docker-compose.yml")


class RitaTunnelAdapter:
    """
    Production adapter that interfaces with RITA v5.1.2, ingests native
    consolidated analysis results, filters for C2 Over DNS / DNS tunnelling,
    applies new-finding state deduplication, and emits schema-compliant DRAFT alerts.
    """

    def __init__(
        self,
        detector_name: str = DETECTOR_NAME,
        model_version: str = MODEL_VERSION,
        docker_compose_path: str | Path = DEFAULT_DOCKER_COMPOSE,
    ) -> None:
        self.detector_name = detector_name
        self.model_version = model_version
        self.rita_version = RITA_VERSION
        self.docker_compose_path = Path(docker_compose_path)
        self._seen_fingerprints: set[str] = set()

    def reset_state(self) -> None:
        """Clear deduplication cache (primarily for test scenarios)."""
        self._seen_fingerprints.clear()

    @property
    def seen_fingerprints(self) -> set[str]:
        return set(self._seen_fingerprints)

    def parse_csv_text(self, csv_text: str) -> list[dict[str, str]]:
        """
        Parse raw RITA view stdout into a list of normalized row dictionaries.

        Skips informational banner lines (e.g. 'Viewing database: ...')
        and maps column headers cleanly.
        """
        rows: list[dict[str, str]] = []
        if not csv_text or not csv_text.strip():
            return rows

        lines = [line.strip() for line in csv_text.splitlines() if line.strip()]
        # Locate the header line starting with Severity,Source IP...
        header_idx = -1
        for idx, line in enumerate(lines):
            if line.startswith("Severity,Source IP"):
                header_idx = idx
                break

        if header_idx == -1:
            logger.debug("No valid RITA CSV header found in output.")
            return rows

        csv_payload = "\n".join(lines[header_idx:])
        reader = csv.DictReader(io.StringIO(csv_payload))
        for row in reader:
            if not row:
                continue
            # Strip whitespace from keys and values
            clean_row = {
                (k.strip() if k else ""): (v.strip() if v else "")
                for k, v in row.items()
                if k is not None
            }
            rows.append(clean_row)

        return rows

    def is_tunnel_finding(self, record: dict[str, str]) -> bool:
        """
        Determine if a RITA finding record represents DNS tunnelling / C2 over DNS.

        Criteria:
            - 'C2 Over DNS Score' present, numeric, and > 0.0.
        """
        score_raw = record.get("C2 Over DNS Score", "").strip()
        if not score_raw:
            return False
        try:
            score = float(score_raw)
            return score > 0.0
        except ValueError:
            return False

    def compute_fingerprint(self, record: dict[str, str]) -> str:
        """
        Derive a deterministic, stable deduplication fingerprint from native RITA fields.

        Uses stable identifiers (source IP, destination IP, FQDN/domain, threat type)
        and deliberately omits volatile fields such as current timestamps.
        """
        src = record.get("Source IP", "unknown").strip()
        dst = record.get("Destination IP", "unknown").strip()
        fqdn = record.get("FQDN", "unknown").strip().lower()
        return f"c2_over_dns_{src}_{dst}_{fqdn}"

    def normalize_severity(self, rita_severity: str) -> str:
        """Map RITA native severity to schema-approved Severity enum."""
        sev = rita_severity.strip().lower()
        if sev == "critical":
            return Severity.CRITICAL
        elif sev == "high":
            return Severity.HIGH
        elif sev == "medium":
            return Severity.MEDIUM
        elif sev == "low":
            return Severity.LOW
        elif sev == "none" or sev == "info":
            return Severity.INFO
        return Severity.MEDIUM

    def map_confidence(self, c2_score: float) -> float:
        """
        Map native RITA C2 Over DNS score to confidence in [0.0, 1.0].
        Clearly designated as a heuristic mapping, not a calibrated probability.
        """
        if c2_score < 0.0:
            return 0.0
        if c2_score > 1.0:
            return 1.0
        # Preserve native score directly as confidence value in [0.0, 1.0]
        return round(c2_score, 4)

    def create_alert(
        self,
        record: dict[str, str],
        cycle_timestamp: Optional[str] = None,
    ) -> Optional[DraftAlert]:
        """
        Convert a native RITA C2 Over DNS finding record into a standardized DRAFT alert.

        Returns:
            DraftAlert instance if is_tunnel_finding is True, else None.
        """
        if not self.is_tunnel_finding(record):
            return None

        # Parse numeric fields safely
        try:
            c2_score = float(record.get("C2 Over DNS Score", "0.0"))
        except ValueError:
            c2_score = 0.0

        try:
            subdomains = int(record.get("Subdomains", "0"))
        except ValueError:
            subdomains = 0

        try:
            conn_count = int(record.get("Connection Count", "0"))
        except ValueError:
            conn_count = 0

        try:
            total_bytes = int(record.get("Total Bytes", "0"))
        except ValueError:
            total_bytes = 0

        source = record.get("Source IP", "unknown").strip()
        destination = record.get("Destination IP", "unknown").strip()
        fqdn = record.get("FQDN", "unknown").strip()
        fingerprint = self.compute_fingerprint(record)

        timestamp = cycle_timestamp or datetime.now(timezone.utc).isoformat()
        flow_id = fingerprint

        severity = self.normalize_severity(record.get("Severity", "medium"))
        confidence = self.map_confidence(c2_score)

        supporting_evidence: dict[str, Any] = {
            "finding_type": "c2_over_dns",
            "domain": fqdn,
            "subdomains_count": subdomains,
            "c2_over_dns_score": c2_score,
            "rita_native_severity": record.get("Severity", "None"),
            "connection_count": conn_count,
            "total_bytes": total_bytes,
            "port_proto_service": record.get("Port:Proto:Service", ""),
            "modifiers": record.get("Modifiers", ""),
            "first_seen": record.get("First Seen", ""),
            "rita_version": self.rita_version,
            "deduplication_fingerprint": fingerprint,
            "confidence_mapping_rationale": "heuristic mapping from native RITA score; not a calibrated probability",
            "threat_intel_status": "disabled (no external reputation queried)",
            "blacklist_status": "disabled",
        }

        alert = create_draft_alert(
            timestamp=timestamp,
            flow_id=flow_id,
            threat_class=ThreatClass.DNS_TUNNEL,
            severity=severity,
            confidence=confidence,
            source=source,
            destination=destination,
            supporting_evidence=supporting_evidence,
            detector=self.detector_name,
            model_version=self.model_version,
            detector_version=self.model_version,
            subtype="c2_over_dns",
            latency_class=LatencyClass.PERIODIC,
        )

        return alert

    def process_findings(
        self,
        records: list[dict[str, str]],
        cycle_timestamp: Optional[str] = None,
    ) -> list[DraftAlert]:
        """
        Process multiple records with new-finding deduplication.

        Only findings whose fingerprints have not yet been seen in previous
        cycles will result in an emitted DraftAlert.
        """
        new_alerts: list[DraftAlert] = []
        for record in records:
            if not self.is_tunnel_finding(record):
                continue

            fp = self.compute_fingerprint(record)
            if fp in self._seen_fingerprints:
                logger.debug("Deduplicating already-seen finding: %s", fp)
                continue

            alert = self.create_alert(record, cycle_timestamp=cycle_timestamp)
            if alert is not None:
                is_valid, errs = validate_draft_alert(alert.to_dict())
                if not is_valid:
                    logger.error("Alert validation error: %s", errs)
                self._seen_fingerprints.add(fp)
                new_alerts.append(alert)

        return new_alerts

    def process_csv_text(
        self,
        csv_text: str,
        cycle_timestamp: Optional[str] = None,
    ) -> list[DraftAlert]:
        """Parse raw CSV text and process findings through deduplication."""
        records = self.parse_csv_text(csv_text)
        return self.process_findings(records, cycle_timestamp=cycle_timestamp)

    def process_csv_file(
        self,
        csv_path: str | Path,
        cycle_timestamp: Optional[str] = None,
    ) -> list[DraftAlert]:
        """Read CSV file from disk and process findings through deduplication."""
        p = Path(csv_path)
        if not p.exists():
            logger.warning("CSV file not found: %s", p)
            return []
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        return self.process_csv_text(content, cycle_timestamp=cycle_timestamp)

    def run_rita_view(self, database: str) -> str:
        """Invoke 'rita view --stdout <database>' via docker compose."""
        cmd = [
            "docker", "compose",
            "-f", str(self.docker_compose_path),
            "run", "--rm",
            "rita", "view", "--stdout", database,
        ]
        logger.info("Executing RITA view command: %s", " ".join(cmd))
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            logger.warning("RITA view exited with code %d: %s", result.returncode, result.stderr)
        return result.stdout

    def run(
        self,
        database: str,
        csv_file: Optional[str | Path] = None,
        output_alerts: Optional[str | Path] = None,
        results_path: Optional[str | Path] = None,
    ) -> dict[str, Any]:
        """
        Execute full cycle on a dataset (either reading pre-saved CSV or querying RITA),
        emit deduplicated alerts, and persist output artifacts.
        """
        if csv_file and Path(csv_file).exists():
            with open(csv_file, "r", encoding="utf-8", errors="replace") as f:
                csv_text = f.read()
        else:
            csv_text = self.run_rita_view(database)

        records = self.parse_csv_text(csv_text)
        tunnel_records = [r for r in records if self.is_tunnel_finding(r)]
        alerts = self.process_findings(tunnel_records)
        alert_dicts = [a.to_dict() for a in alerts]

        if output_alerts is not None:
            out_path = Path(output_alerts)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(alert_dicts, f, indent=2)

        results = {
            "detector": self.detector_name,
            "model_version": self.model_version,
            "rita_version": self.rita_version,
            "threat_class": ThreatClass.DNS_TUNNEL,
            "latency_class": LatencyClass.PERIODIC,
            "database": database,
            "total_rita_records": len(records),
            "c2_over_dns_findings": len(tunnel_records),
            "new_alerts_emitted": len(alerts),
            "total_deduplicated_seen": len(self._seen_fingerprints),
            "alerts": alert_dicts,
        }

        if results_path is not None:
            res_path = Path(results_path)
            res_path.parent.mkdir(parents=True, exist_ok=True)
            with open(res_path, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2)

        return results


def main() -> None:
    parser = argparse.ArgumentParser(description="RITA DNS Tunnelling Adapter for PS-26145")
    parser.add_argument("--database", help="Target RITA dataset name to view")
    parser.add_argument("--csv", help="Optional pre-captured RITA CSV view output file")
    parser.add_argument("--output", help="Output path for sample_alerts.json")
    parser.add_argument("--results", help="Output path for detector_results.json")
    args = parser.parse_args()

    adapter = RitaTunnelAdapter()

    if args.database or args.csv:
        db = args.database or "local_csv"
        res = adapter.run(
            database=db,
            csv_file=args.csv,
            output_alerts=args.output,
            results_path=args.results,
        )
        print(f"Processed RITA dataset '{db}'.")
        print(f"Total rows: {res['total_rita_records']}, C2 Over DNS hits: {res['c2_over_dns_findings']}, Alerts emitted: {res['new_alerts_emitted']}")


if __name__ == "__main__":
    main()
