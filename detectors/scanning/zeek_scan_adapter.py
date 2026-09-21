"""
Zeek Scan Adapter for PS-26145.

Open-Source Attribution:
    Recon/scan detection uses Zeek's built-in Scan framework, reformatted
    into our unified alert schema.
    Zeek = detection engine
    zeek_scan_adapter.py = integration/translation layer

    This adapter adheres to Track A (Reused Components): detection of
    source -> distinct destination ports (Scan::Port_Scan) and
    source -> distinct destination hosts (Scan::Address_Scan) is executed
    entirely by Zeek's Scan framework. The adapter does NOT independently
    calculate fan-out counts from conn.log, which would duplicate Zeek Scan
    and violate Track A principles.
"""

from __future__ import annotations

import argparse
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from alerts.constants import LatencyClass, Severity, ThreatClass
from alerts.draft import DraftAlert, create_draft_alert
from alerts.validator import validate_draft_alert

logger = logging.getLogger("zeek_scan_adapter")

DETECTOR_NAME = "zeek_scan_adapter"
MODEL_VERSION = "1.0.0"
SCHEMA_VERSION = "1.0.0"

SUPPORTED_SCAN_NOTICES = {
    "Scan::Port_Scan": "port_scan",
    "Scan::Address_Scan": "address_scan",
}


class ZeekScanAdapter:
    """
    Adapter that parses Zeek notice.log entries emitted by the Scan framework
    and converts them into normalized DRAFT alerts.
    """

    def __init__(
        self,
        detector_name: str = DETECTOR_NAME,
        model_version: str = MODEL_VERSION,
        confidence: float = 0.95,
        default_severity: str = Severity.HIGH,
    ) -> None:
        self.detector_name = detector_name
        self.model_version = model_version
        self.confidence = confidence
        self.default_severity = default_severity
        self.alerts: list[DraftAlert] = []

    def parse_notice_line(self, line: str) -> Optional[dict[str, Any]]:
        """Safely parse a single JSON line from notice.log."""
        line = line.strip()
        if not line:
            return None
        try:
            data = json.loads(line)
            if isinstance(data, dict):
                return data
            logger.warning("Notice entry is not a JSON object: %r", line)
            return None
        except json.JSONDecodeError as err:
            logger.warning("Malformed JSON in notice.log: %s", err)
            return None

    def is_scan_notice(self, record: dict[str, Any]) -> bool:
        """Determine if a notice record is a Scan notice."""
        note = record.get("note")
        return note in SUPPORTED_SCAN_NOTICES

    def process_notice(self, record: dict[str, Any]) -> Optional[DraftAlert]:
        """
        Convert a Zeek Scan notice record into a standardized DRAFT alert.

        Returns:
            DraftAlert if the record is a valid Scan notice, None otherwise.
        """
        if not isinstance(record, dict):
            logger.warning("Invalid record type: %s", type(record))
            return None

        note = record.get("note")
        if note not in SUPPORTED_SCAN_NOTICES:
            logger.debug("Skipping non-scan notice: %s", note)
            return None

        subtype = SUPPORTED_SCAN_NOTICES[note]

        # Extract timestamp (ts)
        raw_ts = record.get("ts")
        if isinstance(raw_ts, (int, float)):
            try:
                timestamp = datetime.fromtimestamp(raw_ts, tz=timezone.utc).isoformat()
            except (ValueError, OSError):
                timestamp = datetime.now(timezone.utc).isoformat()
        elif isinstance(raw_ts, str):
            timestamp = raw_ts
        else:
            timestamp = datetime.now(timezone.utc).isoformat()

        # Extract source and destination evidence
        source = str(record.get("src") or "unknown")
        destination = str(record.get("dst") or "unknown")

        msg = str(record.get("msg") or "")
        sub = str(record.get("sub") or "")
        actions = record.get("actions", [])
        if not isinstance(actions, list):
            actions = [str(actions)]

        # Scan count handling per specification:
        # If absent in native notice, record exact string rather than fabricating or parsing conn.log
        scan_count: Any = record.get("p") or record.get("n")
        if scan_count is None:
            scan_count = "scan_count unavailable in native notice"

        # Unique flow_id for the detection event
        flow_id = f"zeek_scan_{source}_{destination}_{int(raw_ts) if isinstance(raw_ts, (int, float)) else 'event'}"

        # Construct supporting evidence preserving original Zeek notice fields
        supporting_evidence: dict[str, Any] = {
            "zeek_note": note,
            "zeek_msg": msg,
            "zeek_sub": sub,
            "zeek_actions": actions,
            "scan_count": scan_count,
            "native_notice": record,
        }

        # Subtype-specific severity
        severity = self.default_severity

        # Construct unified DRAFT alert
        alert = create_draft_alert(
            timestamp=timestamp,
            flow_id=flow_id,
            threat_class=ThreatClass.RECONNAISSANCE,
            severity=severity,
            confidence=self.confidence,
            source=source,
            destination=destination,
            supporting_evidence=supporting_evidence,
            detector=self.detector_name,
            model_version=self.model_version,
            detector_version=self.model_version,
            subtype=subtype,
            latency_class=LatencyClass.EVENT_DRIVEN,
        )

        return alert

    def process_notice_log(self, path: str | Path) -> list[DraftAlert]:
        """
        Process a notice.log file, filtering for scan notices and building alerts.

        Args:
            path: Path to notice.log file.

        Returns:
            List of generated DraftAlert objects.
        """
        log_path = Path(path)
        alerts: list[DraftAlert] = []

        if not log_path.exists():
            logger.warning("Notice log path does not exist: %s", log_path)
            return alerts

        try:
            with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                for line_num, line in enumerate(f, start=1):
                    record = self.parse_notice_line(line)
                    if record is None:
                        continue
                    alert = self.process_notice(record)
                    if alert is not None:
                        is_valid, errors = validate_draft_alert(alert.to_dict())
                        if not is_valid:
                            logger.error("Alert validation failed at line %d: %s", line_num, errors)
                        alerts.append(alert)
        except OSError as err:
            logger.error("Error reading %s: %s", log_path, err)

        self.alerts.extend(alerts)
        return alerts

    def run(
        self,
        notice_log: str | Path,
        output_alerts: Optional[str | Path] = None,
        results_path: Optional[str | Path] = None,
    ) -> dict[str, Any]:
        """Run adapter against a notice.log file and optionally save results."""
        alerts = self.process_notice_log(notice_log)
        alert_dicts = [a.to_dict() for a in alerts]

        if output_alerts is not None:
            out_file = Path(output_alerts)
            out_file.parent.mkdir(parents=True, exist_ok=True)
            with open(out_file, "w", encoding="utf-8") as f:
                json.dump(alert_dicts, f, indent=2)

        results = {
            "detector": self.detector_name,
            "model_version": self.model_version,
            "threat_class": ThreatClass.RECONNAISSANCE,
            "latency_class": LatencyClass.EVENT_DRIVEN,
            "input_file": str(notice_log),
            "alerts_generated": len(alert_dicts),
            "alerts": alert_dicts,
        }

        if results_path is not None:
            res_file = Path(results_path)
            res_file.parent.mkdir(parents=True, exist_ok=True)
            with open(res_file, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2)

        return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Zeek Scan Adapter for PS-26145")
    parser.add_argument("--notice-log", required=True, help="Path to notice.log")
    parser.add_argument("--output", default=None, help="Output path for sample_alerts.json")
    parser.add_argument("--results", default=None, help="Output path for detector_results.json")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    adapter = ZeekScanAdapter()
    results = adapter.run(args.notice_log, output_alerts=args.output, results_path=args.results)
    print(f"Generated {results['alerts_generated']} reconnaissance alert(s).")


if __name__ == "__main__":
    main()
