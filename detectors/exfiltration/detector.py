"""
Data Exfiltration Detector for PS-26145 (Track B — Custom).

Module: detectors/exfiltration/detector.py

Architecture:
    Zeek conn.log
          ↓
    flow_stats window
          ↓
    (source, external destination) aggregation
          ↓
    outbound_bytes / inbound_bytes
          ↓
    byte_ratio = outbound_bytes / max(inbound_bytes, 1)
          ↓
    rolling per-host benign baseline
          ↓
    ratio + volume threshold
          ↓
    DRAFT alert
          ↓
    OT-aware Fusion

No payload inspection or decryption is ever performed.
Operates exclusively on passive connection-level byte counts and timing.
"""

from __future__ import annotations

import argparse
import json
import logging
import math
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

repo_root = Path(__file__).resolve().parent.parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from alerts.constants import LatencyClass, Severity, ThreatClass
from alerts.draft import DraftAlert, create_draft_alert
from alerts.validator import validate_draft_alert
from detectors.exfiltration.baseline import HostExfilBaseline
from detectors.exfiltration.network import NetworkClassifier
from features.flow_stats import ExfilFlowWindow, build_exfil_windows
from ingest.parser import ConnRecord, parse_conn_log

logger = logging.getLogger("exfiltration_detector")

DETECTOR_NAME = "exfiltration_detector"
MODEL_VERSION = "1.0.0"
SCHEMA_VERSION = "1.0.0"

DEFAULT_RATIO_THRESHOLD: float = 10.0
DEFAULT_VOLUME_FLOOR: int = 50_000  # 50 KB floor to suppress small DNS/web asymmetry
DEFAULT_WINDOW_SECONDS: float = 60.0

ALERT_DESCRIPTION = (
    "Outbound traffic exhibits an unusually high byte asymmetry relative to the host baseline."
)


class ExfiltrationDetector:
    """
    Custom Data Exfiltration Detector (Track B).
    Evaluates internal-to-external communication for high directional byte asymmetry
    and significant outbound volume compared against a rolling per-host baseline.
    """

    def __init__(
        self,
        ratio_threshold: float = DEFAULT_RATIO_THRESHOLD,
        volume_floor: int = DEFAULT_VOLUME_FLOOR,
        window_seconds: float = DEFAULT_WINDOW_SECONDS,
        network_classifier: Optional[NetworkClassifier] = None,
        baseline: Optional[HostExfilBaseline] = None,
        model_version: str = MODEL_VERSION,
        detector_name: str = DETECTOR_NAME,
    ) -> None:
        self.ratio_threshold = ratio_threshold
        self.volume_floor = volume_floor
        self.window_seconds = window_seconds
        self.network_classifier = network_classifier or NetworkClassifier()
        self.baseline = baseline or HostExfilBaseline()
        self.model_version = model_version
        self.detector_name = detector_name

    def evaluate_window(
        self,
        window: ExfilFlowWindow,
        alert_timestamp: Optional[str] = None,
    ) -> Optional[DraftAlert]:
        """
        Evaluate an aggregated flow window for exfiltration conditions.

        Condition:
            byte_ratio > ratio_threshold AND outbound_bytes >= volume_floor
        """
        if window.byte_ratio <= self.ratio_threshold or window.outbound_bytes < self.volume_floor:
            return None

        # Calculate deviation from host's historical benign baseline
        dev_info = self.baseline.calculate_deviation(
            src_ip=window.source_ip,
            current_ratio=window.byte_ratio,
            current_volume=window.outbound_bytes,
        )

        # Severity qualification:
        # Critical if volume >= 10MB or ratio >= 200
        # High if volume >= 1MB or ratio >= 50
        # Medium otherwise
        if window.outbound_bytes >= 10_000_000 or window.byte_ratio >= 200.0:
            severity = Severity.CRITICAL
        elif window.outbound_bytes >= 1_000_000 or window.byte_ratio >= 50.0:
            severity = Severity.HIGH
        else:
            severity = Severity.MEDIUM

        # Deterministic rule-based confidence mapping
        ratio_excess = window.byte_ratio / max(self.ratio_threshold, 1.0)
        volume_excess = window.outbound_bytes / max(self.volume_floor, 1)
        conf_raw = 0.60 + 0.15 * math.log10(max(ratio_excess, 1.0)) + 0.05 * math.log10(max(volume_excess, 1.0))
        confidence = round(min(0.95, max(0.50, conf_raw)), 2)

        ts = alert_timestamp or datetime.now(timezone.utc).isoformat()
        flow_id = (
            f"exfil_{window.source_ip}_{window.destination_ip}_"
            f"{int(window.window_start)}_{int(window.window_end)}"
        )

        evidence: dict[str, Any] = {
            "finding_type": "asymmetric_data_exfiltration",
            "detection_basis": "behavioral/statistical byte asymmetry",
            "alert_description": ALERT_DESCRIPTION,
            "payload_inspection_status": "uninspected (zero payload inspection)",
            "outbound_bytes": window.outbound_bytes,
            "inbound_bytes": window.inbound_bytes,
            "byte_ratio": round(window.byte_ratio, 4),
            "ratio_threshold": self.ratio_threshold,
            "volume_floor": self.volume_floor,
            "baseline_deviation": dev_info["baseline_deviation"],
            "ratio_multiple": dev_info["ratio_multiple"],
            "insufficient_baseline_data": dev_info["insufficient_baseline_data"],
            "baseline_sample_count": dev_info["baseline_sample_count"],
            "historical_mean_ratio": dev_info["historical_mean_ratio"],
            "baseline_explanation": dev_info["explanation"],
            "window_start": window.window_start,
            "window_end": window.window_end,
            "window_duration_seconds": self.window_seconds,
            "flow_count": window.flow_count,
            "orig_pkts": window.orig_pkts,
            "resp_pkts": window.resp_pkts,
            "duration_sum": round(window.duration_sum, 4),
            "direction": "internal_to_external",
            "confidence_mapping_rationale": (
                "Deterministic rule-based confidence mapped from ratio and volume excess "
                "over detection thresholds. Non-calibrated heuristic."
            ),
        }

        alert = create_draft_alert(
            timestamp=ts,
            flow_id=flow_id,
            threat_class=ThreatClass.EXFILTRATION,
            severity=severity,
            confidence=confidence,
            source=window.source_ip,
            destination=window.destination_ip,
            supporting_evidence=evidence,
            detector=self.detector_name,
            model_version=self.model_version,
            subtype="asymmetric_outbound_transfer",
            latency_class=LatencyClass.PERIODIC,
        )

        return alert

    def process_records(
        self,
        records: Iterable[ConnRecord],
        alert_timestamp: Optional[str] = None,
    ) -> list[DraftAlert]:
        """
        Aggregate ConnRecords into time windows and evaluate for exfiltration.
        """
        windows = build_exfil_windows(
            records=records,
            window_seconds=self.window_seconds,
            network_classifier=self.network_classifier,
        )

        alerts: list[DraftAlert] = []
        for win in windows:
            alert = self.evaluate_window(win, alert_timestamp=alert_timestamp)
            if alert is not None:
                is_valid, errors = validate_draft_alert(alert.to_dict())
                if not is_valid:
                    logger.error("Generated alert failed schema validation: %s", errors)
                alerts.append(alert)

        return alerts

    def process_conn_log(
        self,
        conn_log_path: str | Path,
        output_alerts_path: Optional[str | Path] = None,
        alert_timestamp: Optional[str] = None,
    ) -> list[DraftAlert]:
        """Process conn.log file from disk and optionally save alerts JSON."""
        records = parse_conn_log(conn_log_path)
        alerts = self.process_records(records, alert_timestamp=alert_timestamp)

        if output_alerts_path:
            p_out = Path(output_alerts_path)
            p_out.parent.mkdir(parents=True, exist_ok=True)
            with open(p_out, "w", encoding="utf-8") as f:
                json.dump([a.to_dict() for a in alerts], f, indent=2)
            logger.info("Saved %d exfiltration alerts to %s", len(alerts), p_out)

        return alerts


def main() -> None:
    parser = argparse.ArgumentParser(description="Data Exfiltration Detector (Track B)")
    parser.add_argument("--conn-log", "-c", required=True, help="Path to Zeek conn.log")
    parser.add_argument("--out-alerts", "-o", help="Path to write alerts JSON")
    parser.add_argument(
        "--ratio-threshold",
        "-r",
        type=float,
        default=DEFAULT_RATIO_THRESHOLD,
        help="Outbound/inbound byte ratio threshold (default: 10.0)",
    )
    parser.add_argument(
        "--volume-floor",
        "-v",
        type=int,
        default=DEFAULT_VOLUME_FLOOR,
        help="Absolute outbound byte floor (default: 50000)",
    )
    parser.add_argument(
        "--window",
        "-w",
        type=float,
        default=DEFAULT_WINDOW_SECONDS,
        help="Flow aggregation window duration in seconds (default: 60.0)",
    )
    args = parser.parse_args()

    detector = ExfiltrationDetector(
        ratio_threshold=args.ratio_threshold,
        volume_floor=args.volume_floor,
        window_seconds=args.window,
    )
    alerts = detector.process_conn_log(args.conn_log, args.out_alerts)
    print(f"Processed conn.log: {len(alerts)} exfiltration alerts generated.")
    for a in alerts:
        d = a.to_dict()
        print(
            f"[{d['severity'].upper()}] {d['subtype']} | "
            f"{d['source']} -> {d['destination']} | "
            f"ratio: {d['supporting_evidence']['byte_ratio']} | "
            f"outbound: {d['supporting_evidence']['outbound_bytes']} B | "
            f"conf: {d['confidence']}"
        )


if __name__ == "__main__":
    main()
