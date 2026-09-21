"""
Encrypted Malware / TLS Metadata Detector for PS-26145 (Track B).

Module: detectors/tls/detector.py

Architecture:
    Zeek ssl.log + conn.log
              ↓
    join on Zeek uid
              ↓
    TLS metadata/features
              ↓
    Signal A: JA3/JA3S static offline lookup
              ↓
    Signal B: behavioral score
              ↓
    Signal fusion
              ↓
    DRAFT unified alert
              ↓
    OT-aware fusion layer

No payload decryption is ever performed.
Operates exclusively on passive connection counters and handshake metadata.
"""

from __future__ import annotations

import argparse
import json
import logging
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
from detectors.tls.behavior import DEFAULT_BEHAVIORAL_THRESHOLD, TLSBehaviorModel
from detectors.tls.blacklist import JA3Blacklist
from detectors.tls.tls_features import (
    extract_features_from_files,
    join_ssl_and_conn_records,
    parse_zeek_json_lines,
    parse_zeek_log_file,
)

logger = logging.getLogger("tls_detector")

DETECTOR_NAME = "tls_detector"
MODEL_VERSION = "1.0.0"
SCHEMA_VERSION = "1.0.0"

# Explicit alert description adhering strictly to the no-decryption guarantee
ALERT_DESCRIPTION = (
    "Encrypted TLS session exhibits suspicious fingerprint and/or "
    "connection-level behavioral characteristics (metadata/behavior-based suspicion)."
)


class TLSDetector:
    """
    Custom Encrypted Malware and TLS Metadata Detector (Track B).
    Fuses static offline fingerprint intelligence (Signal A) with
    statistical connection behavior (Signal B).
    """

    def __init__(
        self,
        blacklist_path: Optional[str | Path] = None,
        behavioral_threshold: float = DEFAULT_BEHAVIORAL_THRESHOLD,
        model_version: str = MODEL_VERSION,
        detector_name: str = DETECTOR_NAME,
    ) -> None:
        self.detector_name = detector_name
        self.model_version = model_version
        self.blacklist = JA3Blacklist(blacklist_path)
        self.behavior_model = TLSBehaviorModel(
            threshold=behavioral_threshold,
            model_version=model_version,
        )

    def evaluate_connection(self, features: dict[str, Any]) -> dict[str, Any]:
        """
        Evaluate a single joined TLS flow against Signal A and Signal B.

        Returns a dictionary with fusion status, confidence, severity, and evidence.
        """
        ja3 = features.get("ja3")
        ja3s = features.get("ja3s")

        # Signal A: Static Offline JA3/JA3S lookup
        ja3_match, ja3s_match, ja3_info, ja3s_info = self.blacklist.match(ja3, ja3s)
        has_fp_match = ja3_match or ja3s_match

        # Signal B: Connection-level behavioral anomaly score
        b_eval = self.behavior_model.evaluate(features)
        behavioral_score = b_eval["behavioral_score"]
        has_behavior_anomaly = b_eval["is_anomalous"]

        # Signal Fusion Decision Matrix
        #   Both: high confidence (0.90)
        #   Fingerprint only: medium-high confidence (0.75)
        #   Behavior only: medium confidence (0.65)
        #   Neither: no alert
        if has_fp_match and has_behavior_anomaly:
            fusion_state = "both"
            severity = Severity.HIGH
            confidence = 0.90
            subtype = "encrypted_malware"
            is_alert = True
        elif has_fp_match and not has_behavior_anomaly:
            fusion_state = "fingerprint_only"
            severity = Severity.MEDIUM
            confidence = 0.75
            subtype = "suspicious_fingerprint"
            is_alert = True
        elif not has_fp_match and has_behavior_anomaly:
            fusion_state = "behavior_only"
            severity = Severity.MEDIUM
            confidence = 0.65
            subtype = "tls_behavioral_anomaly"
            is_alert = True
        else:
            fusion_state = "none"
            severity = Severity.INFO
            confidence = 0.0
            subtype = "normal_tls"
            is_alert = False

        return {
            "is_alert": is_alert,
            "fusion_state": fusion_state,
            "severity": severity,
            "confidence": confidence,
            "subtype": subtype,
            "ja3": ja3,
            "ja3s": ja3s,
            "ja3_match": ja3_match,
            "ja3s_match": ja3s_match,
            "ja3_info": ja3_info,
            "ja3s_info": ja3s_info,
            "behavioral_score": behavioral_score,
            "behavioral_eval": b_eval,
            "features": features,
        }

    def create_alert(
        self,
        eval_result: dict[str, Any],
        alert_timestamp: Optional[str] = None,
    ) -> Optional[DraftAlert]:
        """
        Build a schema-valid DraftAlert from an evaluation result.
        Returns None if eval_result is not flagged as an alert.
        """
        if not eval_result["is_alert"]:
            return None

        feat = eval_result["features"]
        uid = feat.get("uid", "unknown_flow")
        flow_id = f"tls_{feat['source']}_{feat['destination']}_{feat['resp_port']}_{uid}"

        ts = alert_timestamp or datetime.now(timezone.utc).isoformat()

        # Build schema-compliant supporting_evidence
        evidence: dict[str, Any] = {
            "finding_type": "tls_encrypted_threat",
            "detection_basis": "metadata/behavior-based suspicion",
            "alert_description": ALERT_DESCRIPTION,
            "decryption_status": "payload uninspected (zero payload decryption)",
            "fusion_state": eval_result["fusion_state"],
            "ja3": eval_result["ja3"],
            "ja3s": eval_result["ja3s"],
            "ja3_match": eval_result["ja3_match"],
            "ja3s_match": eval_result["ja3s_match"],
            "behavioral_score": eval_result["behavioral_score"],
            "mean_packet_size": feat["mean_packet_size"],
            "byte_ratio": feat["byte_ratio"],
            "packet_count": feat["packet_count"],
            "duration": feat["duration"],
            "orig_bytes": feat["orig_bytes"],
            "resp_bytes": feat["resp_bytes"],
            "orig_pkts": feat["orig_pkts"],
            "resp_pkts": feat["resp_pkts"],
            "tls_version": feat["version"],
            "cipher": feat["cipher"],
            "server_name": feat["server_name"],
            "established": feat["established"],
            "confidence_mapping_rationale": (
                "Dual-signal fusion: 'both'=0.90 high, 'fingerprint_only'=0.75 med-high, "
                "'behavior_only'=0.65 med. Heuristic mapping, not calibrated probability."
            ),
            "threat_intel_status": "static offline snapshot (no runtime external lookup)",
            "blacklist_snapshot_version": self.blacklist.metadata.get("version", "local"),
        }

        if eval_result["ja3_info"]:
            evidence["ja3_threat_info"] = eval_result["ja3_info"]
        if eval_result["ja3s_info"]:
            evidence["ja3s_threat_info"] = eval_result["ja3s_info"]
        if eval_result["behavioral_eval"].get("explanations"):
            evidence["behavioral_explanations"] = eval_result["behavioral_eval"]["explanations"]

        alert = create_draft_alert(
            timestamp=ts,
            flow_id=flow_id,
            threat_class=ThreatClass.TLS_ANOMALY,
            severity=eval_result["severity"],
            confidence=eval_result["confidence"],
            source=feat["source"],
            destination=feat["destination"],
            supporting_evidence=evidence,
            detector=self.detector_name,
            model_version=self.model_version,
            subtype=eval_result["subtype"],
            latency_class=LatencyClass.EVENT_DRIVEN,
        )

        return alert

    def process_records(
        self,
        ssl_records: list[dict[str, Any]],
        conn_records: list[dict[str, Any]],
        alert_timestamp: Optional[str] = None,
    ) -> list[DraftAlert]:
        """
        Join records on UID, evaluate both signals, and generate DRAFT alerts.
        """
        joined_features = join_ssl_and_conn_records(ssl_records, conn_records)
        alerts: list[DraftAlert] = []

        for feat in joined_features:
            eval_res = self.evaluate_connection(feat)
            alert = self.create_alert(eval_res, alert_timestamp=alert_timestamp)
            if alert is not None:
                # Self-check against validator
                is_valid, errors = validate_draft_alert(alert.to_dict())
                if not is_valid:
                    logger.error("Generated alert failed validation: %s", errors)
                alerts.append(alert)

        return alerts

    def process_files(
        self,
        ssl_log_path: str | Path,
        conn_log_path: str | Path,
        output_alerts_path: Optional[str | Path] = None,
    ) -> list[DraftAlert]:
        """Process ssl.log and conn.log from disk files."""
        ssl_records = parse_zeek_log_file(ssl_log_path)
        conn_records = parse_zeek_log_file(conn_log_path)
        alerts = self.process_records(ssl_records, conn_records)

        if output_alerts_path:
            p_out = Path(output_alerts_path)
            p_out.parent.mkdir(parents=True, exist_ok=True)
            with open(p_out, "w", encoding="utf-8") as f:
                json.dump([a.to_dict() for a in alerts], f, indent=2)
            logger.info("Saved %d TLS alerts to %s", len(alerts), p_out)

        return alerts


def main() -> None:
    parser = argparse.ArgumentParser(description="Encrypted Malware / TLS Metadata Detector")
    parser.add_argument("--ssl-log", "-s", required=True, help="Path to Zeek ssl.log")
    parser.add_argument("--conn-log", "-c", required=True, help="Path to Zeek conn.log")
    parser.add_argument("--out-alerts", "-o", help="Path to write alerts JSON")
    parser.add_argument("--blacklist", "-b", help="Path to custom JA3 blacklist JSON")
    parser.add_argument(
        "--threshold",
        "-t",
        type=float,
        default=DEFAULT_BEHAVIORAL_THRESHOLD,
        help="Behavioral anomaly threshold (default: 0.50)",
    )
    args = parser.parse_args()

    detector = TLSDetector(
        blacklist_path=args.blacklist,
        behavioral_threshold=args.threshold,
    )
    alerts = detector.process_files(
        ssl_log_path=args.ssl_log,
        conn_log_path=args.conn_log,
        output_alerts_path=args.out_alerts,
    )
    print(f"Processed TLS logs: {len(alerts)} alerts generated.")
    for a in alerts:
        d = a.to_dict()
        print(
            f"[{d['severity'].upper()}] {d['subtype']} | "
            f"{d['source']} -> {d['destination']} | "
            f"conf: {d['confidence']} | fusion: {d['supporting_evidence']['fusion_state']}"
        )


if __name__ == "__main__":
    main()
