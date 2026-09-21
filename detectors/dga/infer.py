"""
DGA Inference and Alert Generation Engine for PS-26145.

Performs deterministic feature extraction and Random Forest inference
on DNS queries, emitting schema-compliant unified DRAFT alerts.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Union

repo_root = Path(__file__).resolve().parent.parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from alerts.constants import LatencyClass, Severity, ThreatClass
from alerts.draft import DraftAlert, create_draft_alert
from alerts.validator import validate_draft_alert
from detectors.dga.features import (
    DEFAULT_NGRAM_PATH,
    DEFAULT_WORDLIST_PATH,
    DGAFeatureExtractor,
    extract_candidate_label,
)
from detectors.dga.model import DGAModel

logger = logging.getLogger("dga_infer")

DETECTOR_NAME = "dga_detector"
DEFAULT_MODEL_PATH = Path("artifacts/dga/models/dga_rf_v1.joblib")


class DGADetector:
    """
    Production DGA detector executing feature extraction, model inference,
    threshold evaluation, and DRAFT alert generation.
    """

    def __init__(
        self,
        model_path: Optional[str | Path] = None,
        wordlist_path: Optional[str | Path] = None,
        ngram_path: Optional[str | Path] = None,
        threshold_override: Optional[float] = None,
    ) -> None:
        self.model_path = Path(model_path or DEFAULT_MODEL_PATH)
        self.model = DGAModel.load(self.model_path)
        self.extractor = DGAFeatureExtractor(
            wordlist_path or DEFAULT_WORDLIST_PATH,
            ngram_path or DEFAULT_NGRAM_PATH,
        )
        self.threshold = threshold_override if threshold_override is not None else self.model.threshold
        self.model_version = self.model.model_version
        self.detector_name = DETECTOR_NAME

    def predict_domain(self, domain: str) -> dict[str, Any]:
        """
        Extract features and predict malicious/DGA probability for a domain.

        Returns:
            Dictionary containing prediction metadata, features, and decision.
        """
        label = extract_candidate_label(domain)
        feats = self.extractor.extract_features(domain)
        vector = [feats[name] for name in self.model.feature_names]

        prob = float(self.model.predict_proba(vector)[0])
        is_dga = bool(prob >= self.threshold)

        return {
            "domain": domain,
            "extracted_label": label,
            "features": feats,
            "feature_vector": vector,
            "probability": round(prob, 4),
            "threshold": self.threshold,
            "is_dga": is_dga,
        }

    def create_alert(
        self,
        domain: str,
        prediction: dict[str, Any],
        telemetry: Optional[dict[str, Any]] = None,
    ) -> Optional[DraftAlert]:
        """
        Construct a schema-compliant DRAFT alert for a positive DGA detection.

        Returns:
            DraftAlert instance if is_dga is True, else None.
        """
        if not prediction.get("is_dga", False):
            return None

        telemetry = telemetry or {}
        raw_ts = telemetry.get("ts")
        if isinstance(raw_ts, (int, float)):
            try:
                timestamp = datetime.fromtimestamp(raw_ts, tz=timezone.utc).isoformat()
            except (ValueError, OSError):
                timestamp = datetime.now(timezone.utc).isoformat()
        else:
            timestamp = datetime.now(timezone.utc).isoformat()

        source = str(telemetry.get("id.orig_h") or telemetry.get("source") or "unknown")
        destination = str(telemetry.get("id.resp_h") or telemetry.get("destination") or "unknown")

        label = prediction.get("extracted_label", domain)
        flow_id = f"dga_dns_{source}_{destination}_{label}"

        feats = prediction.get("features", {})
        prob = prediction.get("probability", 0.0)

        supporting_evidence: dict[str, Any] = {
            "domain": domain,
            "extracted_label": label,
            "probability_estimate": prob,
            "threshold": self.threshold,
            "domain_length": feats.get("domain_length", 0.0),
            "entropy": feats.get("shannon_entropy", 0.0),
            "digit_ratio": feats.get("digit_ratio", 0.0),
            "vowel_consonant_ratio": feats.get("vowel_to_consonant_ratio", 0.0),
            "meaningful_substring": feats.get("longest_meaningful_substring", 0.0),
            "ngram_distance": feats.get("ngram_frequency_distance", 0.0),
            "model_version": self.model_version,
            "calibration_status": "uncalibrated probability estimate",
        }

        if telemetry:
            supporting_evidence["dns_telemetry"] = telemetry

        alert = create_draft_alert(
            timestamp=timestamp,
            flow_id=flow_id,
            threat_class=ThreatClass.DGA,
            severity=Severity.HIGH,
            confidence=min(prob, 1.0),
            source=source,
            destination=destination,
            supporting_evidence=supporting_evidence,
            detector=self.detector_name,
            model_version=self.model_version,
            detector_version=self.model_version,
            subtype="dga_dns",
            latency_class=LatencyClass.EVENT_DRIVEN,
        )

        return alert

    def process_dns_log(self, path: str | Path) -> list[DraftAlert]:
        """
        Process a Zeek dns.log JSON file and emit alerts for detected DGA queries.
        """
        log_path = Path(path)
        alerts: list[DraftAlert] = []
        if not log_path.exists():
            logger.warning("DNS log path does not exist: %s", log_path)
            return alerts

        try:
            with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    query = record.get("query")
                    if not query or not isinstance(query, str):
                        continue

                    pred = self.predict_domain(query)
                    alert = self.create_alert(query, pred, record)
                    if alert is not None:
                        is_valid, errs = validate_draft_alert(alert.to_dict())
                        if not is_valid:
                            logger.error("Alert validation error: %s", errs)
                        alerts.append(alert)
        except OSError as err:
            logger.error("Error reading %s: %s", log_path, err)

        return alerts

    def run(
        self,
        dns_log: str | Path,
        output_alerts: Optional[str | Path] = None,
        results_path: Optional[str | Path] = None,
    ) -> dict[str, Any]:
        """Run full evaluation on a dns.log file and persist artifacts."""
        log_path = Path(dns_log)
        alerts = self.process_dns_log(log_path)
        alert_dicts = [a.to_dict() for a in alerts]

        if output_alerts is not None:
            out_file = Path(output_alerts)
            out_file.parent.mkdir(parents=True, exist_ok=True)
            with open(out_file, "w", encoding="utf-8") as f:
                json.dump(alert_dicts, f, indent=2)

        # Count total queries in dns.log
        total_queries = 0
        if log_path.exists():
            with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                total_queries = sum(1 for line in f if line.strip())

        detection_rate = round(len(alerts) / total_queries, 4) if total_queries > 0 else 0.0

        results = {
            "detector": self.detector_name,
            "model_version": self.model_version,
            "threat_class": ThreatClass.DGA,
            "latency_class": LatencyClass.EVENT_DRIVEN,
            "threshold": self.threshold,
            "input_file": str(dns_log),
            "total_dns_queries": total_queries,
            "detected_queries": len(alerts),
            "detection_rate": detection_rate,
            "alerts": alert_dicts,
        }

        if results_path is not None:
            res_file = Path(results_path)
            res_file.parent.mkdir(parents=True, exist_ok=True)
            with open(res_file, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2)

        return results


def main() -> None:
    parser = argparse.ArgumentParser(description="DGA Inference Engine for PS-26145")
    parser.add_argument("--domain", help="Single domain query to evaluate")
    parser.add_argument("--dns-log", help="Path to Zeek dns.log file")
    parser.add_argument("--output", help="Output path for sample_alerts.json")
    parser.add_argument("--results", help="Output path for detector_results.json")
    args = parser.parse_args()

    detector = DGADetector()

    if args.domain:
        res = detector.predict_domain(args.domain)
        print(f"Domain: {args.domain}")
        print(f"  Extracted Label: {res['extracted_label']}")
        print(f"  DGA Probability: {res['probability']} (Threshold: {res['threshold']})")
        print(f"  Decision: {'MALICIOUS (DGA)' if res['is_dga'] else 'BENIGN'}")
        if res["is_dga"]:
            alert = detector.create_alert(args.domain, res)
            if alert:
                print(f"  Alert ID: {alert.alert_id}")

    if args.dns_log:
        res = detector.run(args.dns_log, output_alerts=args.output, results_path=args.results)
        print(f"Processed {res['total_dns_queries']} DNS queries.")
        print(f"Detected {res['detected_queries']} DGA queries (Rate: {res['detection_rate'] * 100:.2f}%).")


if __name__ == "__main__":
    main()
