"""
Canonical PCAP Evaluation Runner for DGA Detection (PS-26145).

Evaluates the trained FANCI-inspired Random Forest model on the canonical
Zeek dns.log streams for:
  - dga-001-random.pcap
  - dga-002-irregular.pcap

Generates sample_alerts.json, detector_results.json, and metadata.json for each.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

repo_root = Path(__file__).resolve().parent.parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from detectors.dga.infer import DGADetector

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("dga_canonical_eval")


def run_eval() -> None:
    logger.info("Initializing DGA Detector...")
    detector = DGADetector()
    logger.info("Model loaded. Version: %s, Threshold: %s", detector.model_version, detector.threshold)

    cases = [
        {
            "id": "DGA-001",
            "name": "dga-001-random",
            "pcap": "data/raw/dga/dga-001-random.pcap",
            "dns_log": "artifacts/dga/dga-001/zeek/dns.log",
            "out_dir": Path("artifacts/dga/dga-001"),
            "generator": "python-synthetic-random-dga",
            "attack_type": "dga_dns_random",
            "description": "High-entropy pseudo-random domain generation (character mix)",
        },
        {
            "id": "DGA-002",
            "name": "dga-002-irregular",
            "pcap": "data/raw/dga/dga-002-irregular.pcap",
            "dns_log": "artifacts/dga/dga-002/zeek/dns.log",
            "out_dir": Path("artifacts/dga/dga-002"),
            "generator": "python-synthetic-irregular-dga",
            "attack_type": "dga_dns_irregular",
            "description": "Irregular length / vowel-consonant imbalance domain generation",
        },
    ]

    for case in cases:
        logger.info("\n--- Evaluating %s (%s) ---", case["id"], case["name"])
        dns_log = Path(case["dns_log"])
        if not dns_log.exists():
            logger.error("dns.log not found at %s", dns_log)
            continue

        detector_dir = case["out_dir"] / "detector"
        detector_dir.mkdir(parents=True, exist_ok=True)
        alerts_path = detector_dir / "sample_alerts.json"
        results_path = detector_dir / "detector_results.json"
        metadata_path = case["out_dir"] / "metadata.json"

        results = detector.run(
            dns_log=dns_log,
            output_alerts=alerts_path,
            results_path=results_path,
        )

        logger.info(
            "%s: %d / %d queries detected as DGA (Rate: %.2f%%)",
            case["id"],
            results["detected_queries"],
            results["total_dns_queries"],
            results["detection_rate"] * 100,
        )

        metadata = {
            "experiment_id": case["id"],
            "dataset": case["pcap"],
            "attack_type": case["attack_type"],
            "description": case["description"],
            "generator": case["generator"],
            "canonical": True,
            "ground_truth": "malicious",
            "threat_class": "dga",
            "subtype": "dga_dns",
            "latency_class": "event_driven",
            "detector": detector.detector_name,
            "model_version": detector.model_version,
            "decision_threshold": detector.threshold,
            "zeek_telemetry_source": str(dns_log),
            "zeek_script": "scripts/dns_tunnel/dns_53531.zeek",
            "total_dns_queries": results["total_dns_queries"],
            "detected_dga_queries": results["detected_queries"],
            "detection_rate": results["detection_rate"],
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
        }

        with open(metadata_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)
        logger.info("Saved metadata to %s", metadata_path)

    logger.info("\nCanonical DGA evaluation complete.")


if __name__ == "__main__":
    run_eval()
