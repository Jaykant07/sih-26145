"""
detectors/anomaly/evaluate.py
Evaluation engine for PS-26145 Detector #8 (AI Behavioral Anomaly Detector).

Evaluates the trained Isolation Forest pipeline across controlled attack experiments
and benign evaluation sets. Computes score distributions and standard classification metrics.
Saves evaluation report to reports/ai/evaluation.json.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from detectors.anomaly.feature_engineering import extract_features_from_records
from detectors.anomaly.predict import AnomalyDetector
from ingest.parser import parse_conn_log

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("anomaly_evaluate")

REPORTS_DIR = REPO_ROOT / "reports" / "ai"

# Attack experiment evaluation sets
EVAL_EXPERIMENTS = [
    ("DDoS-001", REPO_ROOT / "data" / "zeek" / "ddos" / "ddos-001" / "conn.log", "attack"),
    ("DDoS-002", REPO_ROOT / "data" / "zeek" / "ddos" / "ddos-002" / "conn.log", "attack"),
    ("RECON-001", REPO_ROOT / "data" / "zeek" / "reconnaissance" / "recon-001" / "conn.log", "attack"),
    ("RECON-002", REPO_ROOT / "data" / "zeek" / "reconnaissance" / "recon-002" / "conn.log", "attack"),
    ("DGA-001", REPO_ROOT / "data" / "zeek" / "dga" / "dga-001" / "conn.log", "attack"),
    ("DGA-002", REPO_ROOT / "data" / "zeek" / "dga" / "dga-002" / "conn.log", "attack"),
    ("DNS-001", REPO_ROOT / "data" / "zeek" / "dns_tunnel" / "dns-001" / "conn.log", "attack"),
    ("DNS-002", REPO_ROOT / "data" / "zeek" / "dns_tunnel" / "dns-002" / "conn.log", "attack"),
    ("ENC-002", REPO_ROOT / "data" / "zeek" / "encrypted" / "enc-002" / "conn.log", "attack"),
    ("Exfil-Asymmetric", REPO_ROOT / "artifacts" / "exfiltration" / "asymmetric_upload" / "zeek" / "conn.log", "attack"),
    ("Beacon-Fixed", REPO_ROOT / "artifacts" / "beaconing" / "fixed" / "zeek" / "conn.log", "attack"),
    ("BENIGN-001-Val", REPO_ROOT / "data" / "zeek" / "benign" / "benign-001" / "conn.log", "benign"),
]


def run_evaluation() -> dict[str, Any]:
    """Execute evaluation and return metrics report."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    detector = AnomalyDetector()

    per_experiment_results: list[dict[str, Any]] = []

    y_true: list[int] = []  # 0 = benign, 1 = attack
    y_pred: list[int] = []  # 0 = normal, 1 = anomalous

    for name, path, true_label in EVAL_EXPERIMENTS:
        if not path.is_file():
            logger.warning("Eval source %s not found at %s", name, path)
            continue

        records = list(parse_conn_log(path))
        if not records:
            continue

        alerts = detector.predict(records)
        alert_count = len(alerts)

        # Flag an experiment flow as anomalous if an alert was emitted for it
        alerted_uids = {a.supporting_evidence.get("uid") for a in alerts if a.supporting_evidence}

        is_attack = true_label == "attack"
        for rec in records:
            y_true.append(1 if is_attack else 0)
            y_pred.append(1 if rec.uid in alerted_uids else 0)

        detection_rate = (alert_count / len(records)) if records else 0.0

        per_experiment_results.append({
            "experiment": name,
            "ground_truth": true_label,
            "total_flows": len(records),
            "alerts_emitted": alert_count,
            "detection_rate": round(detection_rate, 4),
        })
        logger.info(
            "Experiment %s (%s): %d/%d flows flagged (%.2f%%)",
            name,
            true_label,
            alert_count,
            len(records),
            detection_rate * 100,
        )

    # Compute confusion matrix metrics
    y_t = np.array(y_true)
    y_p = np.array(y_pred)

    tp = int(np.sum((y_t == 1) & (y_p == 1)))
    fp = int(np.sum((y_t == 0) & (y_p == 1)))
    tn = int(np.sum((y_t == 0) & (y_p == 0)))
    fn = int(np.sum((y_t == 1) & (y_p == 0)))

    precision = float(tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    recall = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    f1 = float(2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    eval_report = {
        "model_version": detector.model_version,
        "calibration_baseline": {
            "benign_min": detector.benign_min,
            "benign_max": detector.benign_max,
        },
        "confusion_matrix": {
            "TP": tp,
            "FP": fp,
            "TN": tn,
            "FN": fn,
        },
        "metrics": {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "false_positive_rate": round(fpr, 4),
        },
        "sample_counts": {
            "total_samples": len(y_true),
            "attack_samples": int(np.sum(y_t == 1)),
            "benign_eval_samples": int(np.sum(y_t == 0)),
        },
        "per_experiment": per_experiment_results,
    }

    out_file = REPORTS_DIR / "evaluation.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(eval_report, f, indent=2)
    logger.info("Saved evaluation report to %s", out_file)

    return eval_report


if __name__ == "__main__":
    report = run_evaluation()
    print("Evaluation successfully completed.")
    print(json.dumps(report, indent=2))
