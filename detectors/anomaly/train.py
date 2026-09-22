"""
detectors/anomaly/train.py
Training pipeline for PS-26145 Detector #8 (AI Behavioral Anomaly Detector).

Trains an Isolation Forest model exclusively on frozen benign baseline experiments:
  - BENIGN-002 (iperf3-tcp)
  - BENIGN-003 (iperf3-udp)
  - BENIGN-004 (short-tcp)
  - BENIGN-005 (normal-dns)
  - ENC-001 (tls-baseline)

Persists:
  - data/features/ai/ai_features_train.csv
  - models/anomaly/feature_schema.json
  - models/anomaly/anomaly_pipeline.joblib
  - reports/ai/feature_summary.json
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from detectors.anomaly.feature_engineering import (
    ALL_MODEL_FEATURES,
    CATEGORICAL_FEATURES,
    DEFAULT_SCHEMA_PATH,
    NUMERICAL_FEATURES,
    extract_features_from_records,
    save_feature_schema,
)
from ingest.parser import ConnRecord, parse_conn_log

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("anomaly_train")

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
MODEL_DIR = REPO_ROOT / "models" / "anomaly"
FEATURES_DIR = REPO_ROOT / "data" / "features" / "ai"
REPORTS_DIR = REPO_ROOT / "reports" / "ai"

# Exact frozen benign training sources (Phase 13)
BENIGN_TRAINING_SOURCES = [
    ("BENIGN-002", REPO_ROOT / "data" / "zeek" / "benign" / "benign-002" / "conn.log"),
    ("BENIGN-003", REPO_ROOT / "data" / "zeek" / "benign" / "benign-003" / "conn.log"),
    ("BENIGN-004", REPO_ROOT / "data" / "zeek" / "benign" / "benign-004" / "conn.log"),
    ("BENIGN-005", REPO_ROOT / "data" / "zeek" / "benign" / "benign-005" / "conn.log"),
    ("ENC-001", REPO_ROOT / "data" / "zeek" / "encrypted" / "enc-001" / "conn.log"),
]


def load_benign_training_records() -> tuple[list[ConnRecord], list[dict[str, Any]]]:
    """Load and parse ConnRecords from all frozen benign baseline experiments."""
    all_records: list[ConnRecord] = []
    source_stats: list[dict[str, Any]] = []

    for name, path in BENIGN_TRAINING_SOURCES:
        if not path.is_file():
            # Fallback path for enc-001 in artifacts if data/zeek not found
            if name == "ENC-001":
                alt = REPO_ROOT / "artifacts" / "tls" / "enc_001_baseline" / "zeek" / "conn.log"
                if alt.is_file():
                    path = alt
        if not path.is_file():
            logger.warning("Benign source %s not found at %s", name, path)
            continue

        recs = list(parse_conn_log(path))
        all_records.extend(recs)
        source_stats.append({
            "experiment": name,
            "path": str(path.relative_to(REPO_ROOT)),
            "record_count": len(recs),
        })
        logger.info("Loaded %d records from %s (%s)", len(recs), name, path)

    return all_records, source_stats


def train_anomaly_detector() -> dict[str, Any]:
    """
    Execute end-to-end training of the Isolation Forest anomaly detector.

    Returns summary metadata dictionary.
    """
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    FEATURES_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Load training telemetry
    records, source_stats = load_benign_training_records()
    if not records:
        raise RuntimeError("No benign training records could be loaded. Training aborted.")

    # 2. Extract shared canonical features
    df_features = extract_features_from_records(records)
    logger.info("Extracted features DataFrame shape: %s", df_features.shape)

    # 3. Data quality audit
    nan_counts = df_features.isna().sum().to_dict()
    inf_counts = {col: int(np.isinf(df_features[col]).sum()) for col in NUMERICAL_FEATURES}

    # Save training dataset artifact
    train_csv_path = FEATURES_DIR / "ai_features_train.csv"
    df_features.to_csv(train_csv_path, index=False)
    logger.info("Saved training features to %s", train_csv_path)

    # 4. Save frozen feature schema
    save_feature_schema(path=MODEL_DIR / "feature_schema.json")

    # 5. Build reproducible training pipeline
    preprocessor = ColumnTransformer(
        transformers=[
            ("num", StandardScaler(), NUMERICAL_FEATURES),
            ("cat", OneHotEncoder(handle_unknown="ignore", sparse_output=False), CATEGORICAL_FEATURES),
        ]
    )

    model = IsolationForest(
        n_estimators=300,
        contamination="auto",
        random_state=42,
        n_jobs=-1,
    )

    pipeline = Pipeline(
        steps=[
            ("preprocessor", preprocessor),
            ("model", model),
        ]
    )

    # 6. Fit model exclusively on benign baseline
    logger.info("Fitting Isolation Forest (n_estimators=300, random_state=42) on %d benign flows...", len(df_features))
    pipeline.fit(df_features)

    # 7. Calibration bridge: compute benign training score range (Phase 22)
    # decision_function returns positive for inliers, negative for outliers
    # raw_anomaly_score = -decision_function (higher = more anomalous)
    decision_scores = pipeline.decision_function(df_features)
    raw_train_scores = -decision_scores

    benign_score_min = float(np.min(raw_train_scores))
    benign_score_max = float(np.max(raw_train_scores))
    benign_score_mean = float(np.mean(raw_train_scores))
    benign_score_std = float(np.std(raw_train_scores))

    logger.info(
        "Benign score distribution: min=%.4f, max=%.4f, mean=%.4f, std=%.4f",
        benign_score_min,
        benign_score_max,
        benign_score_mean,
        benign_score_std,
    )

    # 8. Persist complete model artifact
    model_version = "isolation-forest-v1"
    artifact_payload = {
        "pipeline": pipeline,
        "model_version": model_version,
        "numerical_features": NUMERICAL_FEATURES,
        "categorical_features": CATEGORICAL_FEATURES,
        "all_features": ALL_MODEL_FEATURES,
        "benign_score_min": benign_score_min,
        "benign_score_max": benign_score_max,
        "benign_score_mean": benign_score_mean,
        "benign_score_std": benign_score_std,
        "training_row_count": len(df_features),
        "source_experiments": [s["experiment"] for s in source_stats],
    }

    model_path = MODEL_DIR / "anomaly_pipeline.joblib"
    joblib.dump(artifact_payload, model_path)
    logger.info("Saved trained anomaly pipeline to %s", model_path)

    # 9. Save audit and summary report
    summary = {
        "model": "IsolationForest",
        "parameters": {
            "n_estimators": 300,
            "contamination": "auto",
            "random_state": 42,
            "n_jobs": -1,
        },
        "model_version": model_version,
        "feature_count": len(ALL_MODEL_FEATURES),
        "numerical_features": NUMERICAL_FEATURES,
        "categorical_features": CATEGORICAL_FEATURES,
        "training_rows": len(df_features),
        "source_experiments": source_stats,
        "calibration_bridge": {
            "benign_score_min": benign_score_min,
            "benign_score_max": benign_score_max,
            "benign_score_mean": benign_score_mean,
            "benign_score_std": benign_score_std,
            "formula": "confidence = max(0.0, min(1.0, (raw_score - benign_min) / (benign_max - benign_min)))",
        },
        "data_audit": {
            "nan_counts": nan_counts,
            "inf_counts": inf_counts,
            "duplicate_rows": int(df_features.duplicated().sum()),
        },
    }

    summary_path = REPORTS_DIR / "feature_summary.json"
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    logger.info("Saved feature summary report to %s", summary_path)

    return summary


if __name__ == "__main__":
    summary = train_anomaly_detector()
    print("Training successfully completed.")
    print(json.dumps(summary, indent=2))
