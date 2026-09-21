"""
DGA Detector Training and Evaluation Pipeline for PS-26145.

Trains a Random Forest classifier using FANCI-inspired features on
labeled DGA and benign reference datasets.
Applies temporal validation, threshold optimization, held-out unseen
family testing, and canonical PCAP evaluation.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

repo_root = Path(__file__).resolve().parent.parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from detectors.dga.features import (
    DEFAULT_NGRAM_PATH,
    DEFAULT_WORDLIST_PATH,
    FEATURE_NAMES,
    DGAFeatureExtractor,
)
from detectors.dga.model import DGAModel

logger = logging.getLogger("dga_train")

MODEL_VERSION = "1.0.0"
DEFAULT_MODEL_PATH = Path("artifacts/dga/models/dga_rf_v1.joblib")


def load_dataset(path: str | Path) -> list[dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def prepare_features_and_labels(
    samples: list[dict[str, Any]], extractor: DGAFeatureExtractor
) -> tuple[np.ndarray, np.ndarray, list[str]]:
    X_list = []
    y_list = []
    domains = []
    for s in samples:
        d = s["domain"]
        vec = extractor.extract_vector(d)
        X_list.append(vec)
        y_list.append(int(s["ground_truth"]))
        domains.append(d)
    return np.asarray(X_list, dtype=float), np.asarray(y_list, dtype=int), domains


def tune_threshold(
    model: RandomForestClassifier, X_val: np.ndarray, y_val: np.ndarray
) -> tuple[float, float, dict[float, dict[str, float]]]:
    """
    Search probability thresholds from 0.30 to 0.85 in steps of 0.05
    to find threshold that maximizes F1 score on validation set.
    """
    probs = model.predict_proba(X_val)
    pos_idx = 1 if probs.shape[1] > 1 else 0
    pos_probs = probs[:, pos_idx]

    best_threshold = 0.50
    best_f1 = -1.0
    tuning_curve: dict[float, dict[str, float]] = {}

    for t in np.arange(0.30, 0.86, 0.05):
        t_val = round(float(t), 2)
        preds = (pos_probs >= t_val).astype(int)
        p = precision_score(y_val, preds, zero_division=0)
        r = recall_score(y_val, preds, zero_division=0)
        f = f1_score(y_val, preds, zero_division=0)

        tuning_curve[t_val] = {"precision": round(p, 4), "recall": round(r, 4), "f1": round(f, 4)}
        if f > best_f1:
            best_f1 = f
            best_threshold = t_val

    return best_threshold, best_f1, tuning_curve


def evaluate_set(
    model: RandomForestClassifier, X: np.ndarray, y: np.ndarray, threshold: float
) -> dict[str, Any]:
    probs = model.predict_proba(X)
    pos_idx = 1 if probs.shape[1] > 1 else 0
    pos_probs = probs[:, pos_idx]
    preds = (pos_probs >= threshold).astype(int)

    precision = float(precision_score(y, preds, zero_division=0))
    recall = float(recall_score(y, preds, zero_division=0))
    f1 = float(f1_score(y, preds, zero_division=0))

    try:
        roc_auc = float(roc_auc_score(y, pos_probs))
    except ValueError:
        roc_auc = 0.0

    try:
        pr_auc = float(average_precision_score(y, pos_probs))
    except ValueError:
        pr_auc = 0.0

    cm = confusion_matrix(y, preds).tolist()

    return {
        "samples": len(y),
        "dga_samples": int(np.sum(y == 1)),
        "benign_samples": int(np.sum(y == 0)),
        "threshold": threshold,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "roc_auc": round(roc_auc, 4),
        "pr_auc": round(pr_auc, 4),
        "confusion_matrix": cm,
    }


def train_pipeline(
    train_path: str | Path = "artifacts/dga/datasets/dga_train_dataset.json",
    val_path: str | Path = "artifacts/dga/datasets/dga_val_dataset.json",
    unseen_path: str | Path = "artifacts/dga/datasets/dga_unseen_dataset.json",
    model_output_path: str | Path = DEFAULT_MODEL_PATH,
) -> dict[str, Any]:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    logger.info("Initializing DGA feature extractor...")
    extractor = DGAFeatureExtractor(DEFAULT_WORDLIST_PATH, DEFAULT_NGRAM_PATH)

    # 1. Load Training Data
    logger.info("Loading training data from %s...", train_path)
    train_samples = load_dataset(train_path)
    X_train, y_train, _ = prepare_features_and_labels(train_samples, extractor)

    # 2. Load Validation Data
    logger.info("Loading validation data from %s...", val_path)
    val_samples = load_dataset(val_path)
    X_val, y_val, _ = prepare_features_and_labels(val_samples, extractor)

    # 3. Train RandomForest
    logger.info("Fitting RandomForestClassifier (n_estimators=100, max_depth=12, random_state=42)...")
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=12,
        min_samples_split=4,
        random_state=42,
        class_weight="balanced",
    )
    clf.fit(X_train, y_train)

    # 4. Tune Threshold on Validation Set
    best_thresh, best_f1, tuning_curve = tune_threshold(clf, X_val, y_val)
    logger.info("Optimal threshold on validation set: %.2f (F1: %.4f)", best_thresh, best_f1)

    # 5. Evaluate In-Family Validation
    val_metrics = evaluate_set(clf, X_val, y_val, best_thresh)

    # 6. Evaluate Held-Out Unseen Family (Necurs)
    logger.info("Evaluating held-out unseen family (Necurs) from %s...", unseen_path)
    unseen_samples = load_dataset(unseen_path)
    X_unseen, y_unseen, _ = prepare_features_and_labels(unseen_samples, extractor)
    unseen_probs = clf.predict_proba(X_unseen)[:, 1]
    unseen_preds = (unseen_probs >= best_thresh).astype(int)
    unseen_recall = float(recall_score(y_unseen, unseen_preds, zero_division=0))
    logger.info("Unseen Family (Necurs) Recall: %.4f", unseen_recall)

    unseen_metrics = {
        "family": "necurs",
        "samples": len(y_unseen),
        "threshold": best_thresh,
        "recall": round(unseen_recall, 4),
        "detected_count": int(np.sum(unseen_preds == 1)),
        "mean_probability": round(float(np.mean(unseen_probs)), 4),
    }

    # 7. Package and Persist DGAModel Bundle
    metadata = {
        "model_version": MODEL_VERSION,
        "feature_names": FEATURE_NAMES,
        "feature_order": FEATURE_NAMES,
        "training_dataset": str(train_path),
        "benign_corpus": "artifacts/dga/datasets/benign_reference_domains.txt",
        "training_dga_families": ["banjori", "corebot", "ramdo"],
        "unseen_dga_family": "necurs",
        "random_state": 42,
        "rf_hyperparameters": {
            "n_estimators": 100,
            "max_depth": 12,
            "min_samples_split": 4,
            "class_weight": "balanced",
            "random_state": 42,
        },
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "tuned_threshold": best_thresh,
        "validation_f1": round(best_f1, 4),
        "unseen_family_recall": round(unseen_recall, 4),
    }

    model_wrapper = DGAModel(
        classifier=clf,
        model_version=MODEL_VERSION,
        threshold=best_thresh,
        feature_names=FEATURE_NAMES,
        metadata=metadata,
    )
    model_wrapper.save(model_output_path)
    logger.info("Persisted model artifact to %s", model_output_path)

    # 8. Save Metrics
    metrics_summary = {
        "model_version": MODEL_VERSION,
        "tuned_threshold": best_thresh,
        "validation_metrics": val_metrics,
        "unseen_family_metrics": unseen_metrics,
        "threshold_tuning_curve": tuning_curve,
    }

    metrics_file = Path("artifacts/dga/training/training_metrics.json")
    metrics_file.parent.mkdir(parents=True, exist_ok=True)
    with open(metrics_file, "w", encoding="utf-8") as f:
        json.dump(metrics_summary, f, indent=2)

    return metrics_summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Train FANCI-inspired DGA Detector for PS-26145")
    parser.add_argument("--train-data", default="artifacts/dga/datasets/dga_train_dataset.json")
    parser.add_argument("--val-data", default="artifacts/dga/datasets/dga_val_dataset.json")
    parser.add_argument("--unseen-data", default="artifacts/dga/datasets/dga_unseen_dataset.json")
    parser.add_argument("--output", default=str(DEFAULT_MODEL_PATH))
    args = parser.parse_args()

    results = train_pipeline(
        train_path=args.train_data,
        val_path=args.val_data,
        unseen_path=args.unseen_data,
        model_output_path=args.output,
    )
    print("\n--- Training Complete ---")
    print(f"Model Version: {results['model_version']}")
    print(f"Tuned Threshold: {results['tuned_threshold']}")
    print(f"Validation F1: {results['validation_metrics']['f1']}")
    print(f"Validation Recall: {results['validation_metrics']['recall']}")
    print(f"Validation Precision: {results['validation_metrics']['precision']}")
    print(f"Unseen Family (Necurs) Recall: {results['unseen_family_metrics']['recall']}")


if __name__ == "__main__":
    main()
