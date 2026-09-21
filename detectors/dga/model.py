"""
DGA Random Forest Model Container for PS-26145.

Wraps scikit-learn's RandomForestClassifier with versioned metadata,
deterministic feature ordering, threshold management, and joblib serialization.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Union

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier

from detectors.dga.features import FEATURE_NAMES

DEFAULT_MODEL_VERSION = "1.0.0"
DEFAULT_THRESHOLD = 0.60


class DGAModel:
    """
    Trained DGA detection model wrapper.
    Encapsulates classifier, threshold, feature ordering, and provenance metadata.
    """

    def __init__(
        self,
        classifier: Optional[RandomForestClassifier] = None,
        model_version: str = DEFAULT_MODEL_VERSION,
        threshold: float = DEFAULT_THRESHOLD,
        feature_names: Optional[list[str]] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> None:
        self.classifier = classifier or RandomForestClassifier(
            n_estimators=100,
            max_depth=12,
            min_samples_split=4,
            random_state=42,
            class_weight="balanced",
        )
        self.model_version = model_version
        self.threshold = threshold
        self.feature_names = list(feature_names or FEATURE_NAMES)
        self.metadata = metadata or {
            "model_version": self.model_version,
            "feature_names": self.feature_names,
            "feature_order": self.feature_names,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

    def predict_proba(self, X: Union[list[float], list[list[float]], np.ndarray]) -> np.ndarray:
        """
        Return the predicted probability of the positive (DGA/malicious) class.

        Handles both 1D (single vector) and 2D inputs.
        """
        arr = np.asarray(X, dtype=float)
        if arr.ndim == 1:
            arr = arr.reshape(1, -1)

        if not hasattr(self.classifier, "classes_"):
            raise RuntimeError("Model has not been fitted.")

        probs = self.classifier.predict_proba(arr)
        # Class 1 is the positive (DGA) class
        pos_idx = np.where(self.classifier.classes_ == 1)[0]
        if len(pos_idx) > 0:
            return probs[:, pos_idx[0]]
        return probs[:, 1] if probs.shape[1] > 1 else probs[:, 0]

    def predict(
        self,
        X: Union[list[float], list[list[float]], np.ndarray],
        threshold: Optional[float] = None,
    ) -> np.ndarray:
        """
        Binary classification based on decision threshold.

        Returns 1 (DGA) if proba >= threshold, else 0 (benign).
        """
        t = self.threshold if threshold is None else threshold
        probs = self.predict_proba(X)
        return (probs >= t).astype(int)

    def save(self, path: str | Path) -> None:
        """Persist model and metadata via joblib."""
        save_path = Path(path)
        save_path.parent.mkdir(parents=True, exist_ok=True)
        bundle = {
            "classifier": self.classifier,
            "model_version": self.model_version,
            "threshold": self.threshold,
            "feature_names": self.feature_names,
            "metadata": self.metadata,
        }
        joblib.dump(bundle, save_path)

    @classmethod
    def load(cls, path: str | Path) -> DGAModel:
        """Load persisted model bundle from disk."""
        load_path = Path(path)
        if not load_path.exists():
            raise FileNotFoundError(f"Model file not found: {load_path}")
        bundle = joblib.load(load_path)
        return cls(
            classifier=bundle["classifier"],
            model_version=bundle.get("model_version", DEFAULT_MODEL_VERSION),
            threshold=bundle.get("threshold", DEFAULT_THRESHOLD),
            feature_names=bundle.get("feature_names", FEATURE_NAMES),
            metadata=bundle.get("metadata", {}),
        )
