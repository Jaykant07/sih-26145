"""
detectors/anomaly/predict.py
Inference engine for PS-26145 Detector #8 (AI Behavioral Anomaly Detector).

Loads the frozen Isolation Forest pipeline, enforces schema validation,
scores incoming flows, normalizes anomaly scores to [0.0, 1.0], and emits
standardized DraftAlert objects using the unified alert factory.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any, Iterable, Optional

import joblib
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from alerts.constants import ThreatClass
from alerts.draft import DraftAlert, create_draft_alert
from detectors.anomaly.feature_engineering import (
    ALL_MODEL_FEATURES,
    FeatureSchemaError,
    load_feature_schema,
    prepare_feature_dataframe,
)
from detectors.anomaly.scoring import (
    calculate_raw_anomaly_score,
    normalize_anomaly_score,
)
from features.flow_stats import extract_flow_features
from ingest.parser import ConnRecord

logger = logging.getLogger(__name__)

DEFAULT_MODEL_PATH = REPO_ROOT / "models" / "anomaly" / "anomaly_pipeline.joblib"

_CACHED_DETECTOR: Optional[AnomalyDetector] = None


def get_anomaly_detector(
    model_path: Optional[Path | str] = None,
    anomaly_threshold: float = -0.05,
    min_confidence: float = 0.25,
) -> AnomalyDetector:
    """Return a reusable cached AnomalyDetector instance to avoid repeated disk reads."""
    global _CACHED_DETECTOR
    if model_path is not None:
        return AnomalyDetector(
            model_path=model_path,
            anomaly_threshold=anomaly_threshold,
            min_confidence=min_confidence,
        )
    if _CACHED_DETECTOR is None:
        _CACHED_DETECTOR = AnomalyDetector(
            model_path=DEFAULT_MODEL_PATH,
            anomaly_threshold=anomaly_threshold,
            min_confidence=min_confidence,
        )
    return _CACHED_DETECTOR


class AnomalyDetector:
    """
    AI Behavioral Anomaly Detector using Isolation Forest.

    Emits DraftAlerts with threat_class='anomalous_behavior' and normalized
    anomaly confidence relative to the benign training baseline.
    """


    def __init__(
        self,
        model_path: Optional[Path | str] = None,
        anomaly_threshold: float = -0.05,
        min_confidence: float = 0.25,
    ) -> None:
        """
        Initialize the detector with a trained model artifact.

        Args:
            model_path: Path to the joblib artifact.
            anomaly_threshold: Decision threshold on raw_score.
            min_confidence: Minimum normalized confidence to emit an alert (default: 0.25).
        """
        self.model_path = Path(model_path or DEFAULT_MODEL_PATH)
        self.anomaly_threshold = anomaly_threshold
        self.min_confidence = min_confidence

        if not self.model_path.is_file():
            raise FileNotFoundError(
                f"Trained anomaly model artifact not found at {self.model_path}. "
                "Run detectors/anomaly/train.py first."
            )

        payload = joblib.load(self.model_path)
        if not isinstance(payload, dict) or "pipeline" not in payload:
            raise ValueError(f"Corrupted or invalid model artifact at {self.model_path}")

        self.pipeline = payload["pipeline"]
        self.model_version = payload.get("model_version", "isolation-forest-v1")
        self.benign_min = payload.get("benign_score_min", 0.0)
        self.benign_max = payload.get("benign_score_max", 1.0)
        self.expected_features = payload.get("all_features", ALL_MODEL_FEATURES)

        # Verify feature schema consistency
        try:
            self.feature_schema = load_feature_schema()
        except Exception:
            self.feature_schema = {}

    def predict(
        self,
        records: Iterable[ConnRecord],
        pcap_id: Optional[str] = None,
    ) -> list[DraftAlert]:
        """
        Evaluate an iterable of ConnRecords and emit DraftAlerts for behavioral anomalies.

        Args:
            records: Iterable of ConnRecord objects.
            pcap_id: Optional UUID scoping identifier.

        Returns:
            List of validated DraftAlert instances.
        """
        records_list = list(records)
        if not records_list:
            return []

        # 1. Extract shared canonical features for all records
        extracted_data = []
        for r in records_list:
            feat_obj = extract_flow_features(r)
            d = feat_obj.to_dict()
            extracted_data.append(d)

        df_raw = pd.DataFrame(extracted_data)

        # 2. Prepare & validate feature DataFrame
        df_features = prepare_feature_dataframe(df_raw, schema=self.feature_schema)

        # 3. Predict decision function
        # decision_function returns positive for normal, negative for abnormal
        try:
            decision_values = self.pipeline.decision_function(df_features)
        except Exception as e:
            logger.error("Isolation Forest inference failed: %s", e)
            return []

        alerts: list[DraftAlert] = []

        for idx, (rec, dec_val) in enumerate(zip(records_list, decision_values)):
            raw_score = calculate_raw_anomaly_score(dec_val)
            confidence = normalize_anomaly_score(
                raw_score=raw_score,
                benign_min=self.benign_min,
                benign_max=self.benign_max,
            )

            # Trigger condition: raw_score > threshold AND normalized confidence >= min_confidence
            if raw_score > self.anomaly_threshold and confidence >= self.min_confidence:
                feat_summary = extracted_data[idx]
                evidence = {
                    "raw_anomaly_score": round(raw_score, 4),
                    "normalized_confidence": round(confidence, 4),
                    "benign_min": round(self.benign_min, 4),
                    "benign_max": round(self.benign_max, 4),
                    "uid": rec.uid,
                    "proto": rec.proto,
                    "conn_state": rec.conn_state,
                    "duration": round(feat_summary.get("duration", 0.0), 3),
                    "total_bytes": feat_summary.get("total_bytes", 0),
                    "total_pkts": feat_summary.get("total_pkts", 0),
                    "byte_rate": round(feat_summary.get("byte_rate", 0.0), 2),
                    "packet_rate": round(feat_summary.get("packet_rate", 0.0), 2),
                    "byte_ratio": round(feat_summary.get("byte_ratio", 0.0), 2),
                }
                if pcap_id:
                    evidence["pcap_id"] = pcap_id

                alert = create_draft_alert(
                    threat_class=ThreatClass.ANOMALOUS_BEHAVIOR,
                    confidence=confidence,
                    source=rec.src_ip,
                    destination=rec.dst_ip,
                    supporting_evidence=evidence,
                    detector="ai_behavioral_anomaly",
                    model_version=self.model_version,
                    flow_id=f"flow_{rec.uid}",
                )
                alerts.append(alert)

        logger.info(
            "AnomalyDetector evaluated %d flows; emitted %d anomalous_behavior alert(s)",
            len(records_list),
            len(alerts),
        )
        return alerts
