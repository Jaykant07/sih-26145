"""
detectors/anomaly/scoring.py
Anomaly scoring and confidence calibration bridge for PS-26145 Detector #8.

Converts raw Isolation Forest decision scores into normalized anomaly confidence.

MANDATORY CONFIDENCE SEMANTICS (Phase 22 & 23):
The alert field 'confidence' represents the normalized anomaly score relative
to the benign training-score distribution clamped to [0.0, 1.0].
It is NOT a calibrated probability and MUST NOT be labeled as probability of malware.
"""

from __future__ import annotations

import math
from typing import Union


def calculate_raw_anomaly_score(decision_value: Union[float, int]) -> float:
    """
    Convert scikit-learn IsolationForest decision_function value to positive raw anomaly score.

    Isolation Forest returns negative scores for outliers and positive scores for inliers.
    Inverting sign ensures: higher raw_score = more anomalous.
    """
    if decision_value is None or math.isnan(decision_value) or math.isinf(decision_value):
        return 0.0
    return -float(decision_value)


def normalize_anomaly_score(
    raw_score: Union[float, int],
    benign_min: Union[float, int],
    benign_max: Union[float, int],
) -> float:
    """
    Normalize a raw anomaly score against the benign training baseline range.

    Formula:
        confidence = (raw_score - benign_min) / (benign_max - benign_min)
        clamped strictly to [0.0, 1.0]

    Args:
        raw_score: Inverted decision function output (-decision_function).
        benign_min: Minimum raw anomaly score observed on benign training set.
        benign_max: Maximum raw anomaly score observed on benign training set.

    Returns:
        Confidence float in range [0.0, 1.0].
    """
    # Guard against invalid, NaN, or infinite inputs
    if raw_score is None or math.isnan(raw_score) or math.isinf(raw_score):
        return 0.0
    if benign_min is None or math.isnan(benign_min) or math.isinf(benign_min):
        return 0.0
    if benign_max is None or math.isnan(benign_max) or math.isinf(benign_max):
        return 0.0

    raw_val = float(raw_score)
    b_min = float(benign_min)
    b_max = float(benign_max)

    # Degenerate or inverted baseline range
    if b_max <= b_min:
        return 0.0

    confidence = (raw_val - b_min) / (b_max - b_min)

    # Clamp strictly to [0.0, 1.0]
    return max(0.0, min(1.0, float(confidence)))
