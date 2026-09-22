"""
tests/unit/test_anomaly_scoring.py
Unit tests for detectors.anomaly.scoring module.

Verifies:
  - Normal score within baseline range
  - Minimum score -> 0.0
  - Maximum score -> 1.0
  - Below minimum -> clamped to 0.0
  - Above maximum -> clamped to 1.0
  - Equal min/max -> 0.0
  - Invalid min/max (max < min) -> 0.0
  - NaN and infinite values -> 0.0
  - Raw score sign inversion (-decision_function)
  - Strict confidence bounds [0.0, 1.0]
"""

import math
import pytest

from detectors.anomaly.scoring import (
    calculate_raw_anomaly_score,
    normalize_anomaly_score,
)


class TestAnomalyScoring:

    def test_calculate_raw_anomaly_score_inversion(self) -> None:
        """Isolation Forest returns negative for anomalies; raw score must invert sign."""
        assert calculate_raw_anomaly_score(-0.35) == pytest.approx(0.35)
        assert calculate_raw_anomaly_score(0.20) == pytest.approx(-0.20)
        assert calculate_raw_anomaly_score(0.0) == 0.0

    def test_calculate_raw_anomaly_score_nan_inf(self) -> None:
        """NaN and inf decision values return 0.0 safely."""
        assert calculate_raw_anomaly_score(float("nan")) == 0.0
        assert calculate_raw_anomaly_score(float("inf")) == 0.0
        assert calculate_raw_anomaly_score(float("-inf")) == 0.0
        assert calculate_raw_anomaly_score(None) == 0.0

    def test_normal_score(self) -> None:
        """Mid-range score produces proportional confidence."""
        # benign range: [-0.20, 0.40] (spread = 0.60)
        # raw = 0.10 -> (0.10 - (-0.20)) / 0.60 = 0.30 / 0.60 = 0.50
        conf = normalize_anomaly_score(raw_score=0.10, benign_min=-0.20, benign_max=0.40)
        assert conf == pytest.approx(0.50)

    def test_minimum_score(self) -> None:
        """Score exactly equal to benign min yields confidence 0.0."""
        conf = normalize_anomaly_score(raw_score=-0.20, benign_min=-0.20, benign_max=0.40)
        assert conf == pytest.approx(0.0)

    def test_maximum_score(self) -> None:
        """Score exactly equal to benign max yields confidence 1.0."""
        conf = normalize_anomaly_score(raw_score=0.40, benign_min=-0.20, benign_max=0.40)
        assert conf == pytest.approx(1.0)

    def test_below_minimum_clamped(self) -> None:
        """Score below benign minimum is clamped to 0.0."""
        conf = normalize_anomaly_score(raw_score=-0.50, benign_min=-0.20, benign_max=0.40)
        assert conf == 0.0

    def test_above_maximum_clamped(self) -> None:
        """Score above benign maximum is clamped to 1.0."""
        conf = normalize_anomaly_score(raw_score=0.85, benign_min=-0.20, benign_max=0.40)
        assert conf == 1.0

    def test_equal_min_max(self) -> None:
        """Equal min and max (zero spread) yields 0.0 without ZeroDivisionError."""
        conf = normalize_anomaly_score(raw_score=0.30, benign_min=0.30, benign_max=0.30)
        assert conf == 0.0

    def test_invalid_min_max_inverted(self) -> None:
        """b_max <= b_min yields 0.0 safely."""
        conf = normalize_anomaly_score(raw_score=0.30, benign_min=0.50, benign_max=0.20)
        assert conf == 0.0

    def test_nan_and_inf_handling(self) -> None:
        """NaN or inf in any parameter produces safe 0.0."""
        assert normalize_anomaly_score(float("nan"), 0.0, 1.0) == 0.0
        assert normalize_anomaly_score(0.5, float("nan"), 1.0) == 0.0
        assert normalize_anomaly_score(0.5, 0.0, float("nan")) == 0.0
        assert normalize_anomaly_score(float("inf"), 0.0, 1.0) == 0.0
        assert normalize_anomaly_score(0.5, float("-inf"), 1.0) == 0.0
        assert normalize_anomaly_score(None, 0.0, 1.0) == 0.0

    def test_confidence_strictly_within_unit_interval(self) -> None:
        """Fuzz check: confidence is always in [0.0, 1.0]."""
        for raw in [-100.0, -1.0, 0.0, 0.25, 0.5, 0.75, 1.0, 2.0, 1000.0]:
            conf = normalize_anomaly_score(raw, -0.5, 0.8)
            assert 0.0 <= conf <= 1.0
