"""
Behavioral Anomaly Scoring Model for Encrypted TLS Sessions (Track B).

Calculates a normalized behavioral anomaly score in [0.0, 1.0] based on
connection-level metadata features:
  - Asymmetric byte ratio (upload/download volume imbalance)
  - Mean packet size deviation from benign TLS baseline
  - Packet count and connection duration context

Operates strictly on connection metadata without packet payload inspection.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

logger = logging.getLogger("tls_behavior")

DEFAULT_BEHAVIORAL_THRESHOLD = 0.50
MODEL_VERSION = "1.0.0"

# Calibrated benign TLS baseline parameters (derived from enc-001 baseline)
BASELINE_BYTE_RATIO_REFERENCE = 2.0
BASELINE_BYTE_RATIO_SCALE = 2.0

BASELINE_PKT_SIZE_REFERENCE = 360.0
BASELINE_PKT_SIZE_SCALE = 300.0


class TLSBehaviorModel:
    """
    Explainable statistical anomaly model for encrypted TLS traffic.
    Quantifies upload exfiltration asymmetry and packet volume shifts.
    """

    def __init__(
        self,
        threshold: float = DEFAULT_BEHAVIORAL_THRESHOLD,
        model_version: str = MODEL_VERSION,
    ) -> None:
        self.threshold = threshold
        self.model_version = model_version

    def compute_score(self, features: dict[str, Any]) -> float:
        """
        Calculate normalized behavioral anomaly score in [0.0, 1.0].

        Higher scores reflect strong asymmetric data transmission (C2 uplink /
        data exfiltration) combined with oversized mean packet payloads.
        """
        byte_ratio = float(features.get("byte_ratio") or 0.0)
        mean_pkt_size = float(features.get("mean_packet_size") or 0.0)

        # Deviation in byte ratio above baseline reference
        d_ratio = max(0.0, (byte_ratio - BASELINE_BYTE_RATIO_REFERENCE) / BASELINE_BYTE_RATIO_SCALE)

        # Deviation in mean packet size above baseline reference
        d_pkt_size = max(
            0.0,
            (mean_pkt_size - BASELINE_PKT_SIZE_REFERENCE) / BASELINE_PKT_SIZE_SCALE,
        )

        # Weighted composite raw anomaly index (60% byte asymmetry, 40% packet size shift)
        raw_index = (0.60 * d_ratio) + (0.40 * d_pkt_size)

        # Non-linear squashing to [0.0, 1.0] range
        score = raw_index / (1.0 + raw_index)
        return round(float(score), 4)

    def is_anomalous(self, score: float, threshold: Optional[float] = None) -> bool:
        """Check if behavioral score meets or exceeds the decision threshold."""
        t = threshold if threshold is not None else self.threshold
        return score >= t

    def evaluate(
        self,
        features: dict[str, Any],
        threshold: Optional[float] = None,
    ) -> dict[str, Any]:
        """
        Evaluate connection features and return detailed diagnostic score breakdown.
        """
        t = threshold if threshold is not None else self.threshold
        score = self.compute_score(features)
        anomalous = self.is_anomalous(score, threshold=t)

        byte_ratio = float(features.get("byte_ratio") or 0.0)
        mean_pkt_size = float(features.get("mean_packet_size") or 0.0)

        explanations: list[str] = []
        if byte_ratio > BASELINE_BYTE_RATIO_REFERENCE:
            explanations.append(
                f"Elevated upload byte ratio {byte_ratio:.2f} (baseline <= {BASELINE_BYTE_RATIO_REFERENCE})"
            )
        if mean_pkt_size > BASELINE_PKT_SIZE_REFERENCE:
            explanations.append(
                f"Elevated mean packet size {mean_pkt_size:.1f}B (baseline <= {BASELINE_PKT_SIZE_REFERENCE}B)"
            )

        return {
            "behavioral_score": score,
            "is_anomalous": anomalous,
            "threshold": t,
            "model_version": self.model_version,
            "mean_packet_size": mean_pkt_size,
            "byte_ratio": byte_ratio,
            "packet_count": features.get("packet_count", 0),
            "duration": features.get("duration", 0.0),
            "explanations": explanations,
        }
