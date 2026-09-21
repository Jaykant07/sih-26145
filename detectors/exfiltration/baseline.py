"""
Rolling per-host benign baseline tracker for Data Exfiltration Detector (PS-26145 — Track B).

Tracks historical benign byte-ratio and outbound volume observations on a
per-source-host basis. Computes statistical baseline deviations (Z-score and
fold-change multiple relative to historical distribution) and explicitly reports
when insufficient baseline observations exist.
"""

from __future__ import annotations

import json
import logging
import math
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("exfiltration.baseline")

DEFAULT_MIN_OBSERVATIONS: int = 3


class HostExfilBaseline:
    """
    Per-source-host historical baseline manager.
    Tracks clean historical (byte_ratio, outbound_bytes) samples.
    """

    def __init__(self, min_observations: int = DEFAULT_MIN_OBSERVATIONS) -> None:
        self.min_observations = min_observations
        # {src_ip: [{"ratio": float, "volume": int, "timestamp": float}]}
        self.history: dict[str, list[dict[str, Any]]] = {}

    def add_observation(
        self,
        src_ip: str,
        byte_ratio: float,
        outbound_bytes: int,
        timestamp: Optional[float] = None,
    ) -> None:
        """Record a benign observation for a source host."""
        if src_ip not in self.history:
            self.history[src_ip] = []

        self.history[src_ip].append({
            "ratio": float(byte_ratio),
            "volume": int(outbound_bytes),
            "timestamp": timestamp,
        })

    def get_host_stats(self, src_ip: str) -> Optional[dict[str, Any]]:
        """Compute summary statistics for a given host if observations exist."""
        samples = self.history.get(src_ip, [])
        if not samples:
            return None

        ratios = [s["ratio"] for s in samples]
        volumes = [s["volume"] for s in samples]
        n = len(samples)

        mean_ratio = sum(ratios) / n
        var_ratio = sum((r - mean_ratio) ** 2 for r in ratios) / n if n > 1 else 0.0
        std_ratio = math.sqrt(var_ratio)

        mean_vol = sum(volumes) / n
        var_vol = sum((v - mean_vol) ** 2 for v in volumes) / n if n > 1 else 0.0
        std_vol = math.sqrt(var_vol)

        return {
            "sample_count": n,
            "mean_ratio": round(mean_ratio, 4),
            "std_ratio": round(std_ratio, 4),
            "max_ratio": round(max(ratios), 4),
            "mean_volume": round(mean_vol, 2),
            "std_volume": round(std_vol, 2),
            "max_volume": max(volumes),
        }

    def calculate_deviation(
        self,
        src_ip: str,
        current_ratio: float,
        current_volume: int,
    ) -> dict[str, Any]:
        """
        Calculate statistical deviation of current metrics from host baseline.

        Returns:
            dict containing:
              - baseline_deviation (float): Z-score of ratio deviation (0.0 if insufficient data)
              - ratio_multiple (float): current_ratio / max(mean_ratio, 0.01)
              - insufficient_baseline_data (bool): True if sample_count < min_observations
              - baseline_sample_count (int)
              - historical_mean_ratio (float)
              - explanation (str)
        """
        stats = self.get_host_stats(src_ip)

        if stats is None or stats["sample_count"] < self.min_observations:
            count = stats["sample_count"] if stats else 0
            return {
                "baseline_deviation": 0.0,
                "ratio_multiple": 1.0,
                "insufficient_baseline_data": True,
                "baseline_sample_count": count,
                "historical_mean_ratio": stats["mean_ratio"] if stats else None,
                "historical_std_ratio": stats["std_ratio"] if stats else None,
                "explanation": (
                    f"Insufficient baseline data for host {src_ip} "
                    f"(observed {count} samples, minimum required is {self.min_observations})."
                ),
            }

        mean_r = stats["mean_ratio"]
        std_r = stats["std_ratio"]

        # Prevent zero-division on std
        effective_std = std_r if std_r > 0.05 else 0.05
        z_score = (current_ratio - mean_r) / effective_std

        # Fold change multiple
        ratio_multiple = current_ratio / max(mean_r, 0.01)

        explanation = (
            f"Observed ratio {current_ratio:.2f} deviates by {z_score:.2f} sigma "
            f"({ratio_multiple:.1f}x mean) from historical baseline (mean={mean_r:.2f}, std={std_r:.2f}, n={stats['sample_count']})."
        )

        return {
            "baseline_deviation": round(z_score, 4),
            "ratio_multiple": round(ratio_multiple, 2),
            "insufficient_baseline_data": False,
            "baseline_sample_count": stats["sample_count"],
            "historical_mean_ratio": mean_r,
            "historical_std_ratio": std_r,
            "historical_mean_volume": stats["mean_volume"],
            "explanation": explanation,
        }

    def save_to_file(self, filepath: str | Path) -> None:
        """Save serialized baseline data to JSON file."""
        p = Path(filepath)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "min_observations": self.min_observations,
                    "history": self.history,
                },
                f,
                indent=2,
            )

    def load_from_file(self, filepath: str | Path) -> None:
        """Load baseline data from JSON file."""
        p = Path(filepath)
        if not p.exists():
            raise FileNotFoundError(f"Baseline file not found: {p}")
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
            self.min_observations = data.get("min_observations", DEFAULT_MIN_OBSERVATIONS)
            self.history = data.get("history", {})
