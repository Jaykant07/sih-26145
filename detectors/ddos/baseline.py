"""
Rolling baseline for DDoS detection in PS-26145.

Maintains a per-destination rolling window of *clean* (non-flagged)
metric observations for calculating z-scores.

CRITICAL INVARIANT:
  Flagged windows are NEVER added to the clean baseline.
  This prevents baseline poisoning during sustained attacks.
"""

from __future__ import annotations

import math
from collections import deque
from dataclasses import dataclass, field


@dataclass
class MetricBaseline:
    """
    Rolling baseline for a single numeric metric.

    Maintains the last *max_size* clean observations in a fixed-size
    deque and provides incremental mean/stddev/z-score computation.
    """

    max_size: int
    epsilon: float = 1e-9
    _values: deque[float] = field(default_factory=deque, repr=False)

    def __post_init__(self) -> None:
        # Ensure the deque respects max_size if pre-populated
        if not isinstance(self._values, deque):
            self._values = deque(self._values, maxlen=self.max_size)
        else:
            self._values = deque(self._values, maxlen=self.max_size)

    @property
    def count(self) -> int:
        """Number of observations currently in the baseline."""
        return len(self._values)

    @property
    def is_ready(self) -> bool:
        """True when at least 2 observations exist (enough for stddev)."""
        return len(self._values) >= 2

    def add(self, value: float) -> None:
        """Add a clean observation to the baseline."""
        self._values.append(value)

    @property
    def mean(self) -> float:
        """Arithmetic mean of baseline observations."""
        if not self._values:
            return 0.0
        return sum(self._values) / len(self._values)

    @property
    def stddev(self) -> float:
        """Population standard deviation of baseline observations."""
        n = len(self._values)
        if n < 2:
            return 0.0
        m = self.mean
        variance = sum((v - m) ** 2 for v in self._values) / n
        return math.sqrt(variance)

    def z_score(self, value: float) -> float:
        """
        Calculate z-score for a given value against the baseline.

        z = (value - mean) / max(stddev, epsilon)

        When the baseline has zero variance (stddev < epsilon), the
        z-score is computed against epsilon to avoid division by zero.
        A zero-variance baseline with value == mean returns 0.0.

        Args:
            value: The current observation to score.

        Returns:
            Z-score (can be negative for below-average values).
        """
        m = self.mean
        s = self.stddev
        return (value - m) / max(s, self.epsilon)


class DestinationBaseline:
    """
    Per-destination rolling baselines for DDoS detection.

    Tracks three metrics independently:
      - pkt_rate
      - byte_rate
      - src_ip_entropy

    CRITICAL:
      Only call :meth:`add_clean_window` for windows that were NOT
      flagged as anomalous.  This prevents baseline poisoning.
    """

    def __init__(self, max_windows: int = 30, epsilon: float = 1e-9) -> None:
        self.pkt_rate = MetricBaseline(max_size=max_windows, epsilon=epsilon)
        self.byte_rate = MetricBaseline(max_size=max_windows, epsilon=epsilon)
        self.entropy = MetricBaseline(max_size=max_windows, epsilon=epsilon)

    @property
    def is_ready(self) -> bool:
        """True when all three baselines have enough data for z-scores."""
        return (
            self.pkt_rate.is_ready
            and self.byte_rate.is_ready
            and self.entropy.is_ready
        )

    def add_clean_window(
        self,
        pkt_rate: float,
        byte_rate: float,
        src_ip_entropy: float,
    ) -> None:
        """
        Add metrics from a clean (non-flagged) window to all baselines.

        MUST NOT be called for flagged/anomalous windows.
        """
        self.pkt_rate.add(pkt_rate)
        self.byte_rate.add(byte_rate)
        self.entropy.add(src_ip_entropy)


class BaselineStore:
    """
    Collection of per-destination baselines.

    Each destination IP gets an independent :class:`DestinationBaseline`.
    """

    def __init__(self, max_windows: int = 30, epsilon: float = 1e-9) -> None:
        self._max_windows = max_windows
        self._epsilon = epsilon
        self._baselines: dict[str, DestinationBaseline] = {}

    def get(self, destination_ip: str) -> DestinationBaseline:
        """Get or create the baseline for a destination IP."""
        if destination_ip not in self._baselines:
            self._baselines[destination_ip] = DestinationBaseline(
                max_windows=self._max_windows,
                epsilon=self._epsilon,
            )
        return self._baselines[destination_ip]

    @property
    def destinations(self) -> list[str]:
        """List of all tracked destination IPs."""
        return list(self._baselines.keys())
