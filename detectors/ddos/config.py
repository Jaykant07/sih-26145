"""
DDoS detector configuration for PS-26145.

All thresholds are initial prototype values and must be configurable.
None of these values are claimed as scientifically optimal universal constants.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class DDoSConfig:
    """
    Configuration for the DDoS detector.

    All numeric thresholds are initial prototype values chosen for the
    controlled-lab evaluation environment.  They are intentionally
    configurable and will require tuning for production deployments.
    """

    # ---- Flow window --------------------------------------------------------
    window_seconds: float = 10.0
    """Window duration in seconds for flow aggregation.
    Initial prototype value — not claimed as scientifically optimal."""

    # ---- Rolling baseline ---------------------------------------------------
    baseline_windows: int = 30
    """Number of clean (non-flagged) windows to maintain per destination
    in the rolling baseline.  Configurable prototype parameter."""

    # ---- Z-score thresholds -------------------------------------------------
    z_threshold: float = 4.0
    """Z-score threshold for rate anomaly (pkt_rate / byte_rate).
    Initial tunable threshold — not a universal constant."""

    epsilon: float = 1e-9
    """Minimum denominator to prevent division by zero in z-score."""

    # ---- Entropy anomaly ----------------------------------------------------
    entropy_z_threshold: float = 3.0
    """Z-score threshold for entropy anomaly detection.
    Initial tunable threshold — not a universal constant."""

    # ---- Sub-classification -------------------------------------------------
    syn_ratio_threshold: float = 0.8
    """Fraction of TCP flows that must be SYN-only to classify as SYN flood."""

    udp_ratio_threshold: float = 0.8
    """Fraction of flows that must be UDP to classify as UDP flood."""

    reflection_resp_ratio: float = 3.0
    """Response-to-request byte ratio threshold for reflection-like classification."""

    min_unique_sources_reflection: int = 10
    """Minimum unique source IPs to consider reflection/amplification-like."""

    min_unique_sources_spoofing: int = 20
    """Minimum unique source IPs to consider spoofing-like pattern."""

    # ---- General ------------------------------------------------------------
    min_flows_for_detection: int = 5
    """Minimum flows in a window to be considered for DDoS detection.
    Prevents noise alerts from very sparse windows."""
