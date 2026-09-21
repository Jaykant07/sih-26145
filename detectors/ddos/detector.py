"""
DDoS detector for PS-26145.

Implements the 7-step detection algorithm:
  1. Flow window consumption
  2. Rolling baseline (clean windows only)
  3. Z-score for pkt_rate and byte_rate
  4. Source-IP entropy anomaly detection
  5. AND-gated decision: rate_anomaly AND entropy_anomaly
  6. Sub-classification (SYN flood, UDP flood, etc.)
  7. DRAFT alert emission

This implementation is initially rule/statistical based.
ML is intentionally deferred until measured labeled replay data
demonstrates that the statistical detector is insufficient.

CONFIDENCE METHODOLOGY:
  Confidence is derived deterministically from the z-scores and entropy
  anomaly magnitude.  It is NOT a calibrated probability.  It is a
  bounded [0.0, 1.0] heuristic score computed as:

    raw = max(pkt_z, byte_z) / (2 * z_threshold)
    confidence = min(raw, 1.0)

  This maps the z-score linearly into [0, 1], where:
    - z == z_threshold  → confidence ≈ 0.5
    - z == 2*threshold  → confidence ≈ 1.0
    - z > 2*threshold   → confidence = 1.0 (capped)

  This is a transparent, deterministic transformation documented here.
  It must not be described as a calibrated probability.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from alerts.constants import LatencyClass, Severity, ThreatClass
from alerts.draft import DraftAlert, create_draft_alert
from detectors.ddos.baseline import BaselineStore
from detectors.ddos.classifier import classify_ddos
from detectors.ddos.config import DDoSConfig
from features.flow_stats import FlowWindow, build_flow_windows
from ingest.parser import parse_conn_log

logger = logging.getLogger(__name__)

DETECTOR_NAME = "ddos_detector"
DETECTOR_VERSION = "0.1.0"


class DDoSDetector:
    """
    Stateful DDoS detector operating on FlowWindow objects.

    Maintains per-destination rolling baselines and emits DRAFT alerts
    when the AND-gated decision rule triggers:

        rate_anomaly AND entropy_anomaly

    Rate anomaly:
        pkt_z_score >= z_threshold  OR  byte_z_score >= z_threshold

    Entropy anomaly:
        abs(entropy_z_score) >= entropy_z_threshold
        (detects both significant drops and significant spikes)

    CRITICAL:
        Flagged windows are NOT added to the clean baseline.
    """

    def __init__(self, config: DDoSConfig | None = None) -> None:
        self.config = config or DDoSConfig()
        self.baseline_store = BaselineStore(
            max_windows=self.config.baseline_windows,
            epsilon=self.config.epsilon,
        )
        self._alerts: list[DraftAlert] = []

    @property
    def alerts(self) -> list[DraftAlert]:
        """All alerts generated so far."""
        return list(self._alerts)

    def process_window(self, window: FlowWindow) -> DraftAlert | None:
        """
        Process a single FlowWindow and optionally emit a DRAFT alert.

        Steps:
          1. Skip windows with too few flows.
          2. Compute z-scores against rolling baseline.
          3. Check AND-gated decision rule.
          4. Sub-classify if anomalous.
          5. Emit DRAFT alert.
          6. Update baseline (clean windows only).

        Args:
            window: A :class:`FlowWindow` to evaluate.

        Returns:
            A :class:`DraftAlert` if the window triggers, else ``None``.
        """
        cfg = self.config
        baseline = self.baseline_store.get(window.destination_ip)

        # Skip sparse windows
        if window.flow_count < cfg.min_flows_for_detection:
            # Still add to baseline (sparse windows are not anomalous)
            baseline.add_clean_window(
                pkt_rate=window.pkt_rate,
                byte_rate=window.byte_rate,
                src_ip_entropy=window.src_ip_entropy,
            )
            return None

        # If baseline not ready, add to it and skip detection
        if not baseline.is_ready:
            baseline.add_clean_window(
                pkt_rate=window.pkt_rate,
                byte_rate=window.byte_rate,
                src_ip_entropy=window.src_ip_entropy,
            )
            return None

        # --- Step 3: Z-scores ------------------------------------------------
        pkt_z = baseline.pkt_rate.z_score(window.pkt_rate)
        byte_z = baseline.byte_rate.z_score(window.byte_rate)
        entropy_z = baseline.entropy.z_score(window.src_ip_entropy)

        # --- Step 4 & 5: Decision rule ---------------------------------------
        rate_anomaly = (pkt_z >= cfg.z_threshold) or (byte_z >= cfg.z_threshold)

        # Entropy anomaly: significant drop OR significant spike
        entropy_anomaly = abs(entropy_z) >= cfg.entropy_z_threshold

        is_flagged = rate_anomaly and entropy_anomaly

        if not is_flagged:
            # Clean window — add to baseline
            baseline.add_clean_window(
                pkt_rate=window.pkt_rate,
                byte_rate=window.byte_rate,
                src_ip_entropy=window.src_ip_entropy,
            )
            return None

        # --- FLAGGED: do NOT add to baseline (baseline poisoning prevention) -

        # --- Step 6: Sub-classification --------------------------------------
        subtype, classification_evidence = classify_ddos(window, cfg)

        # --- Confidence -------------------------------------------------------
        max_z = max(pkt_z, byte_z)
        raw_confidence = max_z / (2.0 * cfg.z_threshold)
        confidence = min(max(raw_confidence, 0.0), 1.0)

        # --- Severity ---------------------------------------------------------
        severity = _compute_severity(confidence, window)

        # --- Step 7: DRAFT alert ---------------------------------------------
        window_id = (
            f"w_{window.destination_ip}_{window.window_start:.0f}_"
            f"{window.window_end:.0f}"
        )

        # Determine source representation
        if window.unique_source_count == 1:
            source = next(iter(window.source_ip_counts))
        else:
            source = "multiple"

        # Build supporting evidence
        evidence: dict[str, Any] = {
            # Window context
            "window_seconds": cfg.window_seconds,
            "window_start": window.window_start,
            "window_end": window.window_end,
            # Volume
            "flow_count": window.flow_count,
            "packet_count": window.packet_count,
            "byte_count": window.byte_count,
            "pkt_rate": round(window.pkt_rate, 4),
            "byte_rate": round(window.byte_rate, 4),
            # Z-scores
            "pkt_z_score": round(pkt_z, 4),
            "byte_z_score": round(byte_z, 4),
            "z_threshold": cfg.z_threshold,
            # Baseline context
            "baseline_pkt_rate_mean": round(baseline.pkt_rate.mean, 4),
            "baseline_pkt_rate_stddev": round(baseline.pkt_rate.stddev, 4),
            "baseline_byte_rate_mean": round(baseline.byte_rate.mean, 4),
            "baseline_byte_rate_stddev": round(baseline.byte_rate.stddev, 4),
            # Entropy
            "src_ip_entropy": round(window.src_ip_entropy, 4),
            "entropy_z_score": round(entropy_z, 4),
            "entropy_z_threshold": cfg.entropy_z_threshold,
            "baseline_entropy_mean": round(baseline.entropy.mean, 4),
            "baseline_entropy_stddev": round(baseline.entropy.stddev, 4),
            "entropy_anomaly_type": (
                "drop" if entropy_z < 0 else "spike"
            ),
            # Source diversity
            "unique_source_count": window.unique_source_count,
            # Protocol
            "tcp_flow_count": window.tcp_flow_count,
            "udp_flow_count": window.udp_flow_count,
            "icmp_flow_count": window.icmp_flow_count,
            "tcp_syn_count": window.tcp_syn_count,
            # Confidence methodology
            "confidence_method": (
                "deterministic_z_score_transform: "
                "min(max_z / (2 * z_threshold), 1.0)"
            ),
        }
        # Merge classification-specific evidence
        evidence.update(classification_evidence)

        timestamp = datetime.fromtimestamp(
            window.window_start, tz=timezone.utc
        ).isoformat()

        alert = create_draft_alert(
            timestamp=timestamp,
            flow_id=window_id,
            threat_class=ThreatClass.DDOS,
            severity=severity,
            confidence=confidence,
            source=source,
            destination=window.destination_ip,
            supporting_evidence=evidence,
            detector=DETECTOR_NAME,
            detector_version=DETECTOR_VERSION,
            subtype=subtype,
            latency_class=LatencyClass.EVENT_DRIVEN,
        )

        self._alerts.append(alert)
        logger.info(
            "DDoS alert: %s → %s [%s] confidence=%.3f severity=%s",
            source,
            window.destination_ip,
            subtype,
            confidence,
            severity,
        )
        return alert

    def process_windows(self, windows: list[FlowWindow]) -> list[DraftAlert]:
        """
        Process multiple flow windows in order.

        Args:
            windows: List of :class:`FlowWindow` objects, ideally sorted
                     by ``window_start``.

        Returns:
            List of generated DRAFT alerts.
        """
        new_alerts: list[DraftAlert] = []
        for w in windows:
            alert = self.process_window(w)
            if alert is not None:
                new_alerts.append(alert)
        return new_alerts

    def reset(self) -> None:
        """Reset detector state (baselines and alerts)."""
        self.baseline_store = BaselineStore(
            max_windows=self.config.baseline_windows,
            epsilon=self.config.epsilon,
        )
        self._alerts.clear()


def _compute_severity(confidence: float, window: FlowWindow) -> str:
    """
    Compute initial detector-level severity.

    This is NOT fusion-level severity — it will be refined by the
    OT-aware fusion pipeline based on asset criticality.

    Mapping (based on confidence):
      confidence >= 0.8  → HIGH
      confidence >= 0.5  → MEDIUM
      else               → LOW
    """
    if confidence >= 0.8:
        return Severity.HIGH
    elif confidence >= 0.5:
        return Severity.MEDIUM
    else:
        return Severity.LOW


# ---------------------------------------------------------------------------
# CLI entry point for standalone execution
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Run the DDoS detector against a Zeek conn.log file.

    Usage:
        python -m detectors.ddos.detector --input <conn.log> --output <dir>
    """
    import argparse

    parser = argparse.ArgumentParser(
        description="PS-26145 DDoS Detector — run against Zeek conn.log"
    )
    parser.add_argument(
        "--input", required=True, help="Path to Zeek conn.log (JSON format)"
    )
    parser.add_argument(
        "--output", default="artifacts/ddos",
        help="Output directory for results (default: artifacts/ddos)"
    )
    parser.add_argument(
        "--window", type=float, default=10.0,
        help="Window size in seconds (default: 10.0)"
    )
    parser.add_argument(
        "--baseline-windows", type=int, default=30,
        help="Number of baseline windows (default: 30)"
    )
    parser.add_argument(
        "--z-threshold", type=float, default=4.0,
        help="Z-score threshold (default: 4.0)"
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    # Configure
    config = DDoSConfig(
        window_seconds=args.window,
        baseline_windows=args.baseline_windows,
        z_threshold=args.z_threshold,
    )

    # Parse
    logger.info("Parsing %s ...", args.input)
    records = list(parse_conn_log(args.input))
    logger.info("Parsed %d connection records", len(records))

    # Window
    logger.info("Building flow windows (%.1fs) ...", config.window_seconds)
    windows = build_flow_windows(records, window_seconds=config.window_seconds)
    logger.info("Built %d flow windows", len(windows))

    # Detect
    detector = DDoSDetector(config=config)
    alerts = detector.process_windows(windows)
    logger.info("Generated %d DDoS alerts", len(alerts))

    # Save results
    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Alerts
    alerts_path = out_dir / "sample_alerts.json"
    with alerts_path.open("w") as f:
        json.dump([a.to_dict() for a in alerts], f, indent=2)
    logger.info("Saved alerts to %s", alerts_path)

    # Detector results (all windows summary)
    results = {
        "input_file": str(args.input),
        "total_records": len(records),
        "total_windows": len(windows),
        "alerts_generated": len(alerts),
        "config": {
            "window_seconds": config.window_seconds,
            "baseline_windows": config.baseline_windows,
            "z_threshold": config.z_threshold,
            "entropy_z_threshold": config.entropy_z_threshold,
            "epsilon": config.epsilon,
        },
        "destinations_analyzed": len(set(w.destination_ip for w in windows)),
    }
    results_path = out_dir / "detector_results.json"
    with results_path.open("w") as f:
        json.dump(results, f, indent=2)
    logger.info("Saved results to %s", results_path)


if __name__ == "__main__":
    main()
