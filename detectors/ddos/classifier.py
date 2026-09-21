"""
DDoS sub-classification logic for PS-26145.

After the detector determines that a window is anomalous (rate anomaly
AND entropy anomaly), this module classifies the specific DDoS pattern
based on protocol ratios, connection states, source distribution, and
directional byte volumes.

Sub-types:
  - syn_flood
  - udp_flood
  - reflection_amplification_like
  - spoofing_like
  - volumetric_generic   (fallback)

IMPORTANT:
  Labels such as ``reflection_amplification_like`` and ``spoofing_like``
  use the ``_like`` suffix because passive flow metadata cannot
  definitively prove reflection or spoofing — only that the traffic
  pattern is consistent with such behaviour.
"""

from __future__ import annotations

from typing import Any

from detectors.ddos.config import DDoSConfig
from features.flow_stats import FlowWindow


def classify_ddos(
    window: FlowWindow,
    config: DDoSConfig,
) -> tuple[str, dict[str, Any]]:
    """
    Classify a confirmed DDoS anomaly into a specific sub-type.

    Args:
        window: The anomalous :class:`FlowWindow`.
        config: Detector configuration.

    Returns:
        ``(subtype, evidence_dict)`` where subtype is one of
        ``syn_flood``, ``udp_flood``, ``reflection_amplification_like``,
        ``spoofing_like``, or ``volumetric_generic``.
    """
    evidence: dict[str, Any] = {}

    # --- SYN flood --------------------------------------------------------
    if window.tcp_flow_count > 0:
        syn_ratio = window.tcp_syn_count / window.tcp_flow_count
        evidence["tcp_syn_ratio"] = round(syn_ratio, 4)
        evidence["tcp_syn_count"] = window.tcp_syn_count
        evidence["tcp_syn_ack_count"] = window.tcp_syn_ack_count
        evidence["tcp_flow_count"] = window.tcp_flow_count

        if syn_ratio >= config.syn_ratio_threshold:
            return "syn_flood", evidence

    # --- UDP flood --------------------------------------------------------
    if window.flow_count > 0:
        udp_ratio = window.udp_flow_count / window.flow_count
        evidence["udp_ratio"] = round(udp_ratio, 4)
        evidence["udp_flow_count"] = window.udp_flow_count

        if udp_ratio >= config.udp_ratio_threshold:
            # Check for reflection/amplification-like pattern within UDP
            if (
                window.unique_source_count >= config.min_unique_sources_reflection
                and window.total_orig_ip_bytes > 0
            ):
                resp_ratio = (
                    window.total_resp_ip_bytes / window.total_orig_ip_bytes
                )
                evidence["resp_to_orig_byte_ratio"] = round(resp_ratio, 4)

                if resp_ratio >= config.reflection_resp_ratio:
                    evidence["unique_source_count"] = window.unique_source_count
                    return "reflection_amplification_like", evidence

            return "udp_flood", evidence

    # --- Spoofing-like ----------------------------------------------------
    if window.unique_source_count >= config.min_unique_sources_spoofing:
        evidence["unique_source_count"] = window.unique_source_count
        evidence["src_ip_entropy"] = round(window.src_ip_entropy, 4)

        # Spoofing-like: many diverse sources, potentially with abnormal
        # connection completion behaviour
        if window.tcp_flow_count > 0:
            completion_ratio = window.tcp_syn_ack_count / window.tcp_flow_count
            evidence["tcp_completion_ratio"] = round(completion_ratio, 4)

        return "spoofing_like", evidence

    # --- Volumetric generic (fallback) ------------------------------------
    evidence["flow_count"] = window.flow_count
    evidence["unique_source_count"] = window.unique_source_count
    return "volumetric_generic", evidence
