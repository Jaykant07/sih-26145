"""
Deterministic severity scoring engine for PS-26145.

Evaluates operational severity based on threat class, asset criticality, and
multi-threat correlation.

MANDATORY PRINCIPLE:
Confidence != Severity.
Detector confidence must remain strictly untouched and preserved.
"""

from __future__ import annotations

import logging
from typing import Any

from alerts.constants import Severity, ThreatClass

logger = logging.getLogger(__name__)

# Severity hierarchy from lowest to highest
SEVERITY_LADDER: list[str] = [
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
]

# Explicit, deterministic base severity mapping per threat class
BASE_SEVERITY_MAP: dict[str, str] = {
    ThreatClass.RECONNAISSANCE: Severity.LOW,
    ThreatClass.SCANNING: Severity.LOW,
    ThreatClass.BEACONING: Severity.MEDIUM,
    ThreatClass.DGA: Severity.MEDIUM,
    ThreatClass.DGA_DNS: Severity.MEDIUM,
    ThreatClass.TLS_ANOMALY: Severity.MEDIUM,
    ThreatClass.DDOS: Severity.HIGH,
    ThreatClass.DNS_TUNNEL: Severity.HIGH,
    ThreatClass.EXFILTRATION: Severity.HIGH,
}


def get_base_severity(threat_class: str) -> str:
    """
    Get the explainable base severity for a given threat class.
    Defaults to Severity.MEDIUM if unknown.
    """
    return BASE_SEVERITY_MAP.get(threat_class.lower(), Severity.MEDIUM)


def escalate_severity(current_severity: str) -> str:
    """
    Deterministically escalate severity by one step on the severity ladder.
    Ceiling is Severity.CRITICAL.
    """
    curr = current_severity.lower()
    if curr not in SEVERITY_LADDER:
        return Severity.MEDIUM

    idx = SEVERITY_LADDER.index(curr)
    if idx < len(SEVERITY_LADDER) - 1:
        return SEVERITY_LADDER[idx + 1]
    return SEVERITY_LADDER[-1]


def compute_fused_severity(
    threat_class: str,
    asset_criticality: str,
    is_correlated: bool,
) -> tuple[str, dict[str, Any]]:
    """
    Compute final operational severity through deterministic escalation.

    Escalation Order:
      1. Base severity from threat class
      2. +1 step if asset_criticality == 'critical'
      3. +1 step if is_correlated (group with >= 2 distinct threats)

    Returns:
        `(final_severity, explanation_metadata)`
    """
    base_sev = get_base_severity(threat_class)
    current_sev = base_sev

    criticality_escalated = False
    if asset_criticality.lower() == "critical":
        current_sev = escalate_severity(current_sev)
        criticality_escalated = True

    correlation_escalated = False
    if is_correlated:
        current_sev = escalate_severity(current_sev)
        correlation_escalated = True

    explanation = {
        "base_severity": base_sev,
        "criticality_escalated": criticality_escalated,
        "correlation_escalated": correlation_escalated,
        "final_severity": current_sev,
    }

    return current_sev, explanation


def apply_fused_severity(
    alert: dict[str, Any],
    is_correlated: bool,
) -> dict[str, Any]:
    """
    Apply fused severity to the alert dictionary while strictly preserving confidence.
    """
    threat_class = alert.get("threat_class", "")
    asset_criticality = alert.get("asset_criticality", "unknown")

    # PRESERVE DETECTOR CONFIDENCE BIT-FOR-BIT
    original_confidence = alert.get("confidence")

    final_sev, metadata = compute_fused_severity(
        threat_class=threat_class,
        asset_criticality=asset_criticality,
        is_correlated=is_correlated,
    )

    alert["severity"] = final_sev

    # Verify confidence was not modified
    assert alert.get("confidence") == original_confidence, "CONFIDENCE MUST NEVER BE MODIFIED"

    # Annotate evidence with fusion explanation
    evidence = alert.get("supporting_evidence")
    if isinstance(evidence, dict):
        evidence["fusion_metadata"] = metadata

    return alert
