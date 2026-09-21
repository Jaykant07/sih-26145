"""
DRAFT alert factory for PS-26145.

Creates standardized DRAFT alert records that all detectors emit.
Acts as the single mandatory factory that validates every alert (fail-closed)
before passing it downstream to fusion/.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import logging
from typing import Any, Optional
import uuid

from alerts.constants import SCHEMA_VERSION, Severity
from alerts.validator import AlertValidationError, validate_alert

logger = logging.getLogger(__name__)


@dataclass
class DraftAlert:
    """
    Standardized DRAFT alert record per docs/04_alert_schema.json.

    Required fields:
        alert_id, timestamp, flow_id, threat_class, severity,
        confidence, source, destination, supporting_evidence,
        detector, model_version, schema_version

    Optional / Alias fields:
        detector_version, subtype, asset_criticality, correlated_alert_ids, latency_class
    """

    # Required
    alert_id: str
    timestamp: str
    flow_id: str
    threat_class: str
    severity: str
    confidence: float
    source: str
    destination: str
    supporting_evidence: dict[str, Any]
    detector: str
    model_version: str
    schema_version: str = SCHEMA_VERSION

    # Optional / Aliases
    detector_version: Optional[str] = None
    subtype: Optional[str] = None
    asset_criticality: Optional[str] = None
    correlation_id: Optional[str] = None
    correlated_alert_ids: Optional[list[str]] = None
    latency_class: Optional[str] = None

    def __post_init__(self) -> None:
        if self.model_version is None and self.detector_version is not None:
            self.model_version = self.detector_version
        elif self.detector_version is None and self.model_version is not None:
            self.detector_version = self.model_version

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict, excluding None optional fields."""
        d = asdict(self)
        return {k: v for k, v in d.items() if v is not None}


def create_draft_alert(
    threat_class: str = "",
    confidence: float = 0.0,
    source: str = "",
    destination: str = "",
    supporting_evidence: Optional[dict[str, Any]] = None,
    detector: str = "",
    model_version: Optional[str] = None,
    latency_class: Optional[str] = None,
    *,
    severity: str = Severity.MEDIUM,
    detector_version: Optional[str] = None,
    flow_id: Optional[str] = None,
    timestamp: Optional[str] = None,
    subtype: Optional[str] = None,
    asset_criticality: Optional[str] = None,
    correlation_id: Optional[str] = None,
    correlated_alert_ids: Optional[list[str]] = None,
    alert_id: Optional[str] = None,
    validate: bool = True,
    **kwargs: Any,
) -> DraftAlert:
    """
    Factory function to create a validated DRAFT alert.

    The factory automatically populates:
      - alert_id: UUIDv4 string
      - timestamp: Timezone-aware UTC ISO-8601 string (if not supplied)
      - schema_version: SCHEMA_VERSION ('1.0.0')
      - flow_id: Fallback identifier (if not supplied)

    Args:
        threat_class: Threat classification enum (e.g. 'ddos', 'beaconing').
        confidence: Detector confidence in [0.0, 1.0].
        source: Source IP or identifier.
        destination: Destination IP or identifier.
        supporting_evidence: Non-empty dictionary of deterministic measurements.
        detector: Detector identifier string.
        model_version: Model/detector version string.
        latency_class: 'event_driven' or 'periodic'.
        severity: Initial detector severity ('critical', 'high', 'medium', 'low', 'info').
        detector_version: Alias for model_version.
        flow_id: Identifier for the flow or window.
        timestamp: ISO 8601 UTC timestamp (auto-generated if None).
        subtype: Optional attack subtype.
        asset_criticality: Optional OT asset criticality string.
        correlated_alert_ids: Optional list of UUIDs.
        alert_id: Optional UUIDv4 string (auto-generated if None).
        validate: Whether to validate against schema before returning (default: True).

    Returns:
        A validated :class:`DraftAlert` instance.

    Raises:
        AlertValidationError: If validation fails (fail-closed).
    """
    # 1. Automatic alert_id generation (UUIDv4)
    final_alert_id = alert_id or str(uuid.uuid4())

    # 2. Automatic UTC ISO-8601 timestamp generation
    final_timestamp = timestamp or datetime.now(timezone.utc).isoformat()

    # 3. Automatic flow_id fallback
    final_flow_id = flow_id or f"{source}_{destination}"

    # 4. Version synchronization
    version = model_version or detector_version or kwargs.get("version") or "1.0.0"

    # 5. Evidence dictionary
    evidence = supporting_evidence if supporting_evidence is not None else {}

    # Handle any kwargs that might map to fields
    final_severity = kwargs.get("severity", severity)
    final_subtype = kwargs.get("subtype", subtype)
    final_latency = kwargs.get("latency_class", latency_class)

    alert = DraftAlert(
        alert_id=final_alert_id,
        timestamp=final_timestamp,
        flow_id=final_flow_id,
        threat_class=threat_class,
        severity=final_severity,
        confidence=confidence,
        source=source,
        destination=destination,
        supporting_evidence=evidence,
        detector=detector,
        model_version=version,
        detector_version=version,
        subtype=final_subtype,
        asset_criticality=asset_criticality,
        correlation_id=correlation_id,
        correlated_alert_ids=correlated_alert_ids,
        latency_class=final_latency,
    )

    # 6. Fail-closed validation chokepoint
    if validate:
        validate_alert(alert.to_dict())

    return alert
