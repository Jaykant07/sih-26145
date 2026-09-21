"""
Fusion alert validator for PS-26145.

Provides defense-in-depth schema and semantic validation for alerts entering
and leaving the OT-aware fusion pipeline.
"""

from __future__ import annotations

import logging
from typing import Any

from alerts.draft import DraftAlert
from alerts.validator import AlertValidationError, validate_draft_alert

logger = logging.getLogger(__name__)


def validate_incoming_alert(alert: dict[str, Any] | DraftAlert) -> tuple[bool, list[str]]:
    """
    Validate an incoming DRAFT alert entering the fusion layer.

    Fail-closed: Returns (False, errors) if invalid, and logs the failure.
    """
    d = alert.to_dict() if hasattr(alert, "to_dict") else alert
    if not isinstance(d, dict):
        msg = f"Incoming alert must be dict or DraftAlert, got {type(alert).__name__}"
        logger.error("Fusion incoming validation failed: %s", msg)
        return False, [msg]

    is_valid, errors = validate_draft_alert(d)
    if not is_valid:
        logger.error(
            "Fusion rejected incoming alert: %s (detector=%s, threat_class=%s)",
            errors,
            d.get("detector", "<unknown>"),
            d.get("threat_class", "<unknown>"),
        )
    return is_valid, errors


def validate_final_alert(alert: dict[str, Any] | DraftAlert) -> tuple[bool, list[str]]:
    """
    Validate a final fused alert before it can reach storage or dashboard.

    Fail-closed: Returns (False, errors) if invalid, and logs the failure.
    """
    d = alert.to_dict() if hasattr(alert, "to_dict") else alert
    if not isinstance(d, dict):
        msg = f"Final alert must be dict or DraftAlert, got {type(alert).__name__}"
        logger.error("Fusion final validation failed: %s", msg)
        return False, [msg]

    is_valid, errors = validate_draft_alert(d)
    if not is_valid:
        logger.error(
            "Fusion rejected final alert: %s (detector=%s, threat_class=%s, correlation_id=%s)",
            errors,
            d.get("detector", "<unknown>"),
            d.get("threat_class", "<unknown>"),
            d.get("correlation_id", "<none>"),
        )
    return is_valid, errors


def assert_valid_incoming(alert: dict[str, Any] | DraftAlert) -> dict[str, Any]:
    """
    Assert an incoming alert is valid, raising AlertValidationError if not.
    Returns the alert dict.
    """
    d = alert.to_dict() if hasattr(alert, "to_dict") else alert
    is_valid, errors = validate_incoming_alert(d)
    if not is_valid:
        raise AlertValidationError(f"Invalid incoming alert: {'; '.join(errors)}")
    return d


def assert_valid_final(alert: dict[str, Any] | DraftAlert) -> dict[str, Any]:
    """
    Assert a final fused alert is valid, raising AlertValidationError if not.
    Returns the alert dict.
    """
    d = alert.to_dict() if hasattr(alert, "to_dict") else alert
    is_valid, errors = validate_final_alert(d)
    if not is_valid:
        raise AlertValidationError(f"Invalid final fused alert: {'; '.join(errors)}")
    return d
