"""
Alert schema validator for PS-26145.

Validates DRAFT alert records against docs/04_alert_schema.json.
Serves as the single mandatory, fail-closed validation chokepoint.
"""

from __future__ import annotations

from datetime import datetime
import json
import logging
import math
from pathlib import Path
from typing import Any
import uuid

import jsonschema

logger = logging.getLogger(__name__)

# Path to authoritative JSON schema
SCHEMA_PATH: Path = Path(__file__).resolve().parent.parent / "docs" / "04_alert_schema.json"


class AlertValidationError(ValueError):
    """Raised when an alert fails schema validation or semantic checks (fail-closed)."""
    pass


def load_alert_schema(schema_path: Path = SCHEMA_PATH) -> dict[str, Any]:
    """
    Load the JSON schema directly from docs/04_alert_schema.json.
    """
    if not schema_path.is_file():
        raise FileNotFoundError(f"Authoritative alert schema not found at {schema_path}")
    with open(schema_path, "r", encoding="utf-8") as f:
        return json.load(f)


# Cached compiled Draft7Validator instance
_ALERT_SCHEMA: dict[str, Any] = load_alert_schema()
_SCHEMA_VALIDATOR: jsonschema.Draft7Validator = jsonschema.Draft7Validator(_ALERT_SCHEMA)


def validate_draft_alert(alert: dict[str, Any]) -> tuple[bool, list[str]]:
    """
    Validate a DRAFT alert dict against docs/04_alert_schema.json and semantic rules.

    Checks:
      - Direct JSON schema compliance via jsonschema.Draft7Validator
      - alert_id is a valid UUIDv4
      - timestamp is a valid timezone-aware UTC ISO-8601 string
      - confidence is a finite numeric value in [0.0, 1.0] (rejects NaN, inf, bool)
      - supporting_evidence is a non-empty dictionary
      - model_version is present (or aliased from detector_version)

    Args:
        alert: Alert dict (e.g. from :meth:`DraftAlert.to_dict`).

    Returns:
        ``(is_valid, list_of_error_strings)``.
    """
    errors: list[str] = []

    if not isinstance(alert, dict):
        return False, [f"Alert must be a dictionary, got {type(alert).__name__}"]

    # 1. Alias handling for model_version / detector_version
    eval_dict = alert
    if "model_version" not in alert and "detector_version" in alert:
        eval_dict = dict(alert)
        eval_dict["model_version"] = alert["detector_version"]

    # 2. Semantic check: alert_id UUIDv4
    alert_id = eval_dict.get("alert_id")
    if "alert_id" in eval_dict:
        if not isinstance(alert_id, str):
            errors.append(f"alert_id must be str, got {type(alert_id).__name__}")
        else:
            try:
                parsed_uuid = uuid.UUID(alert_id, version=4)
                if parsed_uuid.version != 4:
                    errors.append(f"alert_id '{alert_id}' is UUIDv{parsed_uuid.version}; must be UUIDv4")
            except (ValueError, AttributeError):
                errors.append(f"alert_id '{alert_id}' is not a valid UUIDv4")

    # 3. Semantic check: timestamp UTC ISO-8601
    ts = eval_dict.get("timestamp")
    if "timestamp" in eval_dict:
        if not isinstance(ts, str):
            errors.append(f"timestamp must be str, got {type(ts).__name__}")
        else:
            try:
                ts_str = ts.replace("Z", "+00:00") if ts.endswith("Z") else ts
                dt = datetime.fromisoformat(ts_str)
                if dt.tzinfo is None or dt.utcoffset() is None:
                    errors.append(f"timestamp '{ts}' is a naive datetime; must be timezone-aware UTC")
                elif dt.utcoffset().total_seconds() != 0:
                    errors.append(f"timestamp '{ts}' has non-zero UTC offset; must be UTC (+00:00 or Z)")
            except (ValueError, TypeError) as e:
                errors.append(f"timestamp '{ts}' is not valid ISO-8601: {e}")

    # 4. Semantic check: confidence range & finite numeric (reject NaN, inf, bool)
    if "confidence" in eval_dict:
        conf = eval_dict["confidence"]
        if conf is None:
            errors.append("confidence is None")
        elif isinstance(conf, bool) or not isinstance(conf, (int, float)):
            errors.append(f"confidence '{conf}' must be numeric (float or int), not {type(conf).__name__}")
        elif math.isnan(conf) or math.isinf(conf):
            errors.append(f"confidence cannot be NaN or Infinity (got {conf})")
        elif not (0.0 <= conf <= 1.0):
            errors.append(f"confidence {conf} is outside allowed range [0.0, 1.0]")

    # 5. Semantic check: supporting_evidence non-empty dict
    if "supporting_evidence" in eval_dict:
        evidence = eval_dict["supporting_evidence"]
        if not isinstance(evidence, dict):
            errors.append(f"supporting_evidence must be a dict/object, not {type(evidence).__name__}")
        elif len(evidence) == 0:
            errors.append("supporting_evidence is empty; must contain at least one key/value")

    # 6. JSON schema validation against docs/04_alert_schema.json
    for err in _SCHEMA_VALIDATOR.iter_errors(eval_dict):
        field_path = ".".join(str(p) for p in err.path) if err.path else "root"
        errors.append(f"Schema violation at '{field_path}': {err.message}")

    is_valid = len(errors) == 0
    if not is_valid:
        logger.error(
            "DRAFT alert validation failed: %s (detector=%s, threat_class=%s)",
            errors,
            eval_dict.get("detector", "<unknown>"),
            eval_dict.get("threat_class", "<unknown>"),
        )

    return is_valid, errors


def validate_alert(alert: dict[str, Any] | Any) -> dict[str, Any]:
    """
    Validate a draft alert dict or DraftAlert instance against the schema.

    Returns the validated alert dictionary if valid.
    Raises AlertValidationError if invalid (fail-closed).
    """
    d = alert.to_dict() if hasattr(alert, "to_dict") else alert
    if not isinstance(d, dict):
        raise AlertValidationError(f"Expected dict or DraftAlert instance, got {type(alert).__name__}")

    is_valid, errors = validate_draft_alert(d)
    if not is_valid:
        raise AlertValidationError(f"DRAFT alert validation failed: {'; '.join(errors)}")

    return d
