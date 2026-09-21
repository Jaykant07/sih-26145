"""
OT-aware Fusion Engine for PS-26145.

Orchestrates defense-in-depth ingress validation, source-based multi-threat
correlation, asset criticality lookup, deterministic severity escalation, and
final schema validation.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional

from alerts.draft import DraftAlert
from fusion.correlator import (
    DEFAULT_CORRELATION_WINDOW_SECONDS,
    CorrelationGroup,
    correlate_alerts,
)
from fusion.criticality import (
    apply_asset_criticality,
    load_asset_inventory,
)
from fusion.severity import apply_fused_severity
from fusion.validator import (
    validate_final_alert,
    validate_incoming_alert,
)

logger = logging.getLogger(__name__)


class FusionEngine:
    """
    OT-Aware Alert Fusion Engine.

    Pipeline:
      1. Defense-in-depth ingress validation (fail-closed)
      2. Source-based multi-threat correlation (configurable window)
      3. Asset criticality resolution (source + destination lookup)
      4. Deterministic severity escalation (base + criticality + correlation)
      5. Final schema validation
    """

    def __init__(
        self,
        correlation_window: float = DEFAULT_CORRELATION_WINDOW_SECONDS,
        assets_path: Optional[Path | str] = None,
    ) -> None:
        self.correlation_window = correlation_window
        self.assets_path = assets_path
        self.asset_inventory = load_asset_inventory(assets_path)

    def reload_assets(self, assets_path: Optional[Path | str] = None) -> None:
        """Reload the asset inventory from disk or specified path."""
        path = assets_path or self.assets_path
        self.asset_inventory = load_asset_inventory(path)

    def process_alerts(
        self,
        alerts: list[dict[str, Any] | DraftAlert],
    ) -> list[dict[str, Any]]:
        """
        Process a batch or stream of DRAFT alerts through the full fusion pipeline.

        Returns only fully schema-valid final alert dictionaries.
        """
        if not alerts:
            return []

        # 1. Defense-in-depth Ingress Validation
        valid_drafts: list[dict[str, Any]] = []
        for a in alerts:
            is_valid, errors = validate_incoming_alert(a)
            if is_valid:
                d = a.to_dict() if hasattr(a, "to_dict") else dict(a)
                valid_drafts.append(d)
            else:
                logger.warning("Dropping invalid incoming alert: %s", errors)

        if not valid_drafts:
            return []

        # 2. Source-based Multi-Threat Correlation
        correlated_alerts, groups = correlate_alerts(
            valid_drafts,
            correlation_window=self.correlation_window,
        )

        # 3. Asset Criticality & 4. Severity Escalation
        final_alerts: list[dict[str, Any]] = []
        for alert in correlated_alerts:
            # Apply asset criticality (checks source & destination)
            apply_asset_criticality(alert, inventory=self.asset_inventory)

            # Determine whether this alert is part of a multi-threat correlation group
            is_correlated = bool(alert.get("correlation_id"))

            # Apply deterministic fused severity (confidence strictly preserved)
            apply_fused_severity(alert, is_correlated=is_correlated)

            # 5. Final Schema Validation (Defense-in-depth)
            is_final_valid, errors = validate_final_alert(alert)
            if is_final_valid:
                final_alerts.append(alert)
            else:
                logger.error(
                    "Fused alert failed final schema validation (dropped): %s (alert_id=%s)",
                    errors,
                    alert.get("alert_id"),
                )

        return final_alerts


def fuse_alerts(
    alerts: list[dict[str, Any] | DraftAlert],
    correlation_window: float = DEFAULT_CORRELATION_WINDOW_SECONDS,
    assets_path: Optional[Path | str] = None,
) -> list[dict[str, Any]]:
    """
    Convenience function to run the full fusion pipeline on a list of alerts.
    """
    engine = FusionEngine(
        correlation_window=correlation_window,
        assets_path=assets_path,
    )
    return engine.process_alerts(alerts)
