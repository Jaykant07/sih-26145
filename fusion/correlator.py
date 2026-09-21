"""
Multi-threat alert correlator for PS-26145.

Groups alerts by source IP within a configurable time window and identifies
correlated multi-threat attack patterns (requiring at least 2 distinct threat classes).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
import logging
from typing import Any, Optional
import uuid

logger = logging.getLogger(__name__)

# Default correlation window: 5 minutes (300.0 seconds)
DEFAULT_CORRELATION_WINDOW_SECONDS: float = 300.0


def _parse_timestamp(ts: str) -> float:
    """Parse ISO-8601 timestamp string to POSIX epoch float."""
    ts_str = ts.replace("Z", "+00:00") if ts.endswith("Z") else ts
    return datetime.fromisoformat(ts_str).timestamp()


@dataclass
class CorrelationGroup:
    """
    Representation of a multi-threat correlation group.
    """
    correlation_id: str
    source: str
    threat_classes: list[str]
    alert_ids: list[str]
    start_time: float
    end_time: float
    alerts: list[dict[str, Any]] = field(default_factory=list)


def correlate_alerts(
    alerts: list[dict[str, Any]],
    correlation_window: float = DEFAULT_CORRELATION_WINDOW_SECONDS,
) -> tuple[list[dict[str, Any]], list[CorrelationGroup]]:
    """
    Correlate alerts by source IP within a bounded time window.

    A correlation group is established if and only if:
      1. Same source IP (`alert["source"]`)
      2. Temporal proximity within `correlation_window` seconds
      3. At least TWO distinct `threat_class` values

    Alerts meeting these criteria receive:
      - `correlation_id`: Shared UUIDv4 string across all group members
      - `correlated_alert_ids`: List of alert_id strings of other alerts in the group

    Alerts that do not correlate retain individual status (no correlation_id or group escalation).

    Args:
        alerts: List of alert dictionaries.
        correlation_window: Time window in seconds (default: 300.0).

    Returns:
        `(updated_alerts, correlation_groups)`
    """
    if not alerts:
        return [], []

    # Deep copy alert dicts to avoid mutating input objects in-place
    processed = [dict(a) for a in alerts]

    # Group alert indices by source
    by_source: dict[str, list[int]] = {}
    for idx, alert in enumerate(processed):
        src = alert.get("source", "")
        by_source.setdefault(src, []).append(idx)

    correlation_groups: list[CorrelationGroup] = []

    for src, indices in by_source.items():
        if not src:
            continue

        # Sort indices by timestamp
        indices_with_time = []
        for idx in indices:
            try:
                t = _parse_timestamp(processed[idx]["timestamp"])
            except Exception as e:
                logger.warning("Failed to parse timestamp for alert %s: %e", processed[idx].get("alert_id"), e)
                t = 0.0
            indices_with_time.append((t, idx))

        indices_with_time.sort(key=lambda x: x[0])

        # Cluster into time windows: greedy anchor-based window
        n = len(indices_with_time)
        i = 0
        while i < n:
            window_start_time, first_idx = indices_with_time[i]
            window_indices = [first_idx]
            j = i + 1

            while j < n:
                curr_time, curr_idx = indices_with_time[j]
                if (curr_time - window_start_time) <= correlation_window:
                    window_indices.append(curr_idx)
                    j += 1
                else:
                    break

            # Check distinct threat classes
            group_threat_classes = list(dict.fromkeys(
                processed[idx].get("threat_class", "") for idx in window_indices
            ))

            if len(group_threat_classes) >= 2:
                # Multi-threat correlation condition satisfied
                group_id = str(uuid.uuid4())
                group_alert_ids = [processed[idx]["alert_id"] for idx in window_indices]
                group_alerts = [processed[idx] for idx in window_indices]
                window_end_time = indices_with_time[j - 1][0]

                group = CorrelationGroup(
                    correlation_id=group_id,
                    source=src,
                    threat_classes=group_threat_classes,
                    alert_ids=group_alert_ids,
                    start_time=window_start_time,
                    end_time=window_end_time,
                    alerts=group_alerts,
                )
                correlation_groups.append(group)

                # Assign correlation fields to all members of the group
                for idx in window_indices:
                    processed[idx]["correlation_id"] = group_id
                    processed[idx]["correlated_alert_ids"] = [
                        aid for aid in group_alert_ids if aid != processed[idx]["alert_id"]
                    ]

                # Move i past this correlated window
                i = j
            else:
                # Single threat class; no correlation group formed
                i += 1

    return processed, correlation_groups
