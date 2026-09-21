"""
OT-aware Fusion layer for PS-26145.
"""

from fusion.correlator import DEFAULT_CORRELATION_WINDOW_SECONDS, CorrelationGroup, correlate_alerts
from fusion.criticality import resolve_asset_criticality
from fusion.engine import FusionEngine, fuse_alerts
from fusion.severity import compute_fused_severity, get_base_severity, escalate_severity
from fusion.validator import validate_incoming_alert, validate_final_alert

__all__ = [
    "FusionEngine",
    "fuse_alerts",
    "correlate_alerts",
    "CorrelationGroup",
    "resolve_asset_criticality",
    "compute_fused_severity",
    "get_base_severity",
    "escalate_severity",
    "validate_incoming_alert",
    "validate_final_alert",
    "DEFAULT_CORRELATION_WINDOW_SECONDS",
]
