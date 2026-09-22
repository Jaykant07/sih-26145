"""
Alert constants for PS-26145.

Shared constants used across all detectors and the unified alert pipeline.
Matches docs/04_alert_schema.json strictly.
"""

from __future__ import annotations


# Schema version for DRAFT alerts (per docs/04_alert_schema.json)
SCHEMA_VERSION: str = "1.0.0"


class ThreatClass:
    """Threat classes — one per detector category."""

    DDOS = "ddos"
    BEACONING = "beaconing"
    DGA = "dga"
    DGA_DNS = "dga_dns"
    DNS_TUNNEL = "dns_tunnel"
    SCANNING = "scanning"
    RECONNAISSANCE = "reconnaissance"
    TLS_ANOMALY = "tls_anomaly"
    EXFILTRATION = "exfiltration"
    ANOMALOUS_BEHAVIOR = "anomalous_behavior"


class Severity:
    """Severity levels (detector-level initial severity)."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class LatencyClass:
    """Latency classes per master plan Section 10."""

    EVENT_DRIVEN = "event_driven"
    PERIODIC = "periodic"
