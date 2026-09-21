"""
Asset criticality evaluation for PS-26145.

Loads the lab demonstration asset inventory from config/assets.yaml and evaluates
asset criticality for source and destination endpoints.

IMPORTANT NOTE:
`config/assets.yaml` is a LAB / DEMONSTRATION asset inventory for evaluation and
testing. It does NOT represent a live production asset database.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional
import yaml

logger = logging.getLogger(__name__)

DEFAULT_ASSETS_PATH: Path = Path(__file__).resolve().parent.parent / "config" / "assets.yaml"

# Valid semantic criticality levels
CRITICALITY_CRITICAL: str = "critical"
CRITICALITY_STANDARD: str = "standard"
CRITICALITY_UNKNOWN: str = "unknown"


def load_asset_inventory(path: Optional[Path | str] = None) -> dict[str, dict[str, Any]]:
    """
    Load asset inventory from config/assets.yaml.

    Returns a mapping of IP address string to asset metadata dict.
    If the file does not exist or has no assets, returns an empty dict.
    """
    file_path = Path(path) if path else DEFAULT_ASSETS_PATH
    if not file_path.is_file():
        logger.warning("Asset configuration file not found at %s; defaulting to empty inventory", file_path)
        return {}

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
            assets = data.get("assets", {})
            if isinstance(assets, dict):
                return assets
            return {}
    except Exception as e:
        logger.error("Failed to load asset inventory from %s: %s", file_path, e)
        return {}


def lookup_ip_criticality(ip: str, inventory: dict[str, dict[str, Any]]) -> str:
    """
    Look up the criticality level of a single IP address.

    Returns:
        'critical', 'standard', or 'unknown'
    """
    if not ip or ip not in inventory:
        return CRITICALITY_UNKNOWN

    asset_info = inventory[ip]
    if isinstance(asset_info, dict):
        crit = str(asset_info.get("criticality", "")).strip().lower()
        if crit in (CRITICALITY_CRITICAL, CRITICALITY_STANDARD):
            return crit

    return CRITICALITY_UNKNOWN


def resolve_asset_criticality(
    source: str,
    destination: str,
    inventory: Optional[dict[str, dict[str, Any]]] = None,
) -> str:
    """
    Resolve the combined asset criticality for an alert by checking BOTH source and destination.

    Deterministic Precedence Policy:
      1. If either source OR destination is 'critical' -> 'critical'
      2. Else if either source OR destination is 'standard' -> 'standard'
      3. Otherwise -> 'unknown'

    Unknown assets are valid and never cause rejection or failure.
    """
    inv = inventory if inventory is not None else load_asset_inventory()

    src_crit = lookup_ip_criticality(source, inv)
    dst_crit = lookup_ip_criticality(destination, inv)

    if src_crit == CRITICALITY_CRITICAL or dst_crit == CRITICALITY_CRITICAL:
        return CRITICALITY_CRITICAL
    if src_crit == CRITICALITY_STANDARD or dst_crit == CRITICALITY_STANDARD:
        return CRITICALITY_STANDARD

    return CRITICALITY_UNKNOWN


def apply_asset_criticality(
    alert: dict[str, Any],
    inventory: Optional[dict[str, dict[str, Any]]] = None,
) -> dict[str, Any]:
    """
    Evaluate and inject `asset_criticality` into the alert dictionary.
    """
    src = alert.get("source", "")
    dst = alert.get("destination", "")
    criticality = resolve_asset_criticality(src, dst, inventory=inventory)
    alert["asset_criticality"] = criticality
    return alert
