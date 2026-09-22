"""
detectors/anomaly/feature_engineering.py
Shared feature consumer and schema validation layer for PS-26145 Detector #8.

Consumes canonical features from features/flow_stats.py.
Enforces the frozen feature schema in models/anomaly/feature_schema.json.
Guarantees clean data quality (no NaNs, no infs, no leakage fields).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Iterable, Optional

import numpy as np
import pandas as pd

from features.flow_stats import extract_flow_features
from ingest.parser import ConnRecord

logger = logging.getLogger(__name__)

REPO_ROOT: Path = Path(__file__).resolve().parent.parent.parent
DEFAULT_SCHEMA_PATH: Path = REPO_ROOT / "models" / "anomaly" / "feature_schema.json"

# Canonical feature list definition
NUMERICAL_FEATURES: list[str] = [
    "duration",
    "orig_bytes",
    "resp_bytes",
    "orig_pkts",
    "resp_pkts",
    "orig_ip_bytes",
    "resp_ip_bytes",
    "total_bytes",
    "total_pkts",
    "byte_rate",
    "packet_rate",
    "byte_ratio",
    "packet_ratio",
    "missed_bytes",
]

CATEGORICAL_FEATURES: list[str] = [
    "proto",
    "conn_state",
]

ALL_MODEL_FEATURES: list[str] = NUMERICAL_FEATURES + CATEGORICAL_FEATURES


class FeatureSchemaError(ValueError):
    """Raised when an input dataset or record violates the frozen feature schema."""
    pass


def build_default_feature_schema() -> dict[str, dict[str, Any]]:
    """Build the dictionary representing the frozen feature schema."""
    schema: dict[str, dict[str, Any]] = {}
    for feat in NUMERICAL_FEATURES:
        schema[feat] = {
            "type": "numeric",
            "source": "features.flow_stats.extract_flow_features",
            "required": True,
            "transformation": "StandardScaler",
        }
    for feat in CATEGORICAL_FEATURES:
        schema[feat] = {
            "type": "categorical",
            "source": "features.flow_stats.extract_flow_features",
            "required": True,
            "transformation": "OneHotEncoder",
        }
    return schema


def save_feature_schema(
    schema: Optional[dict[str, dict[str, Any]]] = None,
    path: Path = DEFAULT_SCHEMA_PATH,
) -> None:
    """Save feature schema dictionary to JSON."""
    if schema is None:
        schema = build_default_feature_schema()
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(schema, f, indent=2)
    logger.info("Saved feature schema to %s", path)


def load_feature_schema(path: Path = DEFAULT_SCHEMA_PATH) -> dict[str, dict[str, Any]]:
    """Load feature schema dictionary from JSON."""
    if not path.is_file():
        raise FileNotFoundError(f"Feature schema not found at {path}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def extract_features_from_records(
    records: Iterable[ConnRecord],
) -> pd.DataFrame:
    """
    Extract canonical model features from an iterable of ConnRecord objects.

    Reuses features.flow_stats.extract_flow_features for every record.
    Returns a pandas DataFrame matching ALL_MODEL_FEATURES.
    """
    rows = []
    for rec in records:
        f = extract_flow_features(rec)
        rows.append(f.to_dict())

    if not rows:
        return pd.DataFrame(columns=ALL_MODEL_FEATURES)

    df = pd.DataFrame(rows)
    return prepare_feature_dataframe(df)


def prepare_feature_dataframe(
    df: pd.DataFrame,
    schema: Optional[dict[str, dict[str, Any]]] = None,
) -> pd.DataFrame:
    """
    Validate, sanitize, and prepare a feature DataFrame for model ingestion.

    - Verifies required features exist.
    - Sanitizes NaN and infinite values.
    - Ensures correct column ordering matching ALL_MODEL_FEATURES.
    """
    if schema is None:
        try:
            schema = load_feature_schema()
        except FileNotFoundError:
            schema = build_default_feature_schema()

    df_clean = df.copy()

    # Verify required features
    missing = [feat for feat in ALL_MODEL_FEATURES if feat not in df_clean.columns]
    if missing:
        raise FeatureSchemaError(f"Input DataFrame is missing required features: {missing}")

    # Sanitize numerical features
    for col in NUMERICAL_FEATURES:
        df_clean[col] = pd.to_numeric(df_clean[col], errors="coerce").fillna(0.0)
        # Replace inf/-inf with 0.0 or high finite ceiling
        df_clean[col] = df_clean[col].replace([np.inf, -np.inf], 0.0)

    # Sanitize categorical features
    for col in CATEGORICAL_FEATURES:
        df_clean[col] = df_clean[col].astype(str).fillna("unknown")

    # Order columns strictly
    return df_clean[ALL_MODEL_FEATURES]
