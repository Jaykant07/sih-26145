"""
TLS and Connection Log Feature Extraction Layer for PS-26145 (Track B).

Re-exports from shared features.tls_features module to maintain backward
compatibility with detector components and evaluation scripts.
"""

from __future__ import annotations

from features.tls_features import (
    EPSILON,
    TLSFeatureRecord,
    extract_features_from_files,
    extract_tls_connection_features,
    join_ssl_and_conn_records,
    parse_zeek_json_lines,
    parse_zeek_log_file,
)

__all__ = [
    "EPSILON",
    "TLSFeatureRecord",
    "extract_features_from_files",
    "extract_tls_connection_features",
    "join_ssl_and_conn_records",
    "parse_zeek_json_lines",
    "parse_zeek_log_file",
]
