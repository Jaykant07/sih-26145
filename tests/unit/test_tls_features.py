"""
Unit tests for features.tls_features — shared TLS metadata feature extraction and UID join.
"""

import pytest

from features.tls_features import (
    TLSFeatureRecord,
    extract_tls_connection_features,
    join_ssl_and_conn_records,
    parse_zeek_json_lines,
)


class TestTLSJoinAndDeduplication:
    def test_matching_uid_join(self):
        ssl_recs = [{"uid": "C1", "ts": 100.0, "version": "TLSv13", "cipher": "TLS_AES_256_GCM_SHA384"}]
        conn_recs = [{"uid": "C1", "ts": 100.0, "orig_bytes": 5000, "resp_bytes": 2000, "orig_pkts": 10, "resp_pkts": 8, "duration": 2.5}]

        joined = join_ssl_and_conn_records(ssl_recs, conn_recs)
        assert len(joined) == 1
        feat = joined[0]
        assert feat["uid"] == "C1"
        assert feat["version"] == "TLSv13"
        assert feat["orig_bytes"] == 5000
        assert feat["resp_bytes"] == 2000

    def test_unmatched_ssl_uid_produces_no_fabricated_record(self):
        ssl_recs = [{"uid": "C2_UNMATCHED", "version": "TLSv12"}]
        conn_recs = [{"uid": "C1_DIFFERENT", "orig_bytes": 1000}]

        joined = join_ssl_and_conn_records(ssl_recs, conn_recs)
        assert len(joined) == 0

    def test_unmatched_conn_uid_ignored(self):
        ssl_recs = [{"uid": "C1", "version": "TLSv13"}]
        conn_recs = [{"uid": "C1", "orig_bytes": 1000}, {"uid": "C2_NO_SSL", "orig_bytes": 5000}]

        joined = join_ssl_and_conn_records(ssl_recs, conn_recs)
        assert len(joined) == 1
        assert joined[0]["uid"] == "C1"

    def test_duplicate_uid_deterministic_first_seen(self):
        ssl_recs = [
            {"uid": "C_DUP", "version": "TLSv13", "server_name": "first.local"},
            {"uid": "C_DUP", "version": "TLSv12", "server_name": "second.local"},
        ]
        conn_recs = [
            {"uid": "C_DUP", "orig_bytes": 1000, "duration": 1.0},
            {"uid": "C_DUP", "orig_bytes": 9999, "duration": 9.0},
        ]

        joined = join_ssl_and_conn_records(ssl_recs, conn_recs)
        assert len(joined) == 1
        assert joined[0]["server_name"] == "first.local"
        assert joined[0]["orig_bytes"] == 1000

    def test_missing_or_empty_uid_safely_ignored(self):
        ssl_recs = [{"version": "TLSv13"}, {"uid": "", "version": "TLSv13"}, {"uid": None}]
        conn_recs = [{"orig_bytes": 1000}]
        joined = join_ssl_and_conn_records(ssl_recs, conn_recs)
        assert len(joined) == 0


class TestTLSBehavioralFeatures:
    def test_hand_computed_behavioral_features(self):
        ssl_rec = {
            "uid": "C_TEST",
            "ts": 500.0,
            "id.orig_h": "192.168.56.102",
            "id.resp_h": "192.168.56.254",
            "id.orig_p": 49152,
            "id.resp_p": 8443,
            "version": "TLSv13",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "server_name": "lab-c2.local",
            "established": True,
            "ja3": "7c5d0596cedb9c086e8bebef099e73dc",
            "ja3s": "15af977ce25de452b96affa2addb1036",
        }
        conn_rec = {
            "uid": "C_TEST",
            "orig_bytes": 16000,
            "resp_bytes": 4000,
            "orig_pkts": 16,
            "resp_pkts": 4,
            "duration": 10.0,
        }

        feat = extract_tls_connection_features(ssl_rec, conn_rec)

        # Hand calculations:
        # total_bytes = 16000 + 4000 = 20000
        # total_pkts = 16 + 4 = 20
        # mean_packet_size = 20000 / 20 = 1000.0
        # byte_ratio = 16000 / 4000 = 4.0
        # packet_count = 20
        # duration = 10.0
        assert feat["mean_packet_size"] == 1000.0
        assert feat["byte_ratio"] == 4.0
        assert feat["packet_count"] == 20
        assert feat["duration"] == 10.0
        assert feat["ja3"] == "7c5d0596cedb9c086e8bebef099e73dc"
        assert feat["ja3s"] == "15af977ce25de452b96affa2addb1036"

    def test_optional_ja3_absent_handled_safely(self):
        ssl_rec = {"uid": "C_NO_JA3", "version": "TLSv13"}
        conn_rec = {"uid": "C_NO_JA3", "orig_bytes": 1000, "resp_bytes": 500}
        feat = extract_tls_connection_features(ssl_rec, conn_rec)
        assert feat["ja3"] is None
        assert feat["ja3s"] is None

    def test_zero_denominator_safety(self):
        ssl_rec = {"uid": "C_ZERO"}
        conn_rec = {"uid": "C_ZERO", "orig_bytes": 1000, "resp_bytes": 0, "orig_pkts": 0, "resp_pkts": 0}
        feat = extract_tls_connection_features(ssl_rec, conn_rec)
        assert feat["mean_packet_size"] == 1000.0  # max(0, 1) -> 1
        assert feat["byte_ratio"] > 1e6  # 1000 / EPSILON

    def test_tls_feature_record_dataclass(self):
        record = TLSFeatureRecord(
            uid="C1",
            timestamp=100.0,
            source="10.0.0.1",
            destination="10.0.0.2",
            orig_port=1234,
            resp_port=443,
            proto="tcp",
            service="ssl",
            version="TLSv13",
            cipher="TLS_AES_256_GCM_SHA384",
            server_name="example.com",
            established=True,
            ja3=None,
            ja3s=None,
            ssl_history="ShAD",
            orig_bytes=1000,
            resp_bytes=500,
            orig_pkts=5,
            resp_pkts=5,
            mean_packet_size=150.0,
            byte_ratio=2.0,
            packet_count=10,
            duration=1.5,
        )
        d = record.to_dict()
        assert d["uid"] == "C1"
        assert d["byte_ratio"] == 2.0
        assert d["ja3"] is None
