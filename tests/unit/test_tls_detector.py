"""
Unit tests for Encrypted Malware / TLS Metadata Detector (Track B — PS-26145).

Verifies:
  - ssl.log and conn.log joining on exact UID
  - Handling of missing, unmatched, and duplicate UIDs
  - Offline static JA3 / JA3S fingerprint lookups
  - Connection-level behavioral feature extraction and zero-division safety
  - Dual-signal fusion decision matrix (fingerprint only, behavior only, both, neither)
  - Strict adherence to no-decryption guarantee in evidence and alert wording
  - Schema compliance against docs/04_alert_schema.json and validate_draft_alert
"""

from pathlib import Path
import pytest

from alerts.constants import LatencyClass, Severity, ThreatClass
from alerts.validator import validate_draft_alert
from detectors.tls.behavior import TLSBehaviorModel
from detectors.tls.blacklist import JA3Blacklist
from detectors.tls.detector import TLSDetector
from detectors.tls.tls_features import (
    extract_tls_connection_features,
    join_ssl_and_conn_records,
    parse_zeek_json_lines,
)

# Canonical fixtures based on real Zeek enc-001 and enc-002 outputs
SAMPLE_SSL_BASELINE = {
    "ts": 1789731217.734122,
    "uid": "UID_BASELINE_001",
    "id.orig_h": "192.168.56.102",
    "id.orig_p": 37558,
    "id.resp_h": "192.168.56.254",
    "id.resp_p": 8443,
    "version": "TLSv13",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "server_name": "lab-c2.local",
    "established": True,
    "ja3": "7c5d0596cedb9c086e8bebef099e73dc",
    "ja3s": "15af977ce25de452b96affa2addb1036",
}

SAMPLE_CONN_BASELINE = {
    "ts": 1789731217.663185,
    "uid": "UID_BASELINE_001",
    "id.orig_h": "192.168.56.102",
    "id.orig_p": 37558,
    "id.resp_h": "192.168.56.254",
    "id.resp_p": 8443,
    "proto": "tcp",
    "service": "ssl",
    "duration": 115.9627,
    "orig_bytes": 5679,
    "resp_bytes": 2965,
    "orig_pkts": 13,
    "resp_pkts": 11,
}

SAMPLE_SSL_C2 = {
    "ts": 1789732791.866308,
    "uid": "UID_C2_002",
    "id.orig_h": "192.168.56.102",
    "id.orig_p": 51796,
    "id.resp_h": "192.168.56.254",
    "id.resp_p": 8443,
    "version": "TLSv13",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "server_name": "lab-c2.local",
    "established": True,
    "ja3": "7c5d0596cedb9c086e8bebef099e73dc",
    "ja3s": "15af977ce25de452b96affa2addb1036",
}

SAMPLE_CONN_C2 = {
    "ts": 1789732791.809134,
    "uid": "UID_C2_002",
    "id.orig_h": "192.168.56.102",
    "id.orig_p": 51796,
    "id.resp_h": "192.168.56.254",
    "id.resp_p": 8443,
    "proto": "tcp",
    "service": "ssl",
    "duration": 58.2608,
    "orig_bytes": 16007,
    "resp_bytes": 2965,
    "orig_pkts": 17,
    "resp_pkts": 14,
}


@pytest.fixture
def detector() -> TLSDetector:
    return TLSDetector()


@pytest.fixture
def blacklist() -> JA3Blacklist:
    return JA3Blacklist()


@pytest.fixture
def behavior_model() -> TLSBehaviorModel:
    return TLSBehaviorModel()


# ===========================================================================
# 1. Join & UID Handling Tests (Tests 1-4, 21-22)
# ===========================================================================

class TestTLSFeatureJoin:
    def test_01_valid_ssl_and_conn_join(self):
        """TEST 1: Valid ssl + conn join on exact UID."""
        joined = join_ssl_and_conn_records([SAMPLE_SSL_BASELINE], [SAMPLE_CONN_BASELINE])
        assert len(joined) == 1
        f = joined[0]
        assert f["uid"] == "UID_BASELINE_001"
        assert f["source"] == "192.168.56.102"
        assert f["destination"] == "192.168.56.254"
        assert f["version"] == "TLSv13"
        assert f["ja3"] == "7c5d0596cedb9c086e8bebef099e73dc"

    def test_02_missing_uid_handled_safely(self):
        """TEST 2: Records missing UID are safely ignored."""
        bad_ssl = {"id.orig_h": "1.2.3.4"}  # no uid
        bad_conn = {"id.orig_h": "1.2.3.4"}
        joined = join_ssl_and_conn_records([bad_ssl], [bad_conn])
        assert len(joined) == 0

    def test_03_unmatched_uid_ignored(self):
        """TEST 3: Unmatched UIDs between ssl and conn are excluded."""
        ssl_rec = dict(SAMPLE_SSL_BASELINE, uid="UID_ONLY_IN_SSL")
        conn_rec = dict(SAMPLE_CONN_BASELINE, uid="UID_ONLY_IN_CONN")
        joined = join_ssl_and_conn_records([ssl_rec], [conn_rec])
        assert len(joined) == 0

    def test_04_duplicate_uid_deterministic(self):
        """TEST 4: Duplicate UIDs are handled deterministically (first wins)."""
        ssl_1 = dict(SAMPLE_SSL_BASELINE, version="TLSv13")
        ssl_2 = dict(SAMPLE_SSL_BASELINE, version="TLSv12")  # duplicate uid
        joined = join_ssl_and_conn_records([ssl_1, ssl_2], [SAMPLE_CONN_BASELINE])
        assert len(joined) == 1
        assert joined[0]["version"] == "TLSv13"

    def test_21_malformed_ssl_log_handled_safely(self):
        """TEST 21: Malformed JSON lines in ssl.log skipped cleanly."""
        raw_text = (
            '{"uid": "U1", "version": "TLSv13"}\n'
            "MALFORMED_GARBAGE_LINE\n"
            '{"uid": "U2", "version": "TLSv12"}\n'
        )
        records = parse_zeek_json_lines(raw_text)
        assert len(records) == 2

    def test_22_malformed_conn_log_handled_safely(self):
        """TEST 22: Malformed JSON lines in conn.log skipped cleanly."""
        raw_text = (
            "#separator \\x09\n"
            "#empty comment\n"
            '{"uid": "C1", "orig_bytes": 100}\n'
            "}{bad_json{\n"
        )
        records = parse_zeek_json_lines(raw_text)
        assert len(records) == 1
        assert records[0]["uid"] == "C1"


# ===========================================================================
# 2. JA3 / JA3S Static Blacklist Tests (Tests 5-10, 29)
# ===========================================================================

class TestJA3BlacklistLookup:
    def test_05_ja3_exact_match(self, blacklist: JA3Blacklist):
        """TEST 5: Known JA3 hash in snapshot triggers exact match."""
        # Cobalt strike default JA3
        cs_ja3 = "51c64c77e60f3980eea90869b68c58a8"
        res = blacklist.lookup_ja3(cs_ja3)
        assert res is not None
        assert res["family"] == "Cobalt Strike"

    def test_06_ja3_non_match(self, blacklist: JA3Blacklist):
        """TEST 6: Unrelated clean JA3 hash returns None."""
        clean_ja3 = "00000000000000000000000000000000"
        assert blacklist.lookup_ja3(clean_ja3) is None

    def test_07_ja3s_exact_match(self, blacklist: JA3Blacklist):
        """TEST 7: Known JA3S hash in snapshot triggers exact match."""
        cs_ja3s = "fd4bc6cea4877646ccd62f4039207513"
        res = blacklist.lookup_ja3s(cs_ja3s)
        assert res is not None
        assert "Cobalt Strike" in res["family"]

    def test_08_ja3s_non_match(self, blacklist: JA3Blacklist):
        """TEST 8: Unrelated clean JA3S returns None."""
        assert blacklist.lookup_ja3s("ffffffffffffffffffffffffffffffff") is None

    def test_09_missing_ja3_handled(self, blacklist: JA3Blacklist):
        """TEST 9: Missing or None JA3 handled gracefully."""
        assert blacklist.lookup_ja3(None) is None
        assert blacklist.lookup_ja3("") is None

    def test_10_missing_ja3s_handled(self, blacklist: JA3Blacklist):
        """TEST 10: Missing or None JA3S handled gracefully."""
        assert blacklist.lookup_ja3s(None) is None
        assert blacklist.lookup_ja3s("") is None


# ===========================================================================
# 3. Behavioral Feature Calculation & Anomaly Scoring (Tests 11-14)
# ===========================================================================

class TestTLSBehavioralFeatures:
    def test_11_behavioral_feature_calculation(self):
        """TEST 11: All 4 behavioral features computed accurately from counters."""
        feat = extract_tls_connection_features(SAMPLE_SSL_BASELINE, SAMPLE_CONN_BASELINE)
        assert feat["packet_count"] == 24
        assert feat["duration"] == 115.9627
        # mean_packet_size = (5679 + 2965) / 24 = 360.1667
        assert abs(feat["mean_packet_size"] - 360.1667) < 0.01
        # byte_ratio = 5679 / 2965 = 1.9153
        assert abs(feat["byte_ratio"] - 1.9153) < 0.01

    def test_12_zero_denominator_safety(self):
        """TEST 12: Zero packets or zero resp_bytes do not cause DivisionByZero."""
        zero_conn = {
            "uid": "U_ZERO",
            "orig_bytes": 100,
            "resp_bytes": 0,  # zero download
            "orig_pkts": 0,
            "resp_pkts": 0,   # zero packets
            "duration": 0.0,
        }
        feat = extract_tls_connection_features({}, zero_conn)
        assert feat["mean_packet_size"] == 100.0
        assert feat["byte_ratio"] > 0
        assert feat["packet_count"] == 0

    def test_13_behavioral_score_below_threshold(self, behavior_model: TLSBehaviorModel):
        """TEST 13: Benign baseline traffic scores below threshold (0.50)."""
        feat = extract_tls_connection_features(SAMPLE_SSL_BASELINE, SAMPLE_CONN_BASELINE)
        score = behavior_model.compute_score(feat)
        assert score < 0.50
        assert not behavior_model.is_anomalous(score)

    def test_14_behavioral_score_above_threshold(self, behavior_model: TLSBehaviorModel):
        """TEST 14: Simulated C2 traffic with heavy asymmetric upload scores >= 0.50."""
        feat = extract_tls_connection_features(SAMPLE_SSL_C2, SAMPLE_CONN_C2)
        score = behavior_model.compute_score(feat)
        assert score >= 0.50
        assert behavior_model.is_anomalous(score)


# ===========================================================================
# 4. Signal Fusion & Alert Contract (Tests 15-20, 23)
# ===========================================================================

class TestTLSSignalFusionAndAlertContract:
    def test_15_fingerprint_only_fusion(self, detector: TLSDetector):
        """TEST 15: JA3 match only -> medium-high confidence (0.75), fingerprint_only."""
        # Benign behavior + known malicious JA3
        feat = extract_tls_connection_features(SAMPLE_SSL_BASELINE, SAMPLE_CONN_BASELINE)
        feat["ja3"] = "a0e9f5d64349fb13191bc781f81f42e1"  # Meterpreter
        feat["ja3s"] = "00000000000000000000000000000000"  # unlisted

        eval_res = detector.evaluate_connection(feat)
        assert eval_res["is_alert"] is True
        assert eval_res["fusion_state"] == "fingerprint_only"
        assert eval_res["confidence"] == 0.75
        assert eval_res["severity"] == Severity.MEDIUM

    def test_16_behavior_only_fusion(self, detector: TLSDetector):
        """TEST 16: Behavior only -> medium confidence (0.65), behavior_only."""
        # C2 behavior + completely unlisted clean JA3/JA3S
        feat = extract_tls_connection_features(SAMPLE_SSL_C2, SAMPLE_CONN_C2)
        feat["ja3"] = "11111111111111111111111111111111"
        feat["ja3s"] = "22222222222222222222222222222222"

        eval_res = detector.evaluate_connection(feat)
        assert eval_res["is_alert"] is True
        assert eval_res["fusion_state"] == "behavior_only"
        assert eval_res["confidence"] == 0.65
        assert eval_res["severity"] == Severity.MEDIUM

    def test_17_both_signals_high_confidence(self, detector: TLSDetector):
        """TEST 17: Both signals active -> high confidence (0.90), both."""
        # C2 behavior + matched JA3
        feat = extract_tls_connection_features(SAMPLE_SSL_C2, SAMPLE_CONN_C2)
        feat["ja3"] = "51c64c77e60f3980eea90869b68c58a8"  # Cobalt Strike

        eval_res = detector.evaluate_connection(feat)
        assert eval_res["is_alert"] is True
        assert eval_res["fusion_state"] == "both"
        assert eval_res["confidence"] == 0.90
        assert eval_res["severity"] == Severity.HIGH

    def test_18_threat_class_conforms_to_schema(self, detector: TLSDetector):
        """TEST 18: Emitted alert has schema-approved threat_class = 'tls_anomaly'."""
        feat = extract_tls_connection_features(SAMPLE_SSL_C2, SAMPLE_CONN_C2)
        feat["ja3"] = "51c64c77e60f3980eea90869b68c58a8"
        eval_res = detector.evaluate_connection(feat)
        alert = detector.create_alert(eval_res)
        assert alert is not None
        d = alert.to_dict()
        assert d["threat_class"] == ThreatClass.TLS_ANOMALY
        assert d["threat_class"] == "tls_anomaly"
        assert d["latency_class"] == LatencyClass.EVENT_DRIVEN
        assert d["latency_class"] == "event_driven"

    def test_19_evidence_contains_actual_observed_values(self, detector: TLSDetector):
        """TEST 19: Alert evidence preserves actual connection and TLS fields."""
        feat = extract_tls_connection_features(SAMPLE_SSL_C2, SAMPLE_CONN_C2)
        eval_res = detector.evaluate_connection(feat)
        alert = detector.create_alert(eval_res)
        assert alert is not None
        ev = alert.supporting_evidence
        assert ev["mean_packet_size"] > 0
        assert ev["byte_ratio"] > 0
        assert ev["duration"] > 0
        assert ev["packet_count"] == 31
        assert "fusion_state" in ev
        assert "ja3" in ev
        assert "ja3s" in ev

    def test_20_alert_text_contains_no_decryption_claim(self, detector: TLSDetector):
        """TEST 20: Verified that alert contains NO payload decryption claims."""
        feat = extract_tls_connection_features(SAMPLE_SSL_C2, SAMPLE_CONN_C2)
        eval_res = detector.evaluate_connection(feat)
        alert = detector.create_alert(eval_res)
        assert alert is not None
        ev = alert.supporting_evidence
        alert_str = str(ev).lower()

        # Forbidden terms:
        forbidden = [
            "malware payload detected",
            "malware found",
            "malware executable detected",
            "payload inspected",
            "decrypted malware",
            "malware extracted",
        ]
        for term in forbidden:
            assert term not in alert_str, f"Found forbidden decryption claim: {term}"

        # Must explicitly declare zero decryption
        assert "zero payload decryption" in ev["decryption_status"]
        assert "metadata/behavior-based suspicion" in ev["detection_basis"]

    def test_23_full_schema_validation(self, detector: TLSDetector):
        """TEST 23: Output alert passes validate_draft_alert and schema fields."""
        feat = extract_tls_connection_features(SAMPLE_SSL_C2, SAMPLE_CONN_C2)
        feat["ja3"] = "51c64c77e60f3980eea90869b68c58a8"
        eval_res = detector.evaluate_connection(feat)
        alert = detector.create_alert(eval_res)
        assert alert is not None
        is_valid, errors = validate_draft_alert(alert.to_dict())
        assert is_valid, f"Validation failed: {errors}"
