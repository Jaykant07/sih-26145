"""
tests/unit/test_anomaly_detector.py
Comprehensive unit and integration tests for PS-26145 Detector #8 (AI Behavioral Anomaly Detector).

Verifies:
  1. Model loading & artifact validation
  2. Feature schema matching and failure on missing features
  3. Deterministic inference with random_state reproducibility
  4. Alert creation, confidence bounds [0.0, 1.0], and supporting evidence
  5. Schema validation pass via validate_draft_alert
  6. End-to-end integration: AnomalyDetector -> DraftAlert -> FusionEngine -> Validated Fused Alert
"""

import sys
from pathlib import Path
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from alerts.constants import ThreatClass, Severity
from alerts.validator import validate_draft_alert
from detectors.anomaly.feature_engineering import (
    ALL_MODEL_FEATURES,
    FeatureSchemaError,
    prepare_feature_dataframe,
)
from detectors.anomaly.predict import AnomalyDetector
from fusion.engine import FusionEngine
from ingest.parser import ConnRecord


def _make_dummy_conn(uid: str = "Cdummy1", duration: float = 1.0, orig_bytes: int = 500, resp_bytes: int = 200) -> ConnRecord:
    return ConnRecord(
        ts=1700000000.0,
        uid=uid,
        src_ip="192.168.1.100",
        src_port=44556,
        dst_ip="192.168.1.1",
        dst_port=80,
        proto="tcp",
        conn_state="SF",
        orig_pkts=10,
        resp_pkts=8,
        orig_ip_bytes=orig_bytes,
        resp_ip_bytes=resp_bytes,
        missed_bytes=0,
        local_orig=True,
        local_resp=True,
        duration=duration,
        orig_bytes=orig_bytes,
        resp_bytes=resp_bytes,
        service="http",
        history="ShADadFf",
    )


class TestAnomalyDetector:

    def test_01_model_loading_and_attributes(self) -> None:
        """Detector loads frozen artifact with correct model version and calibration range."""
        detector = AnomalyDetector()
        assert detector.model_version == "isolation-forest-v1"
        assert detector.pipeline is not None
        assert detector.benign_min < detector.benign_max
        assert set(detector.expected_features) == set(ALL_MODEL_FEATURES)

    def test_02_feature_schema_validation(self) -> None:
        """Missing required feature raises FeatureSchemaError."""
        import pandas as pd
        bad_df = pd.DataFrame([{"duration": 1.0, "total_bytes": 100}])
        with pytest.raises(FeatureSchemaError) as exc_info:
            prepare_feature_dataframe(bad_df)
        assert "missing required features" in str(exc_info.value).lower()

    def test_03_inference_determinism(self) -> None:
        """Running predict on identical inputs returns identical scores and confidences."""
        detector = AnomalyDetector()
        records = [
            _make_dummy_conn("C1", duration=0.01, orig_bytes=1000000, resp_bytes=0),
            _make_dummy_conn("C2", duration=50.0, orig_bytes=100, resp_bytes=100),
        ]
        alerts_1 = detector.predict(records)
        alerts_2 = detector.predict(records)

        assert len(alerts_1) == len(alerts_2)
        for a1, a2 in zip(alerts_1, alerts_2):
            assert a1.confidence == a2.confidence
            assert a1.supporting_evidence["raw_anomaly_score"] == a2.supporting_evidence["raw_anomaly_score"]

    def test_04_alert_schema_compliance(self) -> None:
        """Emitted alerts comply strictly with docs/04_alert_schema.json."""
        detector = AnomalyDetector(anomaly_threshold=-0.5, min_confidence=0.0)
        rec = _make_dummy_conn("Canomaly1", duration=0.001, orig_bytes=5000000, resp_bytes=10)
        alerts = detector.predict([rec], pcap_id="test-pcap-123")

        assert len(alerts) >= 1
        alert = alerts[0]
        assert alert.threat_class == ThreatClass.ANOMALOUS_BEHAVIOR
        assert alert.detector == "ai_behavioral_anomaly"
        assert alert.model_version == "isolation-forest-v1"
        assert 0.0 <= alert.confidence <= 1.0
        assert alert.supporting_evidence["pcap_id"] == "test-pcap-123"
        assert "raw_anomaly_score" in alert.supporting_evidence
        assert "normalized_confidence" in alert.supporting_evidence

        # Fail-closed schema validator check
        is_valid, errors = validate_draft_alert(alert.to_dict())
        assert is_valid is True, f"Alert validation failed: {errors}"

    def test_05_integration_detector_to_fusion(self) -> None:
        """AI anomaly alert passes cleanly through OT-Aware FusionEngine."""
        detector = AnomalyDetector(anomaly_threshold=-0.5, min_confidence=0.0)
        rec = _make_dummy_conn("Cfusion1", duration=0.001, orig_bytes=1000000)
        drafts = detector.predict([rec])
        assert len(drafts) >= 1

        engine = FusionEngine()
        fused = engine.process_alerts(drafts)
        assert len(fused) == len(drafts)

        f_alert = fused[0]
        assert f_alert["threat_class"] == "anomalous_behavior"
        assert f_alert["detector"] == "ai_behavioral_anomaly"
        assert f_alert["severity"] in [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        # Confidence must remain untouched through fusion
        assert f_alert["confidence"] == drafts[0].confidence
