"""Unit tests for DGADetector inference, DNS log ingestion, and alert generation."""

import json
import tempfile
from pathlib import Path
import pytest

from alerts.constants import LatencyClass, Severity, ThreatClass
from alerts.validator import validate_draft_alert
from detectors.dga.infer import DGADetector, DEFAULT_MODEL_PATH


@pytest.fixture(scope="module")
def dga_detector() -> DGADetector:
    if not Path(DEFAULT_MODEL_PATH).exists():
        pytest.skip("Production model not yet trained at DEFAULT_MODEL_PATH")
    return DGADetector()


class TestDGADetectorInference:
    def test_benign_domain_prediction(self, dga_detector: DGADetector):
        res = dga_detector.predict_domain("google.com")
        assert res["domain"] == "google.com"
        assert res["extracted_label"] == "google"
        assert res["is_dga"] is False
        assert res["probability"] < dga_detector.threshold

        # Should not create alert for benign domain
        alert = dga_detector.create_alert("google.com", res)
        assert alert is None

    def test_dga_domain_prediction_and_alert(self, dga_detector: DGADetector):
        # Synthetic random DGA domain from dga-001
        dga_domain = "vn0xg58vzlubb.lab.local"
        res = dga_detector.predict_domain(dga_domain)
        assert res["is_dga"] is True
        assert res["probability"] >= dga_detector.threshold

        telemetry = {
            "ts": 1726732800.0,
            "id.orig_h": "192.168.1.105",
            "id.resp_h": "192.168.1.1",
            "proto": "udp",
            "query": dga_domain,
        }
        alert = dga_detector.create_alert(dga_domain, res, telemetry)
        assert alert is not None

        # Verify alert properties per PS-26145 unified contract
        alert_dict = alert.to_dict()
        assert alert_dict["threat_class"] == ThreatClass.DGA
        assert alert_dict["subtype"] == "dga_dns"
        assert alert_dict["latency_class"] == LatencyClass.EVENT_DRIVEN
        assert alert_dict["model_version"] == dga_detector.model_version
        assert alert_dict["source"] == "192.168.1.105"
        assert alert_dict["destination"] == "192.168.1.1"

        evidence = alert_dict["supporting_evidence"]
        assert evidence["domain"] == dga_domain
        assert evidence["extracted_label"] == "vn0xg58vzlubb"
        assert "probability_estimate" in evidence
        assert "calibration_status" in evidence
        assert "threshold" in evidence

        # Validate against schema
        is_valid, errors = validate_draft_alert(alert_dict)
        assert is_valid, f"Validation failed with errors: {errors}"

    def test_process_dns_log(self, dga_detector: DGADetector):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "dns.log"
            records = [
                {"ts": 1726732801.0, "id.orig_h": "10.0.0.2", "id.resp_h": "10.0.0.1", "query": "google.com"},
                {"ts": 1726732802.0, "id.orig_h": "10.0.0.2", "id.resp_h": "10.0.0.1", "query": "vn0xg58vzlubb.lab.local"},
                {"ts": 1726732803.0, "id.orig_h": "10.0.0.2", "id.resp_h": "10.0.0.1", "query": "microsoft.com"},
            ]
            with open(log_file, "w", encoding="utf-8") as f:
                for r in records:
                    f.write(json.dumps(r) + "\n")

            alerts_file = Path(tmpdir) / "alerts.json"
            results_file = Path(tmpdir) / "results.json"
            results = dga_detector.run(log_file, output_alerts=alerts_file, results_path=results_file)

            assert results["total_dns_queries"] == 3
            assert results["detected_queries"] >= 1
            assert alerts_file.exists()
            assert results_file.exists()
