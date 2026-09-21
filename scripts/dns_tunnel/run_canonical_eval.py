"""
Canonical Evaluation Pipeline for DNS Tunnelling Detection (PS-26145 — Track A).

Processes native RITA v5.1.2 analysis for canonical dnscat2 PCAPs:
  - dns-001-dnscat2.pcap
  - dns-002-dnscat2-jitter.pcap

Generates detector_results.json, sample_alerts.json, and metadata.json.
"""

from __future__ import annotations

import json
import logging
import shutil
from datetime import datetime, timezone
from pathlib import Path

from detectors.dns.rita_tunnel_adapter import RitaTunnelAdapter

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("dns_tunnel_eval")


def run_canonical_evaluation() -> None:
    adapter = RitaTunnelAdapter()

    eval_configs = [
        {
            "id": "DNS-001",
            "pcap": "data/raw/dns_tunnel/dns-001-dnscat2.pcap",
            "description": "Standard dnscat2 0.07 DNS tunnel over UDP/53531",
            "generator": "dnscat2 0.07",
            "source": "192.168.56.102",
            "destination": "192.168.56.254:53531",
            "domain": "lab.local",
            "zeek_log": Path("artifacts/dns_tunnel/dns-001/zeek/dns.log"),
            "database": "ps26145_dns_001",
            "manual_csv": Path("artifacts/dns_tunnel/manual/rita_view_ps26145_dns_001.csv"),
            "out_dir": Path("artifacts/dns_tunnel/dns-001"),
        },
        {
            "id": "DNS-002",
            "pcap": "data/raw/dns_tunnel/dns-002-dnscat2-jitter.pcap",
            "description": "dnscat2 0.07 with jitter (--delay 2000 --steady) over UDP/53531",
            "generator": "dnscat2 0.07 --delay 2000 --steady",
            "source": "192.168.56.102:52775",
            "destination": "192.168.56.254:53531",
            "domain": "lab.local",
            "zeek_log": Path("artifacts/dns_tunnel/dns-002/zeek/dns.log"),
            "database": "ps26145_dns_002",
            "manual_csv": Path("artifacts/dns_tunnel/manual/rita_view_ps26145_dns_002.csv"),
            "out_dir": Path("artifacts/dns_tunnel/dns-002"),
        },
    ]

    for cfg in eval_configs:
        logger.info("\n--- Evaluating %s (%s) ---", cfg["id"], cfg["pcap"])
        out_dir = cfg["out_dir"]
        detector_dir = out_dir / "detector"
        detector_dir.mkdir(parents=True, exist_ok=True)

        alerts_path = detector_dir / "sample_alerts.json"
        results_path = detector_dir / "detector_results.json"
        metadata_path = out_dir / "metadata.json"
        saved_csv = out_dir / "rita_native_view.csv"

        if cfg["manual_csv"].exists():
            shutil.copy2(cfg["manual_csv"], saved_csv)

        # Count Zeek records
        total_zeek_lines = 0
        zeek_data_queries = 0
        if cfg["zeek_log"].exists():
            with open(cfg["zeek_log"], "r", encoding="utf-8", errors="replace") as f:
                lines = [line.strip() for line in f if line.strip()]
                total_zeek_lines = len(lines)
                zeek_data_queries = sum(1 for line in lines if not line.startswith("#"))

        # Run adapter evaluation
        results = adapter.run(
            database=cfg["database"],
            csv_file=cfg["manual_csv"],
            output_alerts=alerts_path,
            results_path=results_path,
        )

        detected = results["c2_over_dns_findings"] > 0
        detection_status = "detected" if detected else "not_detected"

        logger.info(
            "%s: Zeek lines: %d (queries: %d), RITA C2 Over DNS hits: %d, Alerts: %d (Status: %s)",
            cfg["id"],
            total_zeek_lines,
            zeek_data_queries,
            results["c2_over_dns_findings"],
            results["new_alerts_emitted"],
            detection_status,
        )

        metadata = {
            "experiment_id": cfg["id"],
            "dataset": cfg["pcap"],
            "canonical": True,
            "ground_truth": "malicious",
            "attack_type": "dns_tunnel_c2",
            "threat_class": "dns_tunnel",
            "subtype": "c2_over_dns",
            "latency_class": "periodic",
            "generator": cfg["generator"],
            "source": cfg["source"],
            "destination": cfg["destination"],
            "domain": cfg["domain"],
            "zeek_version": "zeek version 9.0.0",
            "zeek_port": "UDP/53531",
            "zeek_script": "scripts/dns_tunnel/dns_53531.zeek",
            "zeek_total_lines": total_zeek_lines,
            "zeek_dns_records": zeek_data_queries,
            "rita_version": adapter.rita_version,
            "rita_database": cfg["database"],
            "rita_detection_engine": "C2 Over DNS analysis",
            "rita_c2_over_dns_detected": detected,
            "detection_status": detection_status,
            "reason_if_negative": (
                "RITA v5.1.2 c2_score_thresholds.base requires >= 100 subdomains; "
                "tables.go explicitly filters out '.local' TLDs; "
                "and internal-to-internal (192.168.0.0/16) traffic is excluded from external threat scoring."
                if not detected else "N/A"
            ),
            "threat_intel_enabled": False,
            "blacklist_enabled": False,
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
        }

        with open(metadata_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)
        logger.info("Saved metadata to %s", metadata_path)


if __name__ == "__main__":
    run_canonical_evaluation()
