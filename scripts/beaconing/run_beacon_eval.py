"""
Evaluation Pipeline for C2 Beaconing Detector (PS-26145 — Track A).

Processes native RITA v5.1.2 analysis for validated beacon experiments:
  1. Fixed beacon (0% jitter, 60s interval): ps26145_beacon_fixed
  2. Jittered beacon (~20% jitter, 60s base): ps26145_beacon_jitter
  3. Legitimate periodic service (DNS resolver/root servers): ps26145_test
  4. Production baseline: ps26145_prod

Generates raw CSV captures, adapter_alerts.json, metadata.json, and summary.json
under artifacts/beaconing/.
"""

from __future__ import annotations

import json
import logging
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

repo_root = Path(__file__).resolve().parent.parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from detectors.beaconing.rita_adapter import (
    DEFAULT_SCORE_THRESHOLD,
    RitaBeaconAdapter,
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("run_beacon_eval")


def run_all_evaluations() -> None:
    adapter = RitaBeaconAdapter(score_threshold=DEFAULT_SCORE_THRESHOLD)

    experiments = [
        {
            "id": "BEACON-FIXED",
            "name": "Fixed Beacon (0% jitter)",
            "database": "ps26145_beacon_fixed",
            "ground_truth": "malicious",
            "attack_type": "c2_beaconing_fixed",
            "generator": "beacon_client.py --interval 60.0 --jitter-pct 0.0",
            "source": "172.16.0.100",
            "destination": "203.0.113.50:8080",
            "zeek_dir": Path("zeek_output_beacon_test_fixed"),
            "out_dir": Path("artifacts/beaconing/fixed"),
        },
        {
            "id": "BEACON-JITTER",
            "name": "Jittered Beacon (~20% jitter)",
            "database": "ps26145_beacon_jitter",
            "ground_truth": "malicious",
            "attack_type": "c2_beaconing_jitter",
            "generator": "beacon_client.py --interval 60.0 --jitter-pct 0.2",
            "source": "172.16.0.100",
            "destination": "203.0.113.50:8080",
            "zeek_dir": Path("zeek_output_beacon_test_jitter"),
            "out_dir": Path("artifacts/beaconing/jitter"),
        },
        {
            "id": "BEACON-BENIGN-PERIODIC",
            "name": "Legitimate Periodic Service (DNS Infrastructure)",
            "database": "ps26145_test",
            "ground_truth": "benign",
            "attack_type": "benign_periodic_service",
            "generator": "periodic DNS resolver and root-server lookups",
            "source": "172.16.0.79 / 172.16.0.81",
            "destination": "8.8.8.8 / 198.41.0.4",
            "zeek_dir": None,
            "out_dir": Path("artifacts/beaconing/benign_periodic"),
        },
        {
            "id": "BEACON-PROD",
            "name": "Production Lab Baseline",
            "database": "ps26145_prod",
            "ground_truth": "benign",
            "attack_type": "production_baseline",
            "generator": "real network capture baseline",
            "source": "various",
            "destination": "various",
            "zeek_dir": None,
            "out_dir": Path("artifacts/beaconing/prod"),
        },
    ]

    summary_records = []

    for exp in experiments:
        logger.info("\n========================================================")
        logger.info("Evaluating %s (%s)", exp["id"], exp["name"])
        logger.info("========================================================")

        out_dir = exp["out_dir"]
        out_dir.mkdir(parents=True, exist_ok=True)
        raw_csv_path = out_dir / "rita_raw.csv"
        alerts_path = out_dir / "adapter_alerts.json"
        metadata_path = out_dir / "metadata.json"

        # Copy Zeek conn.log if available
        total_zeek_conns = 0
        beacon_zeek_conns = 0
        if exp["zeek_dir"] and exp["zeek_dir"].exists():
            zeek_target = out_dir / "zeek"
            zeek_target.mkdir(parents=True, exist_ok=True)
            conn_src = exp["zeek_dir"] / "conn.log"
            if conn_src.exists():
                shutil.copy2(conn_src, zeek_target / "conn.log")
                with open(conn_src, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            total_zeek_conns += 1
                            if "172.16.0.100" in line and "203.0.113.50" in line:
                                beacon_zeek_conns += 1

        # Capture raw RITA stdout
        adapter.reset_state()
        raw_stdout = adapter.run_rita_beacon_analysis(
            database=exp["database"],
            output_path=raw_csv_path,
        )

        # Process through adapter
        eval_result = adapter.run(
            database=exp["database"],
            csv_file=raw_csv_path,
            output_alerts=alerts_path,
        )

        emitted_alerts = eval_result["alerts"]
        detected = len(emitted_alerts) > 0

        # Extract top score and target details from raw output
        top_score = 0.0
        top_target = "N/A"
        raw_rows = adapter.parse_rita_beacon_output(raw_stdout)
        if raw_rows:
            try:
                top_score = float(raw_rows[0].get("Beacon Score", "0.0"))
                top_target = (
                    f"{raw_rows[0].get('Source IP')} -> {raw_rows[0].get('Destination IP')}"
                )
            except ValueError:
                top_score = 0.0

        metadata = {
            "experiment_id": exp["id"],
            "name": exp["name"],
            "ground_truth": exp["ground_truth"],
            "attack_type": exp["attack_type"],
            "generator": exp["generator"],
            "source": exp["source"],
            "destination": exp["destination"],
            "rita_database": exp["database"],
            "rita_version": adapter.rita_version,
            "score_threshold": DEFAULT_SCORE_THRESHOLD,
            "total_zeek_connections": total_zeek_conns,
            "beacon_zeek_connections": beacon_zeek_conns,
            "total_rita_rows": eval_result["total_rita_records"],
            "beacon_candidates": eval_result["beacon_candidates"],
            "qualified_above_threshold": eval_result["qualified_above_threshold"],
            "new_alerts_emitted": eval_result["new_alerts_emitted"],
            "top_beacon_score": top_score,
            "top_target": top_target,
            "detected": detected,
            "threat_intel_enabled": False,
            "blacklist_enabled": False,
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
        }

        with open(metadata_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)

        summary_records.append(metadata)
        logger.info(
            "%s: RITA rows: %d, Candidates: %d, Above threshold: %d, Alerts: %d (Top score: %.3f)",
            exp["id"],
            eval_result["total_rita_records"],
            eval_result["beacon_candidates"],
            eval_result["qualified_above_threshold"],
            eval_result["new_alerts_emitted"],
            top_score,
        )

    # Save consolidated summary
    summary_path = Path("artifacts/beaconing/summary.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "detector": "rita_beacon_adapter",
                "model_version": "5.1.2",
                "rita_version": "v5.1.2",
                "score_threshold": DEFAULT_SCORE_THRESHOLD,
                "latency_class": "periodic",
                "experiments": summary_records,
                "generated_at": datetime.now(timezone.utc).isoformat(),
            },
            f,
            indent=2,
        )
    logger.info("Saved consolidated summary to %s", summary_path)


if __name__ == "__main__":
    run_all_evaluations()
