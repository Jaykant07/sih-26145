"""scripts/seed_demo_alerts.py
Seed demonstration alerts through the full OT-aware Fusion pipeline into SQLite.
All alerts pass through alerts/draft.py -> fusion/engine.py -> storage/sqlite_store.py.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from alerts.draft import create_draft_alert
from fusion.engine import fuse_alerts
from storage.sqlite_store import clear_alerts, get_kpi_summary, init_db, insert_alerts

DB_PATH = Path("data/alerts.db")


def seed_alerts() -> None:
    init_db(DB_PATH)
    clear_alerts(DB_PATH)

    now = datetime.now(timezone.utc)
    base_time = now - timedelta(minutes=45)

    drafts = [
        # --- Attack Chain 1: Attacker 192.168.56.200 Multi-Stage Incident ---
        # Stage 1: Port Scan reconnaissance against PLC-01 (critical asset)
        create_draft_alert(
            threat_class="reconnaissance",
            severity="low",
            confidence=0.96,
            source="192.168.56.200",
            destination="192.168.56.10",
            supporting_evidence={
                "scan_type": "port_scan",
                "ports_contacted": 1024,
                "duration_seconds": 12.5,
                "target_service": "Modbus-TCP",
                "flow_rate_pps": 81.9,
            },
            detector="zeek_scan_adapter",
            flow_id="flow-scan-001",
            timestamp=(base_time + timedelta(minutes=2)).isoformat(),
            subtype="port_scan",
            latency_class="event_driven",
            mitre_technique="T1046",
            action_recommended="block_ip",
        ),
        # Stage 2: C2 Beaconing to external controller
        create_draft_alert(
            threat_class="beaconing",
            severity="medium",
            confidence=0.92,
            source="192.168.56.200",
            destination="198.51.100.25",
            supporting_evidence={
                "beacon_score": 0.945,
                "connection_count": 84,
                "interval_range_seconds": "58.2 - 61.4",
                "ts_skew": 0.012,
                "duration_skew": 0.015,
            },
            detector="rita_beacon_adapter",
            flow_id="flow-c2-002",
            timestamp=(base_time + timedelta(minutes=4)).isoformat(),
            subtype="c2_beacon",
            latency_class="periodic",
            mitre_technique="T1071.001",
            action_recommended="isolate_host",
        ),
        # Stage 3: Bulk data exfiltration outbound
        create_draft_alert(
            threat_class="exfiltration",
            severity="high",
            confidence=0.98,
            source="192.168.56.200",
            destination="203.0.113.80",
            supporting_evidence={
                "outbound_bytes": 104857600,
                "inbound_bytes": 1024,
                "byte_ratio": 102400.0,
                "rolling_baseline_ratio": 1.4,
                "duration_seconds": 35.0,
            },
            detector="exfiltration_detector",
            flow_id="flow-exfil-003",
            timestamp=(base_time + timedelta(minutes=6)).isoformat(),
            subtype="asymmetric_upload",
            latency_class="event_driven",
            mitre_technique="T1048",
            action_recommended="sever_session",
        ),

        # --- Attack Incident 2: Engineering Workstation Compromise (192.168.56.102) ---
        # DGA DNS Queries
        create_draft_alert(
            threat_class="dga_dns",
            severity="medium",
            confidence=0.89,
            source="192.168.56.102",
            destination="10.0.0.1",
            supporting_evidence={
                "query_name": "xkj98vmbnz8.info",
                "dga_probability": 0.941,
                "entropy": 4.15,
                "vowel_ratio": 0.18,
                "ngram_score": 0.88,
            },
            detector="dga_detector",
            flow_id="flow-dns-004",
            timestamp=(base_time + timedelta(minutes=15)).isoformat(),
            subtype="algorithmic_domain",
            latency_class="event_driven",
            mitre_technique="T1568.002",
            action_recommended="sinkhole_domain",
        ),
        # DNS Tunnelling
        create_draft_alert(
            threat_class="dns_tunnel",
            severity="high",
            confidence=0.95,
            source="192.168.56.102",
            destination="8.8.8.8",
            supporting_evidence={
                "base_domain": "tunnel.dnscat2.bad",
                "query_count": 1420,
                "mean_subdomain_length": 48.2,
                "bytes_exfiltrated_est": 68160,
            },
            detector="rita_tunnel_adapter",
            flow_id="flow-tunnel-005",
            timestamp=(base_time + timedelta(minutes=18)).isoformat(),
            subtype="covert_channel",
            latency_class="periodic",
            mitre_technique="T1071.004",
            action_recommended="block_domain",
        ),

        # --- Incident 3: Encrypted Malware on HMI-01 (192.168.56.100, critical asset) ---
        create_draft_alert(
            threat_class="tls_anomaly",
            severity="medium",
            confidence=0.91,
            source="192.168.56.100",
            destination="198.51.100.99",
            supporting_evidence={
                "ja3": "6734f37431670b3ab4292b8f60f29984",
                "ja3_match": "Trickbot / Cobalt Strike C2",
                "sni": "update-service-cloud.biz",
                "self_signed": True,
                "validity_days": 3650,
                "behavioral_score": 0.82,
            },
            detector="tls_detector",
            flow_id="flow-tls-006",
            timestamp=(base_time + timedelta(minutes=25)).isoformat(),
            subtype="encrypted_c2",
            latency_class="event_driven",
            mitre_technique="T1573.002",
            action_recommended="quarantine_asset",
        ),

        # --- Incident 4: DDoS Flood against SCADA Master (10.0.0.1, critical asset) ---
        create_draft_alert(
            threat_class="ddos",
            severity="high",
            confidence=0.99,
            source="192.168.56.250",
            destination="10.0.0.1",
            supporting_evidence={
                "flood_type": "syn_flood",
                "packets_per_second": 145000,
                "syn_ack_ratio": 98.4,
                "baseline_pps": 1200,
                "amplification_factor": 120.8,
            },
            detector="ddos_detector",
            flow_id="flow-ddos-007",
            timestamp=(base_time + timedelta(minutes=35)).isoformat(),
            subtype="syn_flood",
            latency_class="event_driven",
            mitre_technique="T1498.001",
            action_recommended="rate_limit_firewall",
        ),
    ]

    print(f"Passing {len(drafts)} alerts through OT-Aware Fusion Engine...")
    fused = fuse_alerts(drafts)
    print(f"Fused {len(fused)} alerts successfully.")

    inserted = insert_alerts(fused, DB_PATH)
    print(f"Inserted {inserted} alerts into SQLite database: {DB_PATH}")

    kpis = get_kpi_summary(DB_PATH)
    print("Database KPIs after seeding:")
    for k, v in kpis.items():
        print(f"  {k}: {v}")


if __name__ == "__main__":
    seed_alerts()
