# PS-26145 — AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

## Mission

Build a **passive, local-first** cyber-threat detection system for read-only / unidirectional IP traffic.

The prototype analyzes controlled lab traffic or recorded PCAP replay, detects seven threat categories, normalizes all outputs into a unified alert contract, applies OT-aware correlation and asset criticality, and displays real alerts on a local dashboard.

## Hard Constraints

| Constraint | Rule |
|---|---|
| Passive / read-only | No blocking, injection, mitigation, or return-path |
| No payload decryption | Metadata, fingerprints, timing, behavior only |
| Incremental processing | Record-by-record, not wait-for-entire-PCAP |
| Local-first | Core processing and storage remain local |
| Explainability | Every alert includes `supporting_evidence` |
| Honest open-source use | Exact versions, licenses, attribution documented |

## Architecture

```text
                     LAB TRAFFIC / PCAP REPLAY
                                |
                                v
                              ZEEK
                  Passive Network Telemetry
           conn.log | dns.log | ssl.log | notice.log
                                |
                                v
                             INGEST
                       Async JSON Log Tailer
                                |
                 +--------------+--------------+
                 |                             |
                 v                             v
        TRACK A — REUSED              TRACK B — CUSTOM
        • RITA Beaconing              • DDoS
        • RITA DNS Tunnel             • DGA
        • Zeek Scan Framework         • TLS/Metadata
                                      • Exfiltration
                 |                             |
                 +--------------+--------------+
                                |
                                v
                       UNIFIED ALERT LAYER
                         DRAFT Alert Schema
                                |
                                v
                         OT-AWARE FUSION
                  Correlation + Asset Criticality
                                |
                                v
                              SQLITE
                                |
                                v
                       STREAMLIT DASHBOARD
```

## Detector Decisions

| Threat | Decision | Implementation |
|---|---|---|
| Volumetric DDoS | CUSTOM | Sliding-window flow detector |
| C2 Beaconing | REUSE | RITA + adapter |
| DGA | CUSTOM | FANCI-inspired feature classifier (Random Forest) |
| DNS Tunnelling | REUSE | RITA + adapter |
| Suspicious Encrypted TLS | CUSTOM | Metadata/fingerprint/behavior |
| Recon/Port Scan | REUSE | Zeek Scan + adapter |
| Data Exfiltration | CUSTOM | Byte-ratio/behavior detector |

## Technology Stack

- Ubuntu VM
- Python + asyncio
- Zeek (passive telemetry)
- RITA (beaconing, DNS tunnelling)
- scikit-learn (DGA model)
- SQLite (local alert storage)
- Streamlit (dashboard)
- pytest (testing)

## References

- Schüppen et al., *FANCI: Feature-based Automated NXDomain Classification and Intelligence*, USENIX Security 2018.
- Zeek official documentation.
- RITA official repository/documentation.

## License

See individual component licenses in `docs/05_COMPONENTS.md`.
