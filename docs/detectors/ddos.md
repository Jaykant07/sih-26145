# DDoS Detector — PS-26145

## 1. Objective

Detect volumetric and protocol-level DDoS attacks from passive Zeek flow metadata (`conn.log`) without any active network scanning, packet injection, or return-path communication.

Target behaviours:
- Volumetric DDoS (high packet/byte rate)
- SYN flood
- UDP flood / reflection-like behaviour
- Spoofed/distributed-source-like flood behaviour

## 2. Inputs

Zeek `conn.log` in JSON format (one record per line).

Relevant fields (verified against actual output):
- `ts` (100%)
- `uid` (100%)
- `id.orig_h`, `id.orig_p` (100%)
- `id.resp_h`, `id.resp_p` (100%)
- `proto` (100%) — tcp/udp/icmp
- `conn_state` (100%) — S0, SF, SHR, RSTR, OTH etc.
- `orig_pkts`, `resp_pkts` (100%)
- `orig_ip_bytes`, `resp_ip_bytes` (100%) — PRIMARY byte metrics
- `history` (98.6%) — optional
- `service` (90.6%) — optional
- `duration` (45.1%) — optional, missing for many S0 connections
- `orig_bytes`, `resp_bytes` (45.1%) — optional

> [!IMPORTANT]
> `duration`, `orig_bytes`, and `resp_bytes` are missing ~55% of the time in passive connection records (especially aborted handshakes like S0). The detector uses `orig_ip_bytes` and `resp_ip_bytes` as primary byte metrics.

## 3. Architecture

Data flow:
```
Zeek conn.log → ingest/parser.py (ConnRecord) → features/flow_stats.py (FlowWindow) → detectors/ddos/detector.py → alerts/draft.py (DraftAlert)
```

Modules:
- [`ingest/parser.py`](file:///home/jay/sih-26145/ingest/parser.py) — Shared Zeek JSON parser ([`ConnRecord`](file:///home/jay/sih-26145/ingest/parser.py#L22-L58))
- [`features/flow_stats.py`](file:///home/jay/sih-26145/features/flow_stats.py) — Shared flow window aggregation ([`FlowWindow`](file:///home/jay/sih-26145/features/flow_stats.py#L57-L94))
- [`detectors/ddos/config.py`](file:///home/jay/sih-26145/detectors/ddos/config.py) — Configuration ([`DDoSConfig`](file:///home/jay/sih-26145/detectors/ddos/config.py#L14-L66))
- [`detectors/ddos/baseline.py`](file:///home/jay/sih-26145/detectors/ddos/baseline.py) — Rolling baseline ([`MetricBaseline`](file:///home/jay/sih-26145/detectors/ddos/baseline.py#L20-L89), [`DestinationBaseline`](file:///home/jay/sih-26145/detectors/ddos/baseline.py#L91-L134), [`BaselineStore`](file:///home/jay/sih-26145/detectors/ddos/baseline.py#L135-L160))
- [`detectors/ddos/classifier.py`](file:///home/jay/sih-26145/detectors/ddos/classifier.py) — Sub-classification ([`classify_ddos`](file:///home/jay/sih-26145/detectors/ddos/classifier.py#L31-L100))
- [`detectors/ddos/detector.py`](file:///home/jay/sih-26145/detectors/ddos/detector.py) — Core detection engine ([`DDoSDetector`](file:///home/jay/sih-26145/detectors/ddos/detector.py#L57-L278))
- [`detectors/ddos/benchmark.py`](file:///home/jay/sih-26145/detectors/ddos/benchmark.py) — Performance instrumentation ([`BenchmarkResult`](file:///home/jay/sih-26145/detectors/ddos/benchmark.py#L31-L60))
- [`alerts/draft.py`](file:///home/jay/sih-26145/alerts/draft.py) — DRAFT alert factory ([`DraftAlert`](file:///home/jay/sih-26145/alerts/draft.py#L20-L57))
- [`alerts/constants.py`](file:///home/jay/sih-26145/alerts/constants.py) — Shared constants ([`ThreatClass`](file:///home/jay/sih-26145/alerts/constants.py#L13-L23), [`Severity`](file:///home/jay/sih-26145/alerts/constants.py#L25-L33), [`LatencyClass`](file:///home/jay/sih-26145/alerts/constants.py#L35-L39))
- [`alerts/validator.py`](file:///home/jay/sih-26145/alerts/validator.py) — Schema validation ([`validate_draft_alert`](file:///home/jay/sih-26145/alerts/validator.py#L32-L73))

## 4. Feature Definitions

Per [`FlowWindow`](file:///home/jay/sih-26145/features/flow_stats.py#L57-L94) (aggregated per destination IP per time window):

| Feature | Source | Description |
|---------|--------|-------------|
| `flow_count` | count of records | Total connections in window |
| `packet_count` | `sum(orig_pkts + resp_pkts)` | Total packets |
| `byte_count` | `sum(orig_ip_bytes + resp_ip_bytes)` | Total IP-level bytes |
| `pkt_rate` | `packet_count / window_seconds` | Packets per second |
| `byte_rate` | `byte_count / window_seconds` | Bytes per second |
| `unique_source_count` | `count distinct src_ip` | Source diversity |
| `src_ip_entropy` | Shannon entropy of source IP freq. distribution | Source distribution measure |
| `tcp_flow_count` | count where `proto=tcp` | TCP connections |
| `udp_flow_count` | count where `proto=udp` | UDP connections |
| `icmp_flow_count` | count where `proto=icmp` | ICMP connections |
| `tcp_syn_count` | count where `conn_state` in `{S0,REJ,RSTOS0,RSTRH}` | SYN-only connections |
| `tcp_syn_ack_count` | count where `conn_state` in `{SF,S1,S2,...}` | Completed handshakes |
| `conn_state_counts` | frequency dict | State distribution |
| `total_orig_ip_bytes` | `sum(orig_ip_bytes)` | Request volume |
| `total_resp_ip_bytes` | `sum(resp_ip_bytes)` | Response volume |

## 5. Flow Window

Records are assigned to windows based on `floor(ts / window_seconds)`.

Default: `window_seconds = 10` (configurable prototype parameter, NOT claimed as scientifically optimal).

Windows are computed per destination IP. Sorted by `(window_start, destination_ip)`.

## 6. Rolling Baseline

For every destination IP, a rolling baseline of the previous N clean (non-flagged) windows is maintained.

Metrics tracked:
- `pkt_rate`
- `byte_rate`
- `src_ip_entropy`

Default: `baseline_windows = 30` (configurable prototype parameter).

Implementation: Fixed-size deque per metric in [`MetricBaseline`](file:///home/jay/sih-26145/detectors/ddos/baseline.py#L20-L89) class.

## 7. Baseline Poisoning Prevention

CRITICAL INVARIANT: Flagged (anomalous) windows are NEVER added to the clean baseline.

This prevents an attacker from gradually shifting the baseline upward through sustained attack traffic, which would make future attacks harder to detect.

Tested explicitly with a regression test (`TestCase10_BaselinePoisoningRegression` / `test_sustained_attack_does_not_poison_baseline`).

## 8. Z-Score Calculation

For each new window:

```
z = (current_rate - baseline_mean) / max(baseline_stddev, epsilon)
```

Calculated separately for:
- `pkt_z_score`
- `byte_z_score`

Default: `z_threshold = 4.0` (initial tunable threshold, NOT a universal constant).  
Default: `epsilon = 1e-9` (prevents division by zero).

Zero-variance baselines: When `stddev < epsilon`, division uses `epsilon`. If current value equals mean, `z ≈ 0`.

## 9. Source-IP Entropy

Shannon entropy from source-IP frequency distribution:

```
p_i = source_count_i / total_source_count
H = -sum(p_i * log2(p_i))
```

Interpretation:
- LOW entropy: Few sources dominate (could indicate single-source flood)
- HIGH entropy: Many diverse sources (could indicate distributed/spoofed attack)

Entropy ALONE does not prove spoofing. It is supporting evidence.

The detector compares current entropy against a rolling historical entropy baseline (z-score) rather than relying on an arbitrary absolute threshold.

Detects both significant entropy drops and significant entropy spikes.

Default: `entropy_z_threshold = 3.0`

## 10. Threshold Logic (Decision Rule)

The exact decision rule is:

```
rate_anomaly AND entropy_anomaly
```

where:
- `rate_anomaly = (pkt_z_score >= z_threshold) OR (byte_z_score >= z_threshold)`
- `entropy_anomaly = abs(entropy_z_score) >= entropy_z_threshold`

The AND gate exists specifically to reduce false positives from legitimate traffic bursts. A high packet rate alone does NOT trigger a DDoS alert.

## 11. SYN Flood Detection

Evidence:
- TCP traffic dominant
- `tcp_syn_ratio` (`syn_count / tcp_flow_count`) `>= syn_ratio_threshold` (default 0.8)
- Abnormal handshake completion
- Elevated packet rate
- Destination concentration

Classified by [`classifier.py`](file:///home/jay/sih-26145/detectors/ddos/classifier.py) when SYN ratio exceeds threshold.

## 12. UDP Flood Detection

Evidence:
- UDP traffic dominant
- `udp_ratio` (`udp_flow_count / flow_count`) `>= udp_ratio_threshold` (default 0.8)
- Elevated packet/byte rate
- Destination concentration

## 13. Reflection/Amplification-Like Detection

Evidence:
- Many source IPs (`>= min_unique_sources_reflection`, default 10)
- Concentrated destination/service
- Response volume substantially exceeds request volume (`resp_to_orig_byte_ratio >= reflection_resp_ratio`, default 3.0)

Labeled `reflection_amplification_like` (not `reflection`) because passive flow metadata cannot definitively prove reflection.

## 14. Spoofing-Like Detection

Evidence:
- Abnormal source-IP diversity (`>= min_unique_sources_spoofing`, default 20)
- Strong traffic spike (rate anomaly)
- Abnormal connection completion behaviour

Labeled `spoofing_like` because spoofing cannot be confirmed from flow metadata alone.

## 15. Alert Schema

DRAFT alert per master plan Section 9.

Required fields: `alert_id`, `timestamp`, `flow_id`, `threat_class` (`'ddos'`), `severity`, `confidence`, `source`, `destination`, `supporting_evidence`, `detector` (`'ddos_detector'`), `detector_version` (`'0.1.0'`), `schema_version` (`'1.0.0'`).

Optional: `subtype` (`syn_flood`, `udp_flood`, etc.), `latency_class` (`'event_driven'`).

This is a detector-level DRAFT alert. Final severity is determined by OT-aware fusion.

## 16. Confidence Methodology

Confidence is derived deterministically from z-scores:

```
raw = max(pkt_z, byte_z) / (2 * z_threshold)
confidence = min(max(raw, 0.0), 1.0)
```

Mapping:
- `z == z_threshold` → `confidence ≈ 0.5`
- `z == 2 * z_threshold` → `confidence ≈ 1.0`
- `z > 2 * z_threshold` → `confidence = 1.0` (capped)

This is a transparent, deterministic transformation. It is NOT a calibrated probability. It must not be described as a calibrated probability.

Severity mapping (detector-level, NOT fusion-level):
- `confidence >= 0.8` → HIGH
- `confidence >= 0.5` → MEDIUM
- else → LOW

## 17. Limitations

1. Flow metadata only — no payload inspection, no packet-level analysis.
2. Cannot definitively prove spoofing or reflection from flow data.
3. Cannot distinguish DDoS from legitimate traffic bursts with unusual source patterns without additional context.
4. Statistical baselines require a warm-up period (`baseline_windows` clean observations).
5. Sub-second timing analysis is not possible from Zeek connection logs.
6. Encrypted traffic analysis limited to metadata.
7. The detector does not identify the attacker — only the anomalous traffic pattern.
8. All thresholds are initial prototype values requiring empirical tuning.

## 18. False-Positive Scenarios

1. Legitimate CDN or load balancer traffic causing many diverse sources.
2. Backup or data transfer jobs creating byte-rate spikes with unusual source patterns.
3. DNS resolver behaviour (periodic queries from many clients).
4. Network scanning tools creating SYN-like patterns.
5. Application-layer events (software update rollouts, mass reconnections).
6. Flash crowd events.

The AND-gated decision (rate + entropy) mitigates many of these, but does not eliminate all.

## 19. Configuration

All parameters in [`detectors/ddos/config.py`](file:///home/jay/sih-26145/detectors/ddos/config.py) ([`DDoSConfig`](file:///home/jay/sih-26145/detectors/ddos/config.py#L14-L66) dataclass):

| Parameter | Default | Description |
|-----------|---------|-------------|
| `window_seconds` | 10.0 | Flow window duration |
| `baseline_windows` | 30 | Number of clean windows in rolling baseline |
| `z_threshold` | 4.0 | Z-score threshold for rate anomaly |
| `epsilon` | 1e-9 | Minimum denominator for z-score |
| `entropy_z_threshold` | 3.0 | Z-score threshold for entropy anomaly |
| `syn_ratio_threshold` | 0.8 | SYN-only ratio for SYN flood classification |
| `udp_ratio_threshold` | 0.8 | UDP ratio for UDP flood classification |
| `reflection_resp_ratio` | 3.0 | Response/request byte ratio for reflection-like |
| `min_unique_sources_reflection` | 10 | Min sources for reflection-like |
| `min_unique_sources_spoofing` | 20 | Min sources for spoofing-like |
| `min_flows_for_detection` | 5 | Min flows per window for analysis |

All values are initial prototype parameters, not scientifically optimal constants.

## 20. Testing Methodology

16 required test cases in [`tests/unit/test_ddos_detector.py`](file:///home/jay/sih-26145/tests/unit/test_ddos_detector.py):

1. Normal traffic → no alert
2. High pkt rate alone → no alert (entropy guard)
3. High byte rate alone → no alert (entropy guard)
4. Rate anomaly + entropy anomaly → alert
5. Low entropy flood + rate anomaly → triggers
6. High entropy distributed-source + rate anomaly → triggers
7. Zero stddev → no crash
8. Missing optional fields → no crash
9. Flagged windows excluded from baseline
10. Baseline poisoning regression
11. Independent baselines per destination
12. Multiple windows update baseline
13. SYN flood classification
14. UDP flood classification
15. Evidence fields populated
16. Alert schema validation passes

Additional tests: [`MetricBaseline`](file:///home/jay/sih-26145/detectors/ddos/baseline.py#L20-L89) direct tests, confidence range bounds.

Test data: Synthetic [`FlowWindow`](file:///home/jay/sih-26145/features/flow_stats.py#L57-L94) objects for deterministic testing. Real Zeek `conn.log` for integration validation.

## 21. Future ML Extension

This implementation is initially rule/statistical based. ML is intentionally deferred until measured labeled replay data demonstrates that the statistical detector is insufficient.

Potential ML extensions:
- Supervised classifier trained on labeled DDoS traffic vs. benign anomalies
- Autoencoder for unsupervised anomaly detection on flow features
- Online learning for adaptive baseline computation
- Feature importance analysis to refine the statistical features

Any ML extension must maintain: explainability (`supporting_evidence`), determinism, passive operation, and compatibility with the DRAFT alert schema.
