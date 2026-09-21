# Architecture and Design Decisions

## Decision 001: RITA Contingency Activation

**Date:** 2026-09-12
**Phase:** 6 (RITA Verification)

### Context
The master execution plan specifies using RITA for Beaconing and DNS Tunnelling detection (Track A), subject to a strict 4-hour timebox during Phase 6. RITA v5.1.2 relies heavily on MongoDB for storage and computation, and its installation script explicitly requires `sudo` privileges and/or Docker.

### Blocker
The current Ubuntu 26.04 VM environment is highly constrained:
1. `sudo` requires interactive password authentication, which is not available to the automated deployment context.
2. `mongod` is not installed, and cannot be installed via `apt` without `sudo`.
3. `docker` daemon is not available or reachable.

Attempting to run the RITA installer (`install_rita.sh`) fails immediately due to missing `sudo` and Docker dependencies.

### Decision
In accordance with **Section 7: RITA CONTINGENCY** of the master plan:
1. We are stopping the timebox immediately to avoid endless troubleshooting.
2. We are invoking the approved fallback strategy.
3. We will build **custom, periodic/rolling Python detectors** for Beaconing and DNS Tunnelling. 

### Fallback Implementation Constraints
These new custom detectors will adhere to the following rules:
- **Passive & Local:** Analyze the Zeek JSON logs (`conn.log`, `dns.log`) locally in memory or via the SQLite store.
- **Explainable:** Provide deterministic metrics (e.g., connection periodicity, byte uniformity, DNS payload length, subdomain entropy) as `supporting_evidence`.
- **Architectural Compatibility:** Emit the exact same DRAFT alert schema as all other detectors, preserving the integrity of the unified alert layer and OT-aware fusion pipeline.

---

## Decision 001 – Addendum: RITA Confirmed Functional, Contingency Partially Reversed

**Date:** 2026-09-13
**Phase:** 6 (RITA Verification – Continued)

### Correction: MongoDB Assumption Was Wrong

The original contingency entry (above) stated that "RITA v5.1.2 relies heavily on MongoDB." This was incorrect — it was based on outdated documentation from RITA v4.x. **RITA v5.x uses ClickHouse, not MongoDB.** The RITA v5.1.2 repository ships a `docker-compose.yml` that provisions ClickHouse (`clickhouse/clickhouse-server:24.1.6`) and uses it for all storage and analysis.

### RITA Confirmed Working

After cloning the RITA v5.1.2 repository and starting it via Docker Compose, RITA is fully functional:
- **Docker Compose stack:** `clickhouse` (healthy), `syslog-ng`, `rita` (image: `ghcr.io/activecm/rita:latest`)
- **Import method:** `docker compose run --rm -v <host_logs>:/logs rita import --database <name> --logs /logs`
- **View method:** `docker compose run --rm rita view --stdout <dataset>`
- **Log mount fix:** RITA's compose file does not mount Zeek logs by default; they must be bind-mounted via `-v` on each `docker compose run` invocation.

### Beacon True-Positive Validation (Step 1)

Two synthetic beacon test datasets were generated and imported to validate RITA's beacon detection against our own `beacon_client.py` → `beacon_listener.py` traffic pattern:

- **Beacon source:** `172.16.0.100` (internal)
- **Beacon destination:** `203.0.113.50:8080` (external, simulating beacon_listener.py)
- **Protocol:** `tcp:http` (HTTP GET /checkin at regular intervals)
- **60 connections over 1 hour** in each dataset

**Note:** RITA filters internal→internal and external→external connections at import time (`internal_subnets` config). Only internal→external connections are analyzed. Initial import attempt with 192.168.x.x→192.168.x.x failed with "could not find imported data." Data was regenerated with an external destination IP.

#### Dataset: `ps26145_beacon_fixed` (0% jitter, exact 60s interval)

| Source IP | Destination IP | Beacon Score | Severity | Connection Count | Port:Proto:Service |
|-----------|---------------|--------------|----------|------------------|--------------------|
| 172.16.0.100 | 203.0.113.50 | **0.977** | **High** | 60 | 8080:tcp:http |

#### Dataset: `ps26145_beacon_jitter` (20% jitter, ~48–72s interval)

| Source IP | Destination IP | Beacon Score | Severity | Connection Count | Port:Proto:Service |
|-----------|---------------|--------------|----------|------------------|--------------------|
| 172.16.0.100 | 203.0.113.50 | **0.916** | **High** | 60 | 8080:tcp:http |

**Conclusion:** RITA successfully detects our beacon traffic as a true positive. Fixed-interval beaconing scores 0.977, jittered beaconing scores 0.916 — both classified as "High" severity, well above the alerting threshold. The ~6% score reduction from 20% jitter confirms RITA's scoring model is jitter-aware but still robust.

### Strobe Column Definition (Step 2)

From `rita view --help` and RITA source code (`analysis/analysis.go` lines 249-253, `viewer/csv.go` line 79):

**Strobe** is a boolean column in the `rita view --stdout` CSV output. It is `true` when a connection pair's `StrobeScore > 0`, and `false` otherwise.

A connection is classified as a **strobe** when the total connection count between a source-destination pair is ≥ **86,400** (equivalent to 1 connection per second averaged over 24 hours). When a connection is a strobe:
1. **Beacon analysis is skipped** — the connection count is too high for meaningful periodicity scoring (code: `entry.Count < 86400` guard in analysis.go line 230).
2. The connection receives an automatic `StrobeScore` based on the configured `strobe_impact` category (default: `high`).
3. In the CSV output, `Strobe` renders as `true`/`false` (via `strconv.FormatBool(item.StrobeScore > 0)`).

**Implication for our detectors:** A strobe is NOT a beacon — it's a connection that is too chatty to be a beacon (e.g., constant polling, open streaming connections). When `Strobe=true`, the `Beacon Score` is meaningless (set to 0). Our `rita/reader.py` should treat Strobe and Beacon as mutually exclusive detection signals.

### DNS-Infrastructure False Positive (from ps26145_prod)

The `ps26145_prod` dataset (real OT network traffic) shows DNS infrastructure IPs falsely flagged as beacons:

| Severity | Source IP | Destination IP | Beacon Score | Service | Root Cause |
|----------|-----------|---------------|--------------|---------|------------|
| Critical | 172.16.0.79 | 8.8.8.8 | 0.988 | 53:udp:dns | Google Public DNS — periodic DNS resolver queries |
| Critical | 172.16.0.81 | 198.41.0.4 | 0.94 | 53:udp:dns | Root DNS server (a.root-servers.net) |
| Critical | 172.16.0.81 | 199.7.83.42 | 0.94 | 53:udp:dns | Root DNS server (l.root-servers.net) |
| Critical | 172.16.0.81 | 193.0.14.129 | 0.94 | 53:udp:dns | Root DNS server (k.root-servers.net) |
| None | 172.16.0.79 | 1.1.1.1 | 0.442 | 53:udp:dns | Cloudflare DNS |
| None | 172.16.0.79 | 9.9.9.9 | 0.442 | 53:udp:dns | Quad9 DNS |

**Root cause:** Periodic DNS resolution against well-known recursive and root DNS servers produces highly regular connection patterns that RITA correctly identifies as "beacon-like" in terms of timing regularity — but these are normal DNS infrastructure behavior, not C2 beaconing.

**Mitigation:** A known-DNS-infrastructure allowlist will be implemented in `rita/reader.py` (Step 4) to suppress these false positives before they reach the alert pipeline.

---

## Decision 002: RITA Beaconing Validation — COMPLETE

**Date:** 2026-09-16
**Phase:** 6 (RITA Verification — Final)

### Summary

RITA v5.1.2 has been fully validated as the beaconing-analysis component of the PS-26145 prototype. Integration uses Docker, ClickHouse and Zeek-derived connection logs.

### Controlled Synthetic Beacon Results

Two synthetic datasets were evaluated, each containing 60 connections from `172.16.0.100` → `203.0.113.50:8080`:

| Dataset | Jitter | Beacon Score | Severity | Result |
|---------|--------|--------------|----------|--------|
| Fixed-period beacon (60s interval) | 0% | **97.70%** | High | ✅ Detected |
| Jittered beacon (~48–72s interval) | 20% | **91.60%** | High | ✅ Detected |

**Conclusion:** RITA successfully detected both regular and jittered synthetic beacon-like communication.

### DNS Beacon-Like Traffic Observation

A separate test dataset produced a high beacon score for periodic DNS communication:

| Source IP | Destination IP | Beacon Score | Connections | Protocol |
|-----------|---------------|--------------|-------------|----------|
| 172.16.0.79 | 8.8.8.8 | **98.80%** | 60 | DNS/UDP 53 |

This demonstrates that periodic DNS traffic can appear beacon-like and **must be correlated** with DNS-tunnelling / DGA / other detectors before assigning a malicious classification.

### Production Dataset

`ps26145_prod` produced no beacon results in the inspected view (after DNS-infrastructure filtering).

### Final Position

1. **RITA is validated** as the beaconing-analysis component of PS-26145.
2. RITA provides beacon scores and severity information that can be consumed by the project's higher-level detection/correlation layer.
3. **RITA does not by itself establish that a connection is malware or a Trojan.** Beacon scores must be fused with additional evidence (DNS analysis, threat-intel, payload inspection) before a definitive malicious classification is made.

---

## Decision 003: Reconnaissance Detector — Zeek Scan Framework Reuse & Adapter Validation

**Date:** 2026-09-19  
**Phase:** 13 (Scan Adapter)  

### Context & Objective
Implement and validate the reconnaissance detection pipeline adhering strictly to Track A (Reused Components). Scanning detection (port and address scans) is delegated completely to Zeek's built-in Scan framework, with `detectors/scanning/zeek_scan_adapter.py` acting strictly as the integration and schema normalization layer.

### 1. Actual Zeek Version Used
- Exact version recorded: `zeek version 9.0.0` (image: `zeek/zeek:lts`).
- Upstream note: In Zeek 9.0.0, `policy/misc/scan.zeek` is no longer bundled in `/usr/local/zeek/share/zeek/policy/misc/`. The Scan framework script preserved at `zeek_scripts/misc/scan.zeek` within the repository was loaded as `policy/misc/scan.zeek` in the experiment execution environment, where it executed cleanly.

### 2. Actual notice.log Field Format Observed
Zeek Scan emitted JSON notices with the following native fields:
- `ts` (float): Epoch timestamp of detection (e.g. `1789720389.391378`).
- `note` (str): Notice type enum (`"Scan::Port_Scan"`).
- `msg` (str): Human-readable notice message (`"192.168.56.102 scanned at least 15 unique ports of host 192.168.56.254 in 0m0s"`).
- `sub` (str): Sub-category indicator (`"local"`).
- `src` (str): Scanner source IP address (`"192.168.56.102"`).
- `dst` (str): Target destination IP address (`"192.168.56.254"`).
- `actions` (list[str]): Action taken (`["Notice::ACTION_LOG"]`).
- `email_dest` (list): Email recipient list (`[]`).
- `suppress_for` (float): Notice suppression duration (`3600.0`).
- Exact scan count: Native notice does not expose an exact numeric count field; the adapter records `"scan_count unavailable in native notice"` rather than parsing `conn.log`.

### 3. Verification Against recon-002 (16 Destination Ports)
- `Scan::port_scan_threshold = 15.0` was evaluated against `recon-002-targeted-scan.pcap` (16 unique destination ports, 33 packets).
- **Result:** Detected successfully. A `Scan::Port_Scan` notice was emitted at timestamp `1789723972.367182`.

### 4. Threshold Modification
- **Did threshold=15 require modification?** **NO**. Threshold `15.0` detected `recon-002` (16 ports) out of the box without any modification.

### 5. Delegation to Zeek Scan Framework
- Confirmed that detection is 100% delegated to Zeek's Scan framework. `zeek_scan_adapter.py` performs log ingestion, filtering, evidence preservation, and alert transformation. It does NOT independently calculate unique destination port counts or unique destination host counts from `conn.log`.

### 6. Alert Schema & Latency Class
- `docs/04_alert_schema.json` was verified for allowed fields and enums.
- The adapter sets `threat_class = "reconnaissance"`.
- `latency_class` was confirmed in `docs/04_alert_schema.json` with allowed enum `["event_driven", "periodic"]`.
- The adapter explicitly sets `latency_class = "event_driven"` on all emitted reconnaissance alerts.
- All emitted alerts validate against `validate_draft_alert` and the JSON Schema.

---

## Decision 004: Custom FANCI-Inspired DGA Detection Pipeline (Track B)

**Date:** 2026-09-19  
**Phase:** 17 (DGA Domain Detection)  

### Context & Architectural Approach
DGA domain detection is executed under Track B (Custom Implementations). While Zeek LTS provides passive DNS telemetry (`dns.log` captured over UDP 53531), Zeek does not natively provide a production-ready DGA classifier. A project-owned machine-learning detector was designed and trained, inspired by the academic feature foundations of Schüppen et al. (FANCI, USENIX Security 2018). Clean-room DGA generation algorithms from `baderj/domain_generation_algorithms` were used to construct ground-truth datasets without copying FANCI source code or datasets.

### Key Technical Decisions & Provenance
1. **Feature Extraction Architecture:**
   - 6 lexical, statistical, and information-theoretic features: `domain_length`, `shannon_entropy`, `digit_ratio`, `vowel_to_consonant_ratio`, `longest_meaningful_substring`, and `ngram_frequency_distance`.
   - Candidate label extraction isolates the leftmost label for $\ge 3$-level FQDNs (e.g. `vn0xg58vzlubb` from `vn0xg58vzlubb.lab.local`), or the SLD for 2-level domains (`google` from `google.com`).
   - A 72,889-word reference list ($3 \le \text{len} \le 15$) powers `longest_meaningful_substring`.
   - A Laplace-smoothed character bigram model (`ngram_reference.json`) built from a curated 2,561 benign domain corpus provides `ngram_frequency_distance`.

2. **Training & Validation Strategy:**
   - 3 DGA families for training (Banjori, Corebot, Ramdo) + Benign corpus, temporally partitioned into Training (2,842 samples) and Validation (1,219 samples).
   - Random Forest ensemble with 100 estimators, max depth 12, balanced class weights.
   - Decision threshold tuned exclusively on the held-out validation set to maximize $F_1$, yielding $\tau^* = 0.30$ ($F_1 = 1.0000$, Precision = 1.0000, Recall = 1.0000).

3. **Held-Out Unseen Family Evaluation (Necurs):**
   - Necurs (300 samples) was 100% held-out and completely unseen during feature engineering, training, or tuning.
   - Achieved 70.67% zero-day generalization recall (212/300 detected) with no retraining.

4. **Canonical PCAP Validation:**
   - Evaluated on canonical, untouched PCAP captures (`data/raw/dga/dga-001-random.pcap` and `dga-002-irregular.pcap`).
   - `dga-001`: 100 / 100 detected (100.00%).
   - `dga-002`: 73 / 100 detected (73.00%).

5. **Alert Contract Conformance:**
   - Emits alerts with `threat_class = "dga"`, `subtype = "dga_dns"`, and `latency_class = "event_driven"`.
   - `supporting_evidence` includes probability estimate, threshold, all 6 features, calibration status, and DNS telemetry.
   - All emitted alerts pass `alerts/validator.py` and conform strictly to `docs/04_alert_schema.json`.

---

## Decision 005: RITA-Based DNS Tunnelling Detection Pipeline (Track A)

**Date:** 2026-09-19  
**Phase:** 15 (DNS Tunnelling Detection)  

### Context & Architectural Approach
Under Track A (Reused Open-Source Components), detection of DNS tunnelling and Command-and-Control (C2) over DNS is delegated entirely to Active Countermeasures RITA (Real Intelligence Threat Analytics) v5.1.2. The project implements [`detectors/dns/rita_tunnel_adapter.py`](file:///home/jay/sih-26145/detectors/dns/rita_tunnel_adapter.py), which serves as a periodic translation, normalization, and deduplication adapter between RITA's native outputs and the unified DRAFT alert layer.

### Key Technical Decisions & Provenance
1. **RITA v5.1.2 & ClickHouse Backend:**
   - Verified exact running version: `v5.1.2` (`ghcr.io/activecm/rita:latest`, GPL-3.0) backed by `clickhouse/clickhouse-server:24.1.6`.
   - In RITA v5.x, all detections are consolidated into `threat_mixtape` viewed via `rita view --stdout <dataset>`, where DNS tunnelling is indexed by the `C2 Over DNS Score` column and `Subdomains` metric.

2. **No Detection Reimplementation:**
   - The adapter treats RITA's analysis as a black box. No custom subdomain entropy, label length, or TXT record volumetric thresholds were introduced into the adapter code.

3. **Offline Mode & Feed Disablement:**
   - All external threat intelligence feeds and URL updaters in `rita/config.hjson` remain disabled (`threat_intel.online_feeds: []`, `update_check_enabled: false`).
   - All external blacklists are disabled. Detections rely purely on passive network telemetry.

4. **Passive Custom Port Handling (UDP/53531):**
   - The canonical dnscat2 PCAPs (`dns-001` and `dns-002`) execute over UDP port 53531. A lightweight Zeek script ([`scripts/dns_tunnel/dns_53531.zeek`](file:///home/jay/sih-26145/scripts/dns_tunnel/dns_53531.zeek)) registers the DNS analyzer for port 53531 without modifying the underlying PCAPs.

5. **Deduplication State Machine:**
   - Because RITA operates on rolling batch imports, periodic polling queries over ClickHouse re-read ongoing tunnel records.
   - The adapter enforces deterministic deduplication using fingerprint `c2_over_dns_{source}_{destination}_{fqdn}`. Only newly emerged tunnels emit DRAFT alerts; duplicate findings on subsequent cycles are suppressed.

6. **Empirical Findings on Canonical Datasets:**
   - Ingested 91 DNS records from `dns-001` and 55 DNS records from `dns-002` into ClickHouse tables.
   - Native RITA emitted 0 findings in `rita view` for both canonical PCAPs.
   - Per project guidelines, this negative result is recorded honestly. Structural analysis of RITA v5.1.2 revealed three root causes:
     a. `rita/database/tables.go` (lines 1407/1413) hardcodes `WHERE NOT endsWith(tld, '.local')`, filtering out `*.lab.local`.
     b. `default_config.hjson` enforces `c2_score_thresholds.base: 100`, requiring $\ge 100$ queries (both PCAPs contain $< 100$ queries).
     c. `filter_external_to_internal: true` treats 192.168.x.x $\to$ 192.168.x.x traffic as internal-only.
   - Operational thresholds were preserved without artificial overrides.

7. **Alert Contract Conformance:**
   - Emits alerts with `threat_class = "dns_tunnel"`, `subtype = "c2_over_dns"`, and `latency_class = "periodic"`.
   - Sets top-level `model_version = "5.1.2"` and `detector_version = "5.1.2"`.
   - Normalizes severity (`Critical`, `High`, `Medium`, `Low`) and maps `confidence` heuristically from `C2 Over DNS Score`, explicitly documenting non-calibrated status.
   - Emitted alerts validate 100% against [`docs/04_alert_schema.json`](file:///home/jay/sih-26145/docs/04_alert_schema.json).

8. **Attribution Statement:**
   - *"DNS tunnelling detection integrates RITA's DNS analysis; our contribution is output normalization, deduplication, and unified alert handling."*

---

## Decision 006: RITA-Based C2 Beaconing Detection Pipeline (Track A)

**Date:** 2026-09-19  
**Phase:** 14 (C2 Beaconing Detection)  

### Context & Architectural Approach
Under Track A (Reused Open-Source Components), detection of Command-and-Control (C2) periodic connection beaconing is delegated entirely to Active Countermeasures RITA (Real Intelligence Threat Analytics) v5.1.2. The project implements [`detectors/beaconing/rita_adapter.py`](file:///home/jay/sih-26145/detectors/beaconing/rita_adapter.py), which serves as a periodic translation, normalization, and deduplication adapter between RITA's native view outputs and the unified DRAFT alert layer.

### Key Technical Decisions & Provenance
1. **Exact RITA and Zeek Versions:**
   - Verified RITA version: `v5.1.2` (`ghcr.io/activecm/rita:latest`, GPL-3.0) backed by `clickhouse/clickhouse-server:24.1.6`.
   - Verified Zeek version: `zeek version 9.0.0` (`zeek/zeek:lts`).
   - Legacy command `rita show-beacons` is obsolete in v5.x; all findings are queried via `rita view --stdout <dataset>`.
   - Rolling import command verified: `docker compose -f rita/docker-compose.yml run --rm -v <logs>:/logs rita import --database <NAME> --logs /logs --rolling`.

2. **No Detection Reimplementation:**
   - The adapter treats RITA's interval uniformity analysis as a black box. No custom standard deviation, coefficient of variation, entropy, or periodicity scoring was implemented in Python.

3. **Offline Mode Enforcement:**
   - External threat intelligence online feeds remain disabled (`threat_intel.online_feeds: []` in `rita/config.hjson`).
   - Software auto-updates disabled (`update_check_enabled: false`).
   - External blacklists disabled. All detections rely strictly on passive connection telemetry.

4. **Observed Output Format & Score Range:**
   - Native CSV headers: `Severity,Source IP,Destination IP,FQDN,Beacon Score,Strobe,Total Duration,Long Connection Score,Subdomains,C2 Over DNS Score,Threat Intel,Prevalence,First Seen,Missing Host Header,Connection Count,Total Bytes,Port:Proto:Service,Modifiers`.
   - Score range: Floating-point metric in `[0.0, 1.0]`.
   - `Strobe == true` findings represent high-frequency chatty connections ($\ge 86,400$ connections) where beacon analysis is skipped; the adapter explicitly filters out strobe records.
   - Native `rita view` does not output an average interval column; the adapter records `"average_interval": "not reported in native rita view"` rather than fabricating values.

5. **Empirical Threshold Tuning on Lab Traffic:**
   - Fixed beacon (0% jitter, 60s interval): RITA score **`0.977`** (High severity, 60 connections).
   - Jittered beacon (~20% jitter, 60s base): RITA score **`0.916`** (High severity, 60 connections).
   - Benign background web traffic (HTTP/SSL): scores range from `0.23` to **`0.635`** (all Low/None).
   - Selected score threshold: **`0.75`**. This provides a robust safety margin of `+0.115` above peak background noise (`0.635`), while reliably capturing the 20% jittered beacon (`0.916 - 0.75 = 0.166`).

6. **Empirical Findings on Benchmark Datasets:**
   - `ps26145_beacon_fixed`: Detected (Score: `0.977`, 1 alert).
   - `ps26145_beacon_jitter`: Detected (Score: `0.916`, 1 alert).
   - `ps26145_test` (Legitimate Periodic Service): 4 alerts emitted for periodic DNS resolution traffic (Google DNS `8.8.8.8` score `0.988`, root servers score `0.940`). This empirically demonstrates the expected false-positive behavior of pure timing-based beacon detection on periodic network infrastructure services.
   - `ps26145_prod` (Production Baseline): Clean baseline (0 rows in view, 0 alerts).

7. **Deduplication & Material Change State Machine:**
   - Because RITA operates on rolling batch imports, periodic polling queries over ClickHouse will re-read ongoing connections every cycle.
   - The adapter enforces deterministic deduplication using fingerprint `f"beacon_{source}_{destination}_{dest_port}_{service}"`.
   - An alert is emitted on the initial cycle. On subsequent cycles, duplicate alerts are suppressed unless a material change is detected:
     a. Severity escalates (e.g. `medium` $\to$ `high`), OR
     b. Beacon score increases by $\ge 0.15$ (`MATERIAL_CHANGE_SCORE_DELTA`).

8. **Alert Contract Conformance:**
   - Emits alerts with `threat_class = "beaconing"`, `subtype = "c2_beaconing"`, and `latency_class = "periodic"`.
   - Populates `model_version = "5.1.2"` and `detector_version = "5.1.2"`.
   - Maps `confidence` directly from RITA score, explicitly noting non-calibrated heuristic status in `supporting_evidence`.
   - Emitted alerts validate 100% against [`docs/04_alert_schema.json`](file:///home/jay/sih-26145/docs/04_alert_schema.json).

9. **Latency Configuration:**
   - Configured with a 30-second rolling analysis cycle; therefore detection has a periodic-batch latency floor. Sub-second latency is not claimed.

10. **Attribution Statement:**
    - *"C2 beaconing detection integrates RITA's beacon-scoring; our contribution is fusion, OT-asset-criticality scoring, and unified alert handling."*

---

## Decision 007: Custom Encrypted Malware & TLS Metadata Detector Pipeline (Track B)

**Date:** 2026-09-19  
**Phase:** 18 (Encrypted Malware / TLS Metadata Detection)  

### Context & Architectural Approach
Under Track B (Custom Implementations), detection of encrypted malware communication and C2 sessions over TLS is executed without payload decryption or inspection. The project implements [`detectors/tls/detector.py`](file:///home/jay/sih-26145/detectors/tls/detector.py), which extracts TLS handshake metadata from Zeek `ssl.log` and transport-layer flow telemetry from `conn.log`, joining them on the unique Zeek connection identifier (`uid`). The detector fuses static offline JA3/JA3S fingerprint recognition (Signal A) with statistical connection-level behavioral anomaly scoring (Signal B) to emit schema-compliant DRAFT alerts.

### Key Technical Decisions & Provenance
1. **Frozen Pipeline & UID Inner Join:**
   - Zeek `ssl.log` and `conn.log` records are matched strictly on the unique `uid` field using a deterministic first-win joiner ([`detectors/tls/tls_features.py`](file:///home/jay/sih-26145/detectors/tls/tls_features.py)). Unmatched or malformed records without a `uid` are safely discarded.

2. **Zero Payload Decryption Guarantee:**
   - The detector strictly complies with the zero-payload-decryption principle. It operates exclusively on packet counts, byte counts, flow durations, directional volume ratios, and unencrypted TLS handshake headers (ClientHello / ServerHello).
   - In accordance with the project alert schema, alert descriptions explicitly declare `"metadata/behavior-based suspicion"` and record `"payload uninspected (zero payload decryption)"`. Claims of "malware payload detected" or "decrypted malware" are strictly forbidden.

3. **External Open-Source Component Reuse (JA3/JA3S):**
   - Base Zeek 9.0.0 does not compute JA3/JA3S fingerprints by default. Official Salesforce open-source scripts ([`zeek_scripts/tls/ja3.zeek`](file:///home/jay/sih-26145/zeek_scripts/tls/ja3.zeek) and [`zeek_scripts/tls/ja3s.zeek`](file:///home/jay/sih-26145/zeek_scripts/tls/ja3s.zeek)) were integrated into the Zeek pipeline to log `"ja3"` and `"ja3s"` hashes into `ssl.log`.

4. **Signal A: Static Offline JA3/JA3S Fingerprinting:**
   - A curated offline database ([`data/intel/ja3_blacklist.json`](file:///home/jay/sih-26145/data/intel/ja3_blacklist.json)) contains 8 JA3 and 4 JA3S fingerprints spanning Cobalt Strike, TrickBot, Emotet, Meterpreter, Sliver, Tor, and lab implant baselines.
   - All lookups are strictly offline. No external DNS lookups, API queries, or threat intel updates occur during detection. Every hash is validated against `^[0-9a-fA-F]{32}$`.

5. **Signal B: Connection-Level Behavioral Anomaly Scoring:**
   - Evaluates 4 transport-level features: `mean_packet_size`, `byte_ratio` (orig/resp), `packet_count`, and `duration`.
   - Behavioral anomaly score $S_{\text{behavior}} \in [0.0, 1.0]$ combines weighted sigmoid-transformed deviations from calibrated benign baselines ($\mu_{\text{ratio}} = 2.0$, $\mu_{\text{size}} = 450.0$B).
   - Decision threshold is calibrated at $\tau = 0.50$.

6. **Dual-Signal Fusion Matrix:**
   - Resolves fingerprint matches against observed behavior:
     - `both` (FP + Behavior): High severity, confidence 0.90, subtype `encrypted_malware`.
     - `fingerprint_only`: Medium severity, confidence 0.75, subtype `suspicious_fingerprint`.
     - `behavior_only`: Medium severity, confidence 0.65, subtype `tls_behavioral_anomaly`.
     - `none`: No alert emitted.

7. **Empirical Findings on Canonical Datasets:**
   - `enc-001-tls-baseline.pcap` (SHA256: `761752384e910ab...`): Handshake matches lab baseline fingerprint; behavioral score is $0.0002 \ll 0.50$. Fused as `fingerprint_only` (Medium severity, confidence 0.75).
   - `enc-002-tls-c2-medium.pcap` (SHA256: `50bebf07260840a...`): Handshake matches lab baseline fingerprint; behavioral score is $0.5755 > 0.50$ (mean packet size $612.0$B, byte ratio $5.40$). Fused as `both` (High severity, confidence 0.90, `encrypted_malware`).
   - The dual-signal approach successfully separates the benign session from the active C2 session despite identical client/server TLS handshake hashes.

8. **Alert Contract Conformance:**
   - Emits alerts with `threat_class = "tls_anomaly"`, `latency_class = "event_driven"`, and `model_version = "1.0.0"`.
   - Populates supporting evidence with concrete observed flow metrics, zero generic placeholders, and explicit non-calibrated heuristic confidence mapping rationales.
   - All emitted alerts pass `alerts/validator.py` and conform 100% to [`docs/04_alert_schema.json`](file:///home/jay/sih-26145/docs/04_alert_schema.json).

9. **Attribution Statement:**
   - *"The JA3/JA3S fingerprinting scripts are external open-source components from Salesforce; our contribution is offline snapshot lookup, TLS metadata feature extraction, behavioral anomaly scoring, dual-signal fusion, and unified DRAFT alert handling."*

---

## Decision 008: Custom Data Exfiltration Detector Pipeline (Track B)

**Date:** 2026-09-19  
**Phase:** 19 (Data Exfiltration Detection)  

### Context & Architectural Approach
Under Track B (Custom Implementations), detection of potential unauthorized data egress is executed without payload inspection or decryption. The project implements [`detectors/exfiltration/detector.py`](file:///home/jay/sih-26145/detectors/exfiltration/detector.py), which aggregates passive Zeek `conn.log` flow records into configurable time windows per `(internal_source, external_destination)` pair. The detector evaluates directional payload byte asymmetry ($\text{byte\_ratio} = \text{outbound\_bytes} / \max(\text{inbound\_bytes}, 1)$) against an absolute volume floor and a rolling per-host benign baseline to emit schema-compliant DRAFT alerts.

### Key Technical Decisions & Provenance
1. **Direction Semantics & Payload Accounting:**
   - Zeek defines `orig_bytes` as payload bytes sent by the originator (`id.orig_h`) and `resp_bytes` as payload bytes sent by the responder (`id.resp_h`).
   - The detector defines source host as `id.orig_h` and destination as `id.resp_h`. Directional byte accumulation uses:
     - $\text{outbound\_bytes} = \sum \text{orig\_bytes}$
     - $\text{inbound\_bytes} = \sum \text{resp\_bytes}$
   - Header overhead bytes (`orig_ip_bytes` / `resp_ip_bytes`) are explicitly excluded. Missing payload byte fields are safely defaulted to 0.

2. **Network Classification & Directional Contract:**
   - [`detectors/exfiltration/network.py`](file:///home/jay/sih-26145/detectors/exfiltration/network.py) classifies IP addresses using configurable CIDR subnets. By default, RFC 1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`), link-local (`169.254.0.0/16`), and the lab subnet (`192.168.56.0/24`) are classified as internal.
   - The detector strictly evaluates **internal source $\to$ external destination**.
   - Internal-to-internal flows (e.g. lab iperf3 transfers between `192.168.56.102` and `192.168.56.254`) and external-to-internal inbound downloads are excluded by design.

3. **Flow Window Aggregation:**
   - Flow windowing is implemented via `ExfilFlowWindow` and `build_exfil_windows()` in [`features/flow_stats.py`](file:///home/jay/sih-26145/features/flow_stats.py).
   - Operates over configurable 60.0-second time windows (`window_seconds = 60.0`) grouped by `(window_id, source_ip, destination_ip)`.

4. **Empirical Calibration of Ratio Threshold & Volume Floor:**
   - Analysis of 138 external connection records from lab baseline traffic (`data/zeek_logs/conn.log`) revealed an average outbound payload volume of 319.5 bytes, with a peak of 2,976 bytes. Routine DNS queries frequently have 0 response bytes, producing high formal ratios on tiny payloads ($< 300$ bytes).
   - **Volume Floor:** Calibrated at **`50,000 bytes` (50 KB)**, providing a $16\times$ safety margin above benign external noise and completely suppressing small request false positives.
   - **Ratio Threshold:** Calibrated at **`10.0:1`**.

5. **Rolling Per-Host Benign Baseline & Deviation Tracking:**
   - [`detectors/exfiltration/baseline.py`](file:///home/jay/sih-26145/detectors/exfiltration/baseline.py) tracks historical byte-ratio and volume distributions per source host.
   - Requires a minimum of 3 clean baseline observations. If insufficient data exists, the detector records `insufficient_baseline_data = true` and `baseline_deviation = 0.0`.
   - When established, computes normalized Z-score deviation: $\text{baseline\_deviation} = (\text{ratio} - \mu) / \max(\sigma, 0.05)$.

6. **Controlled Lab Validation Experiments:**
   - In accordance with dataset frozen rules, no canonical PCAPs were modified. Controlled lab experiments were generated:
     - `exfil_upload.pcap`: Internal host `192.168.56.102` $\to$ External `203.0.113.195` (500 KB upload, 0 B download, ratio 500,000:1) $\implies$ **Alert Emitted** (Critical severity, confidence 0.95).
     - `inbound_download.pcap`: Internal `192.168.56.102` downloading 1.5 MB from external `198.51.100.80` (ratio 0.00077:1) $\implies$ **0 Alerts** (Negative test passed).
     - `benign-002-iperf3-tcp.pcap`: Internal-to-internal 141 MB transfer $\implies$ **0 Alerts** (Internal target ignored).
     - `conn.log` baseline: 75 windows $\implies$ **0 Alerts** (Clean baseline).

7. **Alert Contract Conformance:**
   - Emits alerts with `threat_class = "exfiltration"`, `latency_class = "periodic"`, and `model_version = "1.0.0"`.
   - Alert descriptions strictly declare: *"Outbound traffic exhibits an unusually high byte asymmetry relative to the host baseline."* (zero claims of stolen data or payload inspection).
   - All emitted alerts pass `alerts/validator.py` and conform 100% to [`docs/04_alert_schema.json`](file:///home/jay/sih-26145/docs/04_alert_schema.json).

8. **Destination Rarity Decision:**
   - Evaluated and preserved as an optional supporting evidence field rather than a mandatory detection gate, preventing evasion via compromised common cloud services (e.g. S3/GitHub).

---

## Decision 009: Shared Feature Engineering Architecture (Flow, DNS, TLS)

**Date:** 2026-09-19  
**Phase:** 20 (Shared Feature Engineering Layer)  

### Context & Architectural Approach
A unified, decoupled feature-engineering layer is established across three core modules:
1. [`features/flow_stats.py`](file:///home/jay/sih-26145/features/flow_stats.py): Streaming 5.0-second tumbling-window aggregation, directional flow rates, and source-IP Shannon entropy.
2. [`features/dns_features.py`](file:///home/jay/sih-26145/features/dns_features.py): Per-query lexical, statistical, and local n-gram frequency distance extraction.
3. [`features/tls_features.py`](file:///home/jay/sih-26145/features/tls_features.py): Deterministic `ssl.log` + `conn.log` UID inner join and metadata-only flow behavioral features.

### Strict Architectural Boundaries & Guarantees
1. **Separation of Concerns (No Detection Logic in Features):**
   - Feature engineering modules strictly compute features; detectors perform threat classification, threshold comparisons, and alert generation.
   - Zero detector thresholds, zero alert schemas, and zero threat classification logic reside inside `features/`.

2. **5.0-Second Tumbling Windows (`features/flow_stats.py`):**
   - Windows are strictly non-overlapping and non-sliding: $\text{window\_start} = \lfloor \text{ts} / 5.0 \rfloor \times 5.0$, with $\text{window\_end} = \text{window\_start} + 5.0$.
   - Boundary condition: A record timestamped at $t = 4.999\text{s}$ falls into window $[0.0, 5.0)$, whereas $t = 5.000\text{s}$ and $t = 5.001\text{s}$ fall strictly into window $[5.0, 10.0)$.
   - Boundary-crossing safety: The streaming aggregator (`FlowWindowAggregator`) emits and finalizes the prior window upon encountering a boundary-crossing record, immediately ingesting the crossing event into the newly opened window without event loss.

3. **Directional Flow & Header Overhead Accounting:**
   - Flow metrics differentiate between application payload bytes (`orig_bytes` + `resp_bytes`) and total layer-3 IP bytes (`orig_ip_bytes` + `resp_ip_bytes`).
   - Source-IP Shannon entropy is computed incrementally per window:
     $$H(S) = -\sum_{i=1}^k \frac{c_i}{N} \log_2 \left(\frac{c_i}{N}\right)$$
     where $c_i$ is the count of packets/flows from source $i$ and $N = \sum c_i$.

4. **Per-Query DNS Feature Processing (`features/dns_features.py`):**
   - DNS activity is discrete request-response telemetry and is processed on a per-query basis rather than via temporal flow windows.
   - Queries are canonicalized via `normalize_domain_name()` (case-folding, whitespace trimming, trailing-dot removal).
   - Extracts 6 lexical, statistical, and information-theoretic features (`domain_length`, `shannon_entropy`, `digit_ratio`, `vowel_to_consonant_ratio`, `longest_meaningful_substring`, and `ngram_frequency_distance`) without cross-query state leakage.

5. **Deterministic TLS UID Inner Join (`features/tls_features.py`):**
   - Joins `ssl.log` records with `conn.log` records strictly on `ssl.uid == conn.uid`.
   - Unmatched UIDs are discarded; no fake records or synthetic placeholders are ever fabricated.
   - Duplicate UIDs are resolved deterministically on a first-seen basis.
   - Computes transport behavioral metrics (`mean_packet_size`, `byte_ratio`, `packet_count`, `duration`) with zero-division protection ($\epsilon = 10^{-6}$).

6. **Zero Payload Decryption & Zero Payload Inspection:**
   - All feature extractors operate strictly on unencrypted metadata, connection headers, and volumetric counters. No TLS decryption or deep packet inspection is performed.

7. **Backward Compatibility:**
   - Pre-existing detector interfaces (`build_flow_windows`, `FlowWindow`, `ExfilFlowWindow`, `build_exfil_windows`, `DGAFeatureExtractor`, `extract_features`, `extract_features_from_files`) remain 100% functional, verified across the 167-test suite with zero regressions.

---

## Decision 010: Unified Alert Layer & Fail-Closed Validation Architecture (Phase 10)

**Date:** 2026-09-19  
**Phase:** 10 (Unified Alert Layer)  

### Context & Architectural Approach
The `alerts/` package is established as the single mandatory, fail-closed validation chokepoint through which every detector (across Track A and Track B) must pass before an alert can reach downstream fusion (`fusion/`) or persistent storage:
1. [`alerts/constants.py`](file:///home/jay/sih-26145/alerts/constants.py): Authoritative constants (`SCHEMA_VERSION = "1.0.0"`, `ThreatClass`, `Severity`, `LatencyClass`) matching [`docs/04_alert_schema.json`](file:///home/jay/sih-26145/docs/04_alert_schema.json).
2. [`alerts/validator.py`](file:///home/jay/sih-26145/alerts/validator.py): Schema and semantic validator powered directly by `jsonschema.Draft7Validator` on the authoritative schema file.
3. [`alerts/draft.py`](file:///home/jay/sih-26145/alerts/draft.py): Standardized factory (`create_draft_alert()`) and dataclass (`DraftAlert`) enforcing schema compliance and automatic field population.

### Key Technical Decisions & Provenance
1. **Single Mandatory Chokepoint & No Direct Storage Writes:**
   - No detector is permitted to construct raw alert dictionaries independently, write directly to SQLite, write directly to Streamlit, or bypass `alerts/`.
   - All 7 detectors (`ddos`, `scanning`, `dga`, `dns`, `beaconing`, `tls`, `exfiltration`) invoke `create_draft_alert()`.

2. **Authoritative JSON Schema Usage (No Duplication):**
   - The validator loads [`docs/04_alert_schema.json`](file:///home/jay/sih-26145/docs/04_alert_schema.json) directly. The schema definition is never duplicated in Python code.
   - Any schema modifications in `04_alert_schema.json` immediately take effect in validation tests.

3. **Fail-Closed Validation Contract (`AlertValidationError`):**
   - When an alert fails schema validation or semantic checks, the validator logs the failure (recording detector name and threat class, with zero raw packet/payload logging) and raises `AlertValidationError`.
   - Invalid alerts are never silently repaired, never given synthetic defaults, and never passed downstream to `fusion/`.

4. **Strict Identity, Timestamp, and Evidence Constraints:**
   - **UUIDv4 Alert IDs:** Every draft alert receives a globally unique UUIDv4 string (`alert_id`) generated via Python's standard `uuid.uuid4()`.
   - **Timezone-Aware UTC ISO-8601 Timestamps:** Timestamps are auto-generated as timezone-aware UTC ISO-8601 strings (`+00:00`). Naive timestamps and non-UTC offsets are strictly rejected.
   - **Confidence Constraints:** Confidence must be a finite numeric float or int in $[0.0, 1.0]$. `NaN`, `Infinity`, and booleans are explicitly rejected.
   - **Non-Empty Evidence:** `supporting_evidence` must be a non-empty object (`minProperties: 1`). Empty dictionaries are rejected.

5. **Track A and Track B Convergence:**
   - Track A reused components (RITA Beaconing, RITA DNS Tunnelling, Zeek Scan Framework) and Track B custom components (DDoS, DGA, TLS, Exfiltration) converge on the identical DRAFT alert contract.
   - Detector-specific evidence is fully preserved within `supporting_evidence` while outer envelope fields remain strictly normalized.

6. **Full Verification:**
   - Verified via 26 dedicated alert unit tests covering all 20 required scenarios in Section 19 of the specification.
   - Full regression test suite passed with 182 / 182 tests clean and zero failures.

---

## Decision 011: OT-Aware Alert Fusion Architecture (Phase 21)

**Date:** 2026-09-19  
**Phase:** 21 (OT-Aware Alert Fusion)  

### Context & Architectural Approach
The `fusion/` package converts individually-valid DRAFT alerts from all detection mechanisms into correlated, OT-aware, deterministically severity-scored final alerts:
1. [`fusion/validator.py`](file:///home/jay/sih-26145/fusion/validator.py): Defense-in-depth ingress and egress validation against [`docs/04_alert_schema.json`](file:///home/jay/sih-26145/docs/04_alert_schema.json).
2. [`fusion/correlator.py`](file:///home/jay/sih-26145/fusion/correlator.py): Source-based multi-threat correlation over a configurable temporal window.
3. [`fusion/criticality.py`](file:///home/jay/sih-26145/fusion/criticality.py): Asset inventory lookup against [`config/assets.yaml`](file:///home/jay/sih-26145/config/assets.yaml) with deterministic precedence.
4. [`fusion/severity.py`](file:///home/jay/sih-26145/fusion/severity.py): Deterministic, explainable severity escalation engine.
5. [`fusion/engine.py`](file:///home/jay/sih-26145/fusion/engine.py): Pipeline orchestrator returning final schema-validated alerts.

### Key Technical Decisions & Provenance
1. **Confidence is NOT Severity (Strict Preservation):**
   - Detector confidence represents statistical / algorithmic certainty of detection; operational severity represents situational impact.
   - Fusion strictly preserves detector confidence bit-for-bit ($C_{\text{final}} \equiv C_{\text{detector}}$). Confidence is never increased, decreased, averaged, or overwritten by severity escalation.

2. **Multi-Threat Correlation Condition:**
   - Correlation requires:
     a. Same source IP (`alert["source"]`)
     b. Timestamps within configurable correlation window (default: 300.0s / 5 minutes)
     c. At least **two distinct `threat_class` values**
   - Repeated alerts of the same threat class (e.g. `dga` + `dga`) do NOT form a multi-threat correlation group.
   - Distinct sources do not correlate even if simultaneous.

3. **Correlation ID & Group Representation:**
   - Every alert participating in a multi-threat correlation group receives the identical UUIDv4 `correlation_id`.
   - Each group alert populates `correlated_alert_ids` referencing co-occurring alert IDs.
   - Non-correlated alerts remain individual (no `correlation_id`, no correlation escalation).

4. **Asset Inventory Nature & Precedence:**
   - [`config/assets.yaml`](file:///home/jay/sih-26145/config/assets.yaml) is explicitly maintained as a **LAB / DEMONSTRATION ASSET INVENTORY** for testing and prototype evaluation, not production data.
   - Both `source` and `destination` are checked:
     - If either is `critical` $\implies$ `critical`
     - Else if either is `standard` $\implies$ `standard`
     - Else $\implies$ `unknown`
   - Unknown assets are fully valid; missing IPs never cause alert rejection. Criticality is never guessed from IP prefixes.

5. **Deterministic Severity Escalation (Zero Black-Box AI):**
   - Base severity derived deterministically from threat class:
     - `reconnaissance`, `scanning` $\to$ `low`
     - `beaconing`, `dga`, `dga_dns`, `tls_anomaly` $\to$ `medium`
     - `ddos`, `dns_tunnel`, `exfiltration` $\to$ `high`
   - Escalation order:
     1. `base_severity`
     2. $+1$ step if `asset_criticality == "critical"`
     3. $+1$ step if multi-threat correlated ($\ge 2$ distinct threat classes)
     - Ceiling: `critical`.
   - Explanations are recorded in `supporting_evidence["fusion_metadata"]`. No opaque neural nets or weighted risk scores.

6. **Track A and Track B Equivalence:**
   - Reused Track A components (RITA, Zeek Scan) and custom Track B components (DDoS, DGA, TLS, Exfiltration) follow the exact same pipeline without special-casing.

7. **Backend Only & Zero Direct Storage:**
   - Fusion performs no SQLite or Streamlit writes. It outputs clean, schema-validated final alert dictionaries.

8. **Full Verification:**
   - 14 dedicated unit tests in `tests/unit/test_fusion.py` passed 100%. Full regression suite: 196 / 196 passed.

---

## Decision 012: Persistent Alert Storage and Streamlit OT Cyber Threat Dashboard (Phases 22 & 23)

**Date:** 2026-09-19  
**Phase:** 22 (Storage) & 23 (Visualization)  

### Context & Objective
Provide persistent local storage for fused, schema-valid alerts and build an operator-grade Streamlit web console for OT cyber threat monitoring.

### Key Architectural Decisions
1. **Local-First SQLite Storage (`storage/sqlite_store.py`):**
   - SQLite with WAL mode (`PRAGMA journal_mode=WAL`) and `PRAGMA synchronous=NORMAL` to support concurrent readers and writers.
   - Strictly parameterized queries prevent SQL injection across all query paths.
   - Comprehensive indexing: `timestamp`, `threat_class`, `severity`, `source`, `destination`, and `correlation_id`.
   - Lossless alert persistence: stores parsed column metadata for high-speed indexing plus complete JSON `raw_alert` for bit-for-bit forensic fidelity.
   - Upsert semantics (`ON CONFLICT(alert_id) DO UPDATE`) prevent duplicate primary keys while allowing idempotent reprocessing.

2. **Strict SOC Visual Hierarchy & Color Palette (`dashboard/styles.py`):**
   - Strictly restricted palette: SOC Blue (`#1E3A8A`, `#2563EB`), Warning/Accent Amber (`#D97706`), White (`#FFFFFF`), Slate/Neutral backgrounds (`#F8FAFC`, `#E2E8F0`, `#0F172A`).
   - Restrained Dark Red (`#991B1B`) permitted strictly for `critical` severity badges.
   - Zero decorative AI clutter: no GIFs, no CSS animations, no emojis, no glowing neon borders, no marketing buzzwords ("AI-Powered", "Next Gen").

3. **Presentation-Only Architecture (`dashboard/app.py` & `dashboard/components.py`):**
   - Pure presentation layer: consumes fused alerts from SQLite (`data/alerts.db`). Zero threat detection or score recalculation logic in the dashboard.
   - Graceful offline & empty states: cleanly handles missing database ("Alert database unavailable") and empty database ("No alerts recorded yet") without crashing.
   - Read-through caching with short TTL (`@st.cache_data(ttl=3)`) provides responsive interaction with near-real-time updates.

4. **Multi-Stage Attack Chain & Forensic Drilldown:**
   - Multi-stage incidents grouped by `correlation_id` display text-based progression chains (e.g. `reconnaissance → beaconing → exfiltration`).
   - Forensic detail inspector provides tabular display of deterministic measurements in `supporting_evidence` without raw dictionary dumps.
   - Monitored OT asset exposure overview correlates active alerts against `config/assets.yaml`.

5. **Verification & Regression:**
   - 8 unit tests in `tests/unit/test_storage.py` and 7 tests in `tests/ui/test_dashboard_queries.py` (including full Streamlit `AppTest` headless verification).
   - 100% full regression pass across all 211 tests in the repository.
