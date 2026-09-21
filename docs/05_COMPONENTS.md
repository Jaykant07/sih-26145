# Reused Component Inventory

This document tracks all external, open-source components reused under Track A of SIH Problem Statement PS-26145. In accordance with architectural principles, detection logic is preserved from upstream engines, while project-owned adapters handle data ingestion, normalisation, deduplication, and DRAFT alert emission.

---

## 1. Zeek Network Security Monitor

- **Component:** Zeek (LTS)
- **Exact Version:** `zeek version 9.0.0`
- **Container Image:** `zeek/zeek:lts`
- **Upstream License:** BSD-3-Clause
- **Track A Roles:**
  1. **Primary Network Telemetry Engine:** Ingests raw PCAP / passive network traffic and generates structured transaction logs (`conn.log`, `dns.log`, `notice.log`).
  2. **Reconnaissance / Scan Detector:** Reuses Zeek's native Scan framework (`policy/misc/scan.zeek`) for port scan (`Scan::Port_Scan`) and address scan (`Scan::Address_Scan`) detection.
- **Adapter Implementation:**
  - File: [`detectors/scanning/zeek_scan_adapter.py`](file:///home/jay/sih-26145/detectors/scanning/zeek_scan_adapter.py)
  - Mode: Streaming / Event-driven (`latency_class = "event_driven"`)
  - Alerts Emitted: `threat_class = "reconnaissance"`, `subtype = "port_scan" | "address_scan"`
- **Attribution Statement:**
  > *"Recon/scan detection uses Zeek's built-in Scan framework, reformatted into our unified alert schema."*

---

## 2. Active Countermeasures RITA (Real Intelligence Threat Analytics)

- **Component:** RITA
- **Exact Version:** `v5.1.2`
- **Container Image:** `ghcr.io/activecm/rita:latest`
- **Upstream License:** GPL-3.0
- **Underlying Storage:** `clickhouse/clickhouse-server:24.1.6`
- **Compose Stack:** [`rita/docker-compose.yml`](file:///home/jay/sih-26145/rita/docker-compose.yml)
- **Configuration File:** [`rita/config.hjson`](file:///home/jay/sih-26145/rita/config.hjson)
- **Track A Roles:**
  1. **Beaconing Detection:** Periodic connection detection based on time-delta uniformity and connection scoring.
  2. **DNS Tunnelling & C2 Over DNS Detection:** Statistical analysis of subdomain cardinality, query entropy, and persistence.
- **Configuration Constraints (Offline Mode):**
  - `threat_intel.online_feeds: []` (External threat feeds disabled)
  - `threat_intel.custom_feeds: []`
  - `update_check_enabled: false` (No outbound telemetry / update checks)
  - Static blacklists: Disabled
- **Adapter Implementations:**
  - **DNS Tunnelling Adapter:**
    - File: [`detectors/dns/rita_tunnel_adapter.py`](file:///home/jay/sih-26145/detectors/dns/rita_tunnel_adapter.py)
    - Mode: Periodic polling (`latency_class = "periodic"`)
    - Native Output Source: `rita view --stdout <dataset>` (`C2 Over DNS Score`, `Subdomains`)
    - Deduplication: State machine tracking `c2_over_dns_{source}_{destination}_{fqdn}` across cycles
    - Alerts Emitted: `threat_class = "dns_tunnel"`, `subtype = "c2_over_dns"`
  - **Beaconing Adapter:**
    - File: [`detectors/beaconing/rita_adapter.py`](file:///home/jay/sih-26145/detectors/beaconing/rita_adapter.py)
    - Mode: Periodic polling (`latency_class = "periodic"`)
    - Native Output Source: `rita view --stdout <dataset>` (`Beacon Score`, `Severity`, `Connection Count`, `Port:Proto:Service`)
    - Score Threshold: `0.75` (tuned against lab replay traffic: fixed 0.977, jitter 0.916, background <= 0.635)
    - Deduplication: State machine tracking `beacon_{source}_{destination}_{dest_port}_{service}` and material changes (severity escalation or score delta >= 0.15)
    - Alerts Emitted: `threat_class = "beaconing"`, `subtype = "c2_beaconing"`
- **Attribution Statements:**
  - *DNS Tunnelling:* "DNS tunnelling detection integrates RITA's DNS analysis; our contribution is output normalization, deduplication, and unified alert handling."
  - *C2 Beaconing:* "C2 beaconing detection integrates RITA's beacon-scoring; our contribution is fusion, OT-asset-criticality scoring, and unified alert handling."

---

## 3. Salesforce JA3 / JA3S Zeek Scripts (TLS Fingerprint Generation)

- **Component:** JA3 & JA3S Zeek scripts (Salesforce open source)
- **Upstream License:** BSD-3-Clause
- **Local Script Paths:**
  - [`zeek_scripts/tls/ja3.zeek`](file:///home/jay/sih-26145/zeek_scripts/tls/ja3.zeek)
  - [`zeek_scripts/tls/ja3s.zeek`](file:///home/jay/sih-26145/zeek_scripts/tls/ja3s.zeek)
- **Role in Pipeline:**
  - Extends Zeek's `SSL::Info` record to calculate and log MD5 hashes for TLS ClientHello (`ja3`) and ServerHello (`ja3s`) handshakes directly into `ssl.log`.
- **Custom Project Contributions (Track B):**
  - **Offline Blacklist:** Curated static database ([`data/intel/ja3_blacklist.json`](file:///home/jay/sih-26145/data/intel/ja3_blacklist.json)) with MD5 syntax validation and zero runtime external network dependencies ([`detectors/tls/blacklist.py`](file:///home/jay/sih-26145/detectors/tls/blacklist.py)).
  - **UID Inner Join & Feature Extraction:** Extracts TLS metadata and connection-level counters (`mean_packet_size`, `byte_ratio`, `packet_count`, `duration`) matched on Zeek `uid` ([`detectors/tls/tls_features.py`](file:///home/jay/sih-26145/detectors/tls/tls_features.py)).
  - **Behavioral Scoring:** Statistical anomaly model evaluating directional transfer asymmetry and packet size deviations ([`detectors/tls/behavior.py`](file:///home/jay/sih-26145/detectors/tls/behavior.py)).
  - **Dual-Signal Fusion Engine:** Fuses static fingerprint recognition with dynamic connection behavior to qualify alerts into `encrypted_malware`, `suspicious_fingerprint`, or `tls_behavioral_anomaly` ([`detectors/tls/detector.py`](file:///home/jay/sih-26145/detectors/tls/detector.py)).
  - **Zero Payload Decryption Guarantee:** All operations run purely on unencrypted handshake headers and transport-layer flow counters.
- **Alert Contract:**
  - `threat_class = "tls_anomaly"`
  - `latency_class = "event_driven"`
  - `model_version = "1.0.0"`
- **Attribution Statement:**
  > *"The JA3/JA3S fingerprinting scripts are external open-source components from Salesforce; our contribution is offline snapshot lookup, TLS metadata feature extraction, behavioral anomaly scoring, dual-signal fusion, and unified DRAFT alert handling."*

---

## 4. Custom Data Exfiltration Detector (Track B)

- **Component:** Data Exfiltration Detector
- **Implementation File:** [`detectors/exfiltration/detector.py`](file:///home/jay/sih-26145/detectors/exfiltration/detector.py)
- **Role in Pipeline:**
  - Evaluates passive Zeek connection logs (`conn.log`) for directional byte asymmetry and absolute outbound volume thresholds on internal source $\to$ external destination flows.
- **Custom Project Contributions (Track B):**
  - **Network Classification:** Configurable CIDR classifier ([`detectors/exfiltration/network.py`](file:///home/jay/sih-26145/detectors/exfiltration/network.py)) to cleanly differentiate internal networks (RFC 1918, `192.168.56.0/24`) from external destinations. Excludes internal-to-internal transfers (e.g. iperf3) and inbound downloads.
  - **Windowed Flow Aggregation:** Extends [`features/flow_stats.py`](file:///home/jay/sih-26145/features/flow_stats.py) with `ExfilFlowWindow` and `build_exfil_windows()` over configurable 60.0-second time windows.
  - **Directional Byte Accounting:** Accumulates payload bytes sent by originator (`orig_bytes` outbound) and responder (`resp_bytes` inbound), strictly avoiding layer-3/4 header metrics.
  - **Rolling Per-Host Benign Baseline:** Tracks historical byte-ratio and volume distributions per source host ([`detectors/exfiltration/baseline.py`](file:///home/jay/sih-26145/detectors/exfiltration/baseline.py)), calculating normalized Z-score `baseline_deviation`.
  - **Dual-Threshold Decision Gate:** Emits DRAFT alerts only when $\text{byte\_ratio} > 10.0$ **AND** $\text{outbound\_bytes} \ge 50,000$ bytes (50 KB).
  - **Zero Payload Inspection Guarantee:** Operates strictly on passive flow counters and connection timing.
- **Alert Contract:**
  - `threat_class = "exfiltration"`
  - `latency_class = "periodic"`
  - `model_version = "1.0.0"`
  - `subtype = "asymmetric_outbound_transfer"`




