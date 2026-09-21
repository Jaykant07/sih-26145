# PS-26145 — MASTER EXECUTION PLAN
## AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
### FINAL | Start-to-End | 7-Day Plan | Antigravity Agent Ready

**Status:** FINAL EXECUTION BASELINE  
**Target:** Working, demonstrable, measurable, local-first prototype  
**Environment:** Ubuntu VM + Antigravity Agent IDE  
**Team assumption:** 6 people  
**Timeline:** 7 days

---

# 1. PURPOSE AND RULES

This is the single source of execution guidance for the prototype. It combines the finalized architecture, requirements, detector decisions, seven-day schedule, SIH-oriented checklist, testing strategy, risks, and agent instructions.

## Priority when documents conflict

1. Official PS-26145 and official SIH submission rules.
2. Hard safety/problem constraints.
3. This master plan.
4. Other repository documentation.
5. Agent assumptions.

**Never silently invent missing requirements.**

## Definition of completion

A task is complete only when:

```text
IMPLEMENTED
+ EXECUTED
+ TESTED
+ EVIDENCE CAPTURED
+ EXIT GATE PASSED
```

Code existing is not completion.

---

# 2. PROJECT MISSION

Build a passive, local-first cyber-threat detection system for read-only/unidirectional IP traffic.

The prototype must:

1. Analyze controlled lab traffic or recorded PCAP replay.
2. Use Zeek for passive network telemetry.
3. Process telemetry incrementally.
4. Detect seven finalized threat categories.
5. Reuse verified open-source components where appropriate.
6. Build the selected custom detectors.
7. Normalize all outputs into one alert contract.
8. Apply OT-aware correlation and asset criticality.
9. Store final alerts locally.
10. Display real alerts on a dashboard.
11. Provide supporting evidence.
12. Perform no active response.
13. Measure throughput and latency.

---

# 3. HARD CONSTRAINTS

## C1 — Passive / read-only

Never:

- block traffic;
- inject packets;
- reset connections;
- modify firewall rules;
- trigger mitigation scripts;
- perform BGP blackholing;
- probe monitored hosts;
- create a return/control path.

This project is:

```text
DETECT → SCORE → ALERT → DISPLAY
```

Not:

```text
DETECT → BLOCK / MITIGATE
```

## C2 — No payload decryption

TLS/encrypted traffic may use:

- metadata;
- verified fingerprints;
- duration;
- bytes;
- timing;
- behavioral anomalies.

Never claim payload decryption.

Correct claim:

> Suspicious encrypted-session behavior is detected using available metadata and flow behavior.

## C3 — Incremental processing

Custom pipeline:

```text
Zeek record appended
→ ingest
→ detector
→ DRAFT alert
→ fusion
→ SQLite
→ dashboard
```

Do not wait for the entire PCAP and call that real-time.

RITA may operate periodically/rolling; measure it separately.

## C4 — Local-first

Core processing and alert storage remain local.

## C5 — Explainability

Every alert requires `supporting_evidence`.

## C6 — Honest open-source use

Record:

- exact version;
- license;
- source;
- purpose;
- integration point;
- acknowledgement.

Do not claim third-party tools as original work.

---

# 4. FINAL ARCHITECTURE

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

---

# 5. FINAL DETECTOR DECISIONS

| Threat | Decision | Implementation |
|---|---|---|
| Volumetric DDoS | CUSTOM | Explainable flow/window detector |
| C2 Beaconing | REUSE | RITA + adapter |
| DGA | CUSTOM | FANCI-inspired feature classifier |
| DNS Tunnelling | REUSE | RITA + adapter |
| Encrypted Malware/Suspicious TLS | CUSTOM | Metadata/fingerprint/behavior |
| Recon/Port Scan | REUSE | Zeek Scan + adapter |
| Data Exfiltration | CUSTOM | Byte-ratio/behavior detector |

**Do not change these decisions silently.**

---

# 6. REUSED COMPONENTS

## 6.1 Zeek

Purpose: passive telemetry.

Expected logs:

```text
conn.log
dns.log
ssl.log
notice.log
```

Actual availability depends on the Zeek version, loaded scripts, and traffic. Verify real fields before coding.

JSON logging must be verified against the installed Zeek release.

## 6.2 Zeek Scan

Use:

```text
policy/misc/scan.zeek
```

The project path is:

```text
notice.log
→ zeek_scan_adapter.py
→ DRAFT alert
```

Do not rebuild scan fan-out logic if Zeek Scan works.

## 6.3 RITA

Preferred for:

- beaconing;
- DNS tunnelling.

Before adapter coding, record:

```text
Exact version
License
Repository
Ubuntu compatibility
Installation method
Input format
Actual output format
Commands tested
Rolling behavior
```

Do not use legacy RITA commands without verifying the exact installed release.

---

# 7. RITA CONTINGENCY

RITA is the biggest schedule risk.

## Day-1 hard timebox

```text
4 focused hours maximum
```

Success:

- beaconing output verified;
- DNS tunnelling output verified.

If successful: continue with RITA.

If not successful:

1. Stop consuming unlimited time.
2. Record exact version/environment/error.
3. Record the 4-hour timebox.
4. Activate the previously approved custom periodic fallback only after documenting the decision.

The fallback must remain:

- passive;
- local;
- explainable;
- compatible with the same architecture.

Do not switch casually.

---

# 8. CUSTOM DETECTORS

## 8.1 DDoS

Start with deterministic sliding-window logic.

Use only verified fields.

Possible signals:

- connection rate;
- byte/packet rate where available;
- source diversity;
- destination concentration;
- baseline deviation.

Evidence:

```text
window_size
observed_rate
baseline_rate
source_count
destination
threshold/deviation
```

No deep learning unless it provides measurable benefit.

## 8.2 DGA

Inspired by:

> Schüppen et al., FANCI: Feature-based Automated NXDomain Classification and Intelligence, USENIX Security 2018.

Do not claim FANCI code/model/dataset as ours.

Start with:

- domain length;
- Shannon entropy;
- digit ratio;
- vowel/consonant ratio;
- meaningful-substring feature;
- n-gram distance.

Baseline model:

```text
Random Forest
```

Required:

- train/test split;
- precision;
- recall;
- F1;
- confusion matrix;
- model versioning.

## 8.3 TLS

Use only verified data:

- TLS metadata;
- verified fingerprints if available;
- duration;
- bytes;
- timing;
- rarity/baseline.

Never claim decrypted malware detection.

## 8.4 Exfiltration

Use:

- outbound bytes;
- inbound bytes;
- outbound/inbound ratio;
- duration;
- volume;
- baseline deviation.

Evidence should expose measured values.

---

# 9. ALERT CONTRACT

Every detector emits a standardized **DRAFT alert**.

Required:

```text
alert_id
timestamp
flow_id
threat_class
severity
confidence
source
destination
supporting_evidence
detector
model_version
schema_version
```

Optional:

```text
subtype
asset_criticality
correlated_alert_ids
latency_class
```

## Rule

```text
CONFIDENCE ≠ SEVERITY
```

Confidence = detector belief.

Severity = operational importance after context/fusion.

Detectors must not directly write final alerts to SQLite or the dashboard.

---

# 10. LATENCY CLASSES

## Event-driven

Used for:

- Scan;
- DDoS;
- DGA;
- TLS;
- Exfiltration.

## Periodic / rolling

Used for:

- RITA beaconing;
- RITA DNS tunnelling.

Benchmark separately:

```text
Track A latency
Track B latency
```

Never claim one universal real-time latency unless measured for the exact workflow.

---

# 11. OT-AWARE FUSION — PRIMARY NOVELTY

Pipeline:

```text
DRAFT Alert
→ Validation
→ Correlation
→ Confidence Preservation
→ Asset Criticality Lookup
→ Severity Policy
→ Final Alert
```

## Asset criticality

```text
critical
standard
unknown
```

Example:

```yaml
192.168.10.10:
  name: plc-demo
  criticality: critical
```

Label this as a lab/demo asset inventory.

## Correlation

Start deterministic:

```text
related source
+ bounded time window
+ multiple relevant alerts
```

Do not build a graph database or unexplained AI correlation engine.

## Defensible novelty claim

> A passive, local-first architecture that combines heterogeneous network detection outputs into a unified explainable alert layer and applies OT-aware correlation and asset criticality to produce operationally meaningful risk alerts.

---

# 12. TECHNOLOGY STACK

```text
Ubuntu VM
Python
Zeek
asyncio
RITA
scikit-learn
SQLite
Streamlit
pytest
Git
Antigravity Agent IDE
```

## Do not add without approval

```text
Kafka
Elasticsearch
Kubernetes
Microservices
Security Onion
Suricata
Snort
FastNetMon
Cloud databases
Cloud queues
FastAPI
React
Deep-learning infrastructure
```

These are scope creep for the current prototype.

---

# 13. WHY FASTNETMON IS NOT USED

FastNetMon was considered and rejected because its design includes active mitigation capabilities. A custom passive DDoS detector:

- better fits the no-active-response constraint;
- is simpler;
- is easier to defend;
- avoids unnecessary compliance explanation.

Final decision:

```text
DDoS = CUSTOM
```

---

# 14. REPOSITORY STRUCTURE

```text
sih-26145/
├── README.md
├── MASTER_EXECUTION_PLAN.md
├── .gitignore
├── requirements.txt or pyproject.toml
├── config/
│   └── assets.yaml
├── data/
│   ├── pcap/
│   ├── manifests/
│   ├── reference/
│   └── models/
├── docs/
│   ├── 04_alert_schema.json
│   ├── 05_COMPONENTS.md
│   ├── 08_RESEARCH_REFERENCES.md
│   ├── field_contracts.md
│   ├── benchmark_methodology.md
│   └── decisions.md
├── ingest/
│   ├── tailer.py
│   ├── parser.py
│   └── router.py
├── features/
│   ├── flow_stats.py
│   ├── dns_features.py
│   └── tls_features.py
├── detectors/
│   ├── beaconing/rita_adapter.py
│   ├── dns/rita_tunnel_adapter.py
│   ├── scanning/zeek_scan_adapter.py
│   ├── ddos/
│   ├── dga/
│   ├── tls/
│   └── exfiltration/
├── alerts/
│   ├── draft.py
│   ├── validator.py
│   └── constants.py
├── fusion/
│   ├── validator.py
│   ├── correlator.py
│   ├── criticality.py
│   ├── severity.py
│   └── engine.py
├── storage/sqlite_store.py
├── dashboard/app.py
├── scripts/
├── tests/
│   ├── unit/
│   ├── integration/
│   └── fixtures/
├── benchmarks/
└── artifacts/
```

---

# 15. DATASET / LAB TRAFFIC

Required scenarios:

```text
01_benign
02_ddos
03_beaconing
04_dns_tunnel
05_dga
06_tls
07_scanning
08_exfiltration
09_mixed
```

Each manifest must contain:

```text
Scenario
Threat label
PCAP path
Source/generation method
Date
Expected detector
Expected evidence
Replay command
Notes
```

Use only:

- isolated lab VMs;
- synthetic traffic;
- controlled PCAPs;
- recorded traffic;
- safe replay.

Never attack public or unauthorized systems.

---

# 16. 30 PHASES

## Phase 0 — Freeze
Freeze scope, constraints, detector decisions, architecture, stack, schema. Commit.

**Gate:** no coding before baseline commit.

## Phase 1 — Environment
Ubuntu, Git, Python, venv, dependency baseline.

**Gate:** versions recorded.

## Phase 2 — Repository
Create exact structure.

**Gate:** repository committed.

## Phase 3 — Zeek
Install, record version, run safe PCAP, enable JSON, verify real logs.

**Gate:** real Zeek JSON exists.

## Phase 4 — Scan
Load Zeek Scan, replay controlled scan, capture notice.

**Gate:** real scan notice exists.

## Phase 5 — TLS fields
Inspect real `ssl.log`, record fields/packages.

**Gate:** no assumed TLS fields.

## Phase 6 — RITA
Pin version, install, import logs, verify beacon + tunnel output.

**Gate:** RITA works OR fallback decision documented.

## Phase 7 — Components
Fill component inventory.

**Gate:** every reused component documented.

## Phase 8 — Lab data
Create nine scenario manifests.

**Gate:** every scenario reproducible.

## Phase 9 — Field contracts
Map detectors to actual input fields.

**Gate:** no imaginary fields.

## Phase 10 — Alert foundation
DRAFT factory, IDs, constants, validation.

**Gate:** valid mock alerts pass; invalid fail.

## Phase 11 — Ingest
Async tailer, parser, router, malformed handling, shutdown.

**Gate:** real records reach consumer.

## Phase 12 — Features
Flow, DNS, TLS modules + unit tests.

**Gate:** independently testable.

## Phase 13 — Scan adapter
`notice.log → adapter → DRAFT`.

**Gate:** controlled scan alert.

## Phase 14 — Beacon adapter
Verified RITA output → DRAFT.

**Gate:** beacon alert.

## Phase 15 — Tunnel adapter
Verified RITA output → DRAFT.

**Gate:** tunnel alert.

## Phase 16 — DDoS
Window, aggregation, baseline, threshold, evidence.

**Gate:** benign-vs-attack test.

## Phase 17 — DGA
Features, data, train/test, Random Forest, metrics, model, inference.

**Gate:** reproducible training/inference.

## Phase 18 — TLS
Verified metadata/fingerprint/behavior detector.

**Gate:** explainable alert without decryption claim.

## Phase 19 — Exfiltration
Directional bytes, ratio, baseline, deviation.

**Gate:** controlled scenario distinguishable.

## Phase 20 — Unified integration
All seven paths emit the same DRAFT schema.

**Gate:** no detector-specific storage/dashboard path.

## Phase 21 — OT-aware fusion
Validation, correlation, confidence, criticality, severity.

**Gate:** deterministic and explainable tests pass.

## Phase 22 — SQLite
DB init, insert, query, filters, restart persistence.

**Gate:** real alerts persist.

## Phase 23 — Streamlit
Real alerts, filters, evidence, criticality, correlation.

**Gate:** real stored alert visible.

## Phase 24 — End-to-end
PCAP → Zeek → ingest → detector → fusion → SQLite → dashboard.

**Gate:** one real alert crosses full pipeline.

## Phase 25 — Scenarios
Run all nine.

**Gate:** honest result log exists.

## Phase 26 — Benchmark
Latency, throughput, CPU/RAM where practical, metrics.

**Gate:** every number has raw evidence.

## Phase 27 — Compliance
Passive/read-only/no decryption/open-source checks.

**Gate:** checklist passes.

## Phase 28 — Documentation
Actual versions, commands, failures, fixes, limitations.

**Gate:** no critical TBD.

## Phase 29 — SIH checklist
Problem, implementation, innovation, evaluation, reproducibility.

**Gate:** evidence-backed.

## Phase 30 — Jury rehearsal
Practice all technical and novelty questions.

**Gate:** team can defend implementation honestly.

---

# 17. SEVEN-DAY SCHEDULE

## DAY 1 — Freeze + verify

### Whole team
Phase 0.

### Person A — Network
Phases 3 + 4:
Zeek + Scan.

### Person B — Backend/Network
Phase 5:
TLS field verification.

### Person C — Integration
Phase 6 FIRST:
RITA verification, 4-hour timebox.

### Persons D + E
Phases 1 + 2:
environment + repository.

### Rolling
Phase 7:
component inventory.

### Day-1 gate

- [ ] scope frozen;
- [ ] environment ready;
- [ ] repo ready;
- [ ] Zeek works;
- [ ] real JSON logs;
- [ ] scan notice;
- [ ] TLS fields documented;
- [ ] RITA works OR fallback documented.

---

## DAY 2 — Foundations

### Persons D + E
Phase 8 — lab data.

### Person A
Phases 9 + 12 — field contracts/features.

### Person B
Phase 10 — alerts.

### Person C
Phase 11 — ingest.

### Day-2 gate

- [ ] alert validation;
- [ ] ingest tests;
- [ ] feature tests;
- [ ] manifests.

---

## DAY 3 — Track A + hardest work

### Person C
Phases 13, 14, 15:
all Track A adapters.

### Person A
Phase 16:
DDoS.

### Person B
Start Phase 17:
DGA feature/data preparation.

### Day-3 gate

- [ ] Track A alerts;
- [ ] DDoS test;
- [ ] DGA features/data ready.

---

## DAY 4 — Finish Track B

### Person B
Finish Phase 17 — DGA.

### Person D
Phase 18 — TLS.

### Person E
Phase 19 — Exfiltration.

### Whole team
Phase 20 — unified integration.

### Day-4 gate

All seven paths emit schema-valid DRAFT alerts.

If behind, simplify dashboard/scenario variants.

Do not cut:

```text
DGA
FUSION
```

---

## DAY 5 — Fusion

### Persons B + C
Phase 21 — Fusion.

### Person E
Phase 22 — SQLite.

### Available member
`config/assets.yaml`.

### Day-5 gate

- [ ] critical asset;
- [ ] standard asset;
- [ ] unknown asset;
- [ ] correlation;
- [ ] invalid alert;
- [ ] SQLite restart persistence.

---

## DAY 6 — Integration + dashboard

### Person F / available member
Phase 23 — Streamlit.

### Whole team
Phase 24 — full pipeline.
Phase 25 — nine scenarios.

### Persons C + D
Start Phase 26 — benchmark.

### Day-6 gate

One real alert visibly travels:

```text
PCAP
→ Zeek
→ Detection
→ Unified Alert
→ Fusion
→ SQLite
→ Dashboard
```

All scenario results logged honestly.

---

## DAY 7 — Finish + defend

Morning:
finish Phase 26.

Whole team:
Phase 27 compliance.

Documentation:
Phase 28.

Checklist:
Phase 29.

Jury:
Phase 30.

### Final gate

Every required checkbox has evidence.

---

# 18. CRITICAL PATH

```text
Environment
→ Zeek
→ RITA verification
→ Real fields
→ Alert foundation
→ Ingest
→ Seven detectors
→ Unified alerts
→ Fusion
→ SQLite
→ Dashboard
→ Scenarios
→ Benchmark
```

Parallelize everything possible.

---

# 19. TWO PHASES NOT TO SHORTCUT

```text
PHASE 17 — DGA
PHASE 21 — FUSION
```

Why:

- DGA has the longest custom ML cycle.
- Fusion is the primary novelty claim.

Under pressure, cut:

- dashboard polish;
- animations;
- extra charts;
- extra scenario variants;
- unnecessary infrastructure.

Do not cut core evidence or fusion.

---

# 20. TESTING

## Unit

Test:

- schema;
- features;
- DDoS calculations;
- DGA features;
- TLS;
- exfiltration ratios;
- adapters;
- correlation;
- criticality;
- severity.

## Integration

```text
Zeek fixture
→ ingest
→ detector
→ DRAFT
```

## End-to-end

```text
PCAP
→ Zeek
→ ingest
→ detector
→ fusion
→ SQLite
→ dashboard
```

---

# 21. BENCHMARKING

Save raw results.

Record:

```text
date
machine
Ubuntu version
CPU
RAM
Python version
Zeek version
RITA version
dataset
scenario
rate
latency
throughput
CPU/RAM
result
```

Measure:

- Track A latency;
- Track B latency;
- throughput;
- CPU/RAM where practical;
- false positives;
- precision/recall/F1 for applicable ML.

Never invent numbers.

---

# 22. DOCUMENTATION HONESTY RULE

These words require evidence:

```text
implemented
working
tested
detected
real-time
streaming
AI-powered
accurate
low latency
high throughput
```

If reality differs from the plan, document the actual failure and limitation.

---

# 23. SIH-ORIENTED FINAL CHECKLIST

## Problem

- [ ] read-only/unidirectional compatible;
- [ ] no active response;
- [ ] no payload decryption;
- [ ] incremental processing;
- [ ] throughput target stated and tested;
- [ ] structured alerts.

## Prototype

- [ ] PCAP replay;
- [ ] Zeek;
- [ ] JSON logs;
- [ ] ingest;
- [ ] seven paths;
- [ ] unified alerts;
- [ ] fusion;
- [ ] SQLite;
- [ ] dashboard.

## Innovation

- [ ] reused vs custom clear;
- [ ] unified alert layer;
- [ ] OT context;
- [ ] criticality;
- [ ] correlation;
- [ ] explainability.

## Evaluation

- [ ] benign;
- [ ] nine scenarios;
- [ ] misses logged;
- [ ] false positives logged;
- [ ] latency;
- [ ] throughput;
- [ ] ML metrics where applicable.

## Reproducibility

- [ ] versions pinned;
- [ ] components documented;
- [ ] manifests present;
- [ ] clean-start tested.

---

# 24. JURY QUESTIONS

Prepare:

1. What problem does PS-26145 solve?
2. Why passive/read-only?
3. How does unidirectional operation work?
4. Why Zeek?
5. Why RITA?
6. Why reuse open source?
7. What is original?
8. Why not FastNetMon?
9. Why not Suricata/Snort?
10. Why no active response?
11. How is encrypted traffic analyzed?
12. Why Random Forest?
13. Confidence vs severity?
14. Asset criticality?
15. Correlation?
16. Unified alert layer?
17. Why SQLite?
18. Why Streamlit?
19. Why two latency classes?
20. Throughput testing?
21. False-positive testing?
22. Benchmark methodology?
23. RITA failure handling?
24. Limitations?
25. Scaling beyond prototype?

Answers must match actual implementation.

---

# 25. FAILURE RULES

## Zeek unavailable

Stop detector work. Fix telemetry.

## Missing log

Check traffic and configuration before calling it a failure.

## RITA unavailable

Follow Day-1 4-hour timebox.

## Detector failure

Log it. Do not fabricate alert.

## Invalid alert

Reject before persistence.

## SQLite failure

Report it. Do not fake dashboard data.

---

# 26. GIT DISCIPLINE

Minimum:

```text
main
```

Optional:

```text
feature/zeek
feature/ingest
feature/dga
feature/fusion
feature/dashboard
```

Before merge:

- tests pass;
- no secrets;
- no broken imports.

Commit meaningful milestones.

---

# 27. ANTIGRAVITY AGENT OPERATING CONTRACT

The agent must treat this file as the project contract.

The agent must NOT:

- silently change architecture;
- replace Zeek/RITA without approval;
- add major infrastructure;
- add active response;
- inject packets;
- decrypt payloads;
- invent fields;
- invent RITA output;
- fabricate metrics/tests/results;
- create fake final demo data;
- mark TODO work complete;
- claim third-party work as ours.

The agent MUST:

1. Read this file first.
2. Inspect current repository.
3. Inspect installed versions.
4. Inspect real input data.
5. Implement the smallest correct solution.
6. Add tests.
7. Run tests.
8. Report actual results.
9. Update documentation if reality differs.
10. Stop at an exit gate until evidence exists.

When uncertain:

```text
DO NOT GUESS

INSPECT
→ VERIFY
→ DOCUMENT
→ ASK IF ARCHITECTURAL APPROVAL IS REQUIRED
```

---

# 28. ANTIGRAVITY MASTER PROMPT

Copy this into Antigravity:

```text
You are the implementation agent for SIH PS-26145.

MASTER_EXECUTION_PLAN.md is the authoritative project contract. Read it completely before modifying code.

PROJECT:
Build a passive, local-first prototype for AI-based detection of cyber threats in unidirectional/read-only IP traffic.

ARCHITECTURE:
PCAP/Lab Traffic → Zeek → JSON Logs → Async Ingest → Reused Detection + Custom Detectors → Unified DRAFT Alert Layer → OT-Aware Fusion → SQLite → Streamlit.

FINAL DETECTORS:
1. DDoS — custom.
2. Beaconing — RITA + adapter.
3. DGA — custom feature-based classifier inspired by FANCI.
4. DNS tunnelling — RITA + adapter.
5. Suspicious encrypted TLS — custom metadata/fingerprint/behavior only.
6. Scanning — Zeek Scan + adapter.
7. Exfiltration — custom flow behavior.

NON-NEGOTIABLE:
- Passive/read-only.
- No packet injection.
- No blocking.
- No mitigation.
- No firewall modification.
- No return-path assumptions.
- No unauthorized targets.
- No payload decryption.
- Local-first.
- Incremental custom processing.
- Supporting evidence in every alert.
- Confidence and severity are different.
- Never fabricate versions, fields, metrics, tests, outputs, or results.

DO NOT:
- Replace Zeek/RITA without approval.
- Add Suricata, Snort, FastNetMon, Kafka, Elasticsearch, Kubernetes, cloud services, microservices, FastAPI, React, or major infrastructure without approval.
- Rebuild a detector marked REUSE.
- Claim Zeek/RITA/Zeek Scan as original.
- Guess Zeek fields.
- Guess RITA commands/output.
- Use legacy RITA examples without verifying installed release.
- Create fake final-demo data.
- Mark untested work complete.

FOR EVERY TASK:
1. Read the relevant phase.
2. Inspect repository.
3. Inspect actual component/data behavior.
4. Implement minimal correct solution.
5. Add/update tests.
6. Run tests.
7. Show actual results.
8. Update documentation.
9. State whether exit gate passed.

RITA:
Verify exact release before adapters. Day 1 has a 4-hour timebox. If usable beacon/tunnel output is not produced, stop and report exact blocker. Do not silently spend days troubleshooting. Use fallback only after documenting the decision.

ZEEK:
Never implement against assumed fields. Run Zeek and document actual fields first.

ALERTS:
All seven paths emit schema-valid DRAFT alerts. Detectors do not directly write to SQLite/dashboard. Fusion produces final operational alerts.

FUSION:
Protect Phase 21. Use deterministic, explainable correlation and asset-criticality-aware severity.

DOCUMENTATION:
If reality differs from the plan, record the real version, failure, workaround, and limitation.

WHEN UNCERTAIN:
Do not hallucinate.
Inspect → verify → document.
Ask for approval if changing architecture, detector scope, safety constraints, or critical path.

START:
Do not code detectors immediately.
First inspect repository and report:
1. Current structure.
2. Ubuntu/Python/Git environment.
3. Installed dependencies.
4. Current completed phase.
5. Next incomplete phase.
6. First exit gate.
Then execute one phase at a time.
```

---

# 29. DAILY AGENT PROMPT

Use every session:

```text
Read MASTER_EXECUTION_PLAN.md and inspect the current repository.

Report:
1. Current completed phase.
2. Current incomplete phase.
3. Exit gate.
4. Evidence already available.
5. Blockers.
6. Next smallest task.

Do not change architecture or scope.
Do not fabricate anything.

Implement only the next approved task.

After implementation:
1. run tests;
2. show actual results;
3. explain failures honestly;
4. update relevant documentation;
5. state PASS or NOT PASS for the exit gate.
```

---

# 30. FINAL DEMO

Show:

1. Problem: passive/read-only traffic analysis.
2. PCAP replay.
3. Zeek telemetry.
4. Reused + custom detection paths.
5. Unified DRAFT alert.
6. OT-aware fusion.
7. Same threat on standard vs critical asset.
8. SQLite persistence.
9. Streamlit dashboard.
10. Benchmark evidence.

---

# 31. FINAL ACCEPTANCE CRITERIA

The project is complete only when:

## Telemetry

- [ ] Zeek installed/version documented.
- [ ] PCAP replay works.
- [ ] JSON logs verified.

## Reused

- [ ] Scan works.
- [ ] Scan adapter works.
- [ ] Beacon path works or approved fallback.
- [ ] Tunnel path works or approved fallback.
- [ ] versions/licenses documented.

## Custom

- [ ] DDoS.
- [ ] DGA evaluated.
- [ ] TLS behavior.
- [ ] Exfiltration.

## Integration

- [ ] seven schema-valid paths.
- [ ] unified layer.
- [ ] fusion.
- [ ] criticality.
- [ ] correlation.

## Storage/UI

- [ ] real alerts persist.
- [ ] real alerts display.

## Evaluation

- [ ] benign baseline.
- [ ] nine scenarios.
- [ ] misses/false positives recorded.
- [ ] latency.
- [ ] throughput.
- [ ] ML metrics where applicable.

## Compliance

- [ ] passive.
- [ ] read-only.
- [ ] no active response.
- [ ] no payload decryption.
- [ ] open-source attribution.

## Reproducibility

- [ ] versions pinned.
- [ ] setup tested.
- [ ] no secrets.
- [ ] no fake data required.
- [ ] clean-start demo tested.

---

# 32. DEFINITION OF DONE

```text
IT BUILDS
+ IT RUNS
+ IT PROCESSES REAL TELEMETRY
+ IT DETECTS
+ IT EXPLAINS
+ IT FUSES
+ IT STORES
+ IT DISPLAYS
+ IT IS MEASURED
+ IT IS DOCUMENTED
+ IT IS REPRODUCIBLE
+ IT IS HONEST
```

---

# 33. FINAL EXECUTION ORDER

```text
DAY 1
0 Freeze
1 Environment
2 Repository
3 Zeek
4 Scan
5 TLS fields
6 RITA
7 Components

DAY 2
8 Lab data
9 Field contracts
10 Alert foundation
11 Ingest
12 Features

DAY 3
13 Scan adapter
14 Beacon adapter
15 DNS tunnel adapter
16 DDoS
17 Start DGA

DAY 4
17 Finish DGA
18 TLS
19 Exfiltration
20 Unified alerts

DAY 5
21 OT-Aware Fusion
22 SQLite

DAY 6
23 Dashboard
24 End-to-end
25 Nine scenarios
26 Benchmark start

DAY 7
26 Benchmark finish
27 Compliance
28 Documentation
29 SIH checklist
30 Jury rehearsal
```

---

# 34. FINAL PRINCIPLE

Do not build the biggest system.

Build the **smallest complete, defensible, measurable system** that satisfies the problem.

Priority:

```text
WORKING PIPELINE
>
MEASURABLE RESULTS
>
EXPLAINABLE NOVELTY
>
EXTRA FEATURES
>
VISUAL POLISH
```

If time becomes limited:

```text
KEEP:
Zeek
Seven threat paths
Unified alerts
Fusion
SQLite
Evidence
Benchmark

SIMPLIFY:
Dashboard
Charts
Animations
Extra ML
Extra infrastructure
Extra scenario variants
```

Never sacrifice the core pipeline for cosmetics.

---

# 35. IMPLEMENTATION REFERENCES

Use the exact installed versions and official documentation.

Primary references:

1. Zeek official documentation — JSON logging and Scan framework.
2. RITA official repository/documentation — current installation, Zeek ingestion, beaconing, DNS tunnelling.
3. Schüppen et al. — FANCI, USENIX Security 2018.
4. Python asyncio documentation.
5. scikit-learn documentation.
6. Streamlit documentation.

---

# END
