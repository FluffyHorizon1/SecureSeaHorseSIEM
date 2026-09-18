# SecureSeaHorse SIEM — Phase 4 Changelog

## Version 1.4.0 — Traffic Classification & Exploit Detection

### Summary

Phase 4 adds an adaptive traffic classification engine that categorizes network and system telemetry into six attack categories, scores detections by confidence, and tags each finding with the corresponding MITRE ATT&CK technique ID. Detection uses a dual approach: per-device statistical baselines (EWMA) flag anomalies, while regex patterns catch known exploit signatures. All detections are persisted to PostgreSQL and logged with MITRE context.

---

### Attack Categories (6)

| Category | Sub-types | MITRE Tactics | Detection Method |
|---|---|---|---|
| **DDoS** | Volumetric, SYN flood, amplification, app-layer | Impact | Inbound volume z-score + log signatures |
| **Port Scanning** | Sequential, stealth, service enumeration | Discovery / Recon | Connection refused/reset counts + tool signatures |
| **Brute Force** | Standard, credential stuffing, password spray | Credential Access | Auth failure rate z-score + username diversity analysis |
| **Data Exfiltration** | Volume anomaly, DNS tunneling, ratio shift | Exfiltration | Outbound volume z-score + in/out ratio + DNS tunnel signatures |
| **C2 Beaconing** | Periodic beacon, DNS beacon, known frameworks | Command and Control | Report interval regularity (CoV) + framework signatures |
| **Lateral Movement** | Internal scan, pass-the-hash, PtT, SMB, RDP, WMI | Lateral Movement | Internal IP scan patterns + credential abuse signatures |

---

### Architecture

**Three new headers:**

1. **`mitre_map.h`** — Static registry of 28 MITRE ATT&CK technique mappings. Each detection sub-type (e.g. `ddos_syn_flood`) maps to a technique ID (`T1498.001`), name, tactic, and URL. The registry is a read-only `std::map` initialized at startup.

2. **`baseline_tracker.h`** — Per-device adaptive baselines using Exponentially Weighted Moving Average (EWMA). Tracks 8 metrics per device: inbound/outbound network rates, in/out ratio, CPU usage, RAM usage, auth failure rate, total event rate, and report interval timing. Computes z-scores for anomaly detection and translates them to confidence scores.

3. **`traffic_classifier.h`** — The main detection engine. Contains 6 detection modules (one per attack category), each combining statistical baseline anomalies with regex pattern matching. Outputs `ThreatDetection` structs tagged with MITRE ATT&CK metadata.

**Updated files:**

4. **`db_layer.h`** — Added `threat_detections` table with MITRE columns and `insert_threat_detection()` method. Indexes on device_id, category, and mitre_id.

5. **`server.cpp`** — Integrated classifier into the processing pipeline after regex analysis and before CSV output. Threats are persisted to PostgreSQL and logged at severity-appropriate levels.

6. **`server.conf`** — Added 15 new config keys for classifier tuning.

---

### Detection Approach: Baselines + Thresholds

**Adaptive Baselines (EWMA):**
- Each device builds its own "normal" profile over time.
- The EWMA smooths observations with configurable learning rate (`cls_baseline_alpha`, default 0.05).
- A warmup period (`cls_baseline_warmup`, default 20 samples) prevents false positives on cold start.
- Anomalies are scored by z-score: how many standard deviations the current observation is from the baseline mean.

**Fixed Thresholds (Configurable Overrides):**
- Every statistical check also has an absolute ceiling (e.g. 100MB inbound = DDoS regardless of baseline).
- Absolute thresholds catch attacks on newly-registered devices before baselines are ready.
- All thresholds are tunable via `server.conf` without recompilation.

**Confidence Scoring:**
- Each detection carries a confidence score from 0.0 to 1.0.
- Statistical detections derive confidence from z-score magnitude.
- Log-based pattern matches use fixed confidence based on pattern specificity (e.g. Cobalt Strike signature = 0.9).
- Concurrent indicators boost confidence (e.g. network spike + CPU spike = higher DDoS confidence).

---

### MITRE ATT&CK Integration

Every detection is tagged with:
- **Technique ID** (e.g. `T1498.001`)
- **Technique Name** (e.g. "Network Denial of Service: Direct Network Flood")
- **Tactic** (e.g. "Impact")

This enables direct mapping to MITRE ATT&CK Navigator, SOC playbooks, and threat intelligence feeds. 28 technique mappings ship built-in.

---

### Database Schema Addition

```sql
threat_detections
├── id (BIGSERIAL PK)
├── device_id, timestamp_ms, machine_ip
├── category, sub_type, severity
├── confidence (DOUBLE PRECISION)
├── mitre_id, mitre_name, mitre_tactic
├── description, evidence
└── received_at (TIMESTAMPTZ, auto)

Indexes:
├── idx_threats_device_ts (device_id, timestamp_ms DESC)
├── idx_threats_category  (category, received_at DESC)
└── idx_threats_mitre     (mitre_id, received_at DESC)
```

Table is created automatically on server start. No manual migration needed.

---

### Configuration Reference

```ini
# Master switch
classifier_enabled = true

# Baseline learning
cls_baseline_alpha  = 0.05   # EWMA learning rate
cls_baseline_warmup = 20     # Samples before baseline is trusted

# Anomaly z-score tiers
cls_z_high   = 3.0           # → severity=critical
cls_z_medium = 2.5           # → severity=high
cls_z_low    = 2.0           # → severity=medium

# Per-category thresholds
cls_ddos_inbound_z         = 3.0
cls_ddos_inbound_abs_bytes = 100000000
cls_portscan_refused_min   = 10
cls_brute_min_failures     = 5
cls_exfil_outbound_z       = 3.0
cls_exfil_outbound_abs_bytes = 50000000
cls_c2_jitter_max          = 0.15
```

---

### Migration Guide from v1.3.0

1. **New files to add:**
   - `mitre_map.h` → alongside other headers
   - `baseline_tracker.h` → alongside other headers
   - `traffic_classifier.h` → alongside other headers

2. **Updated files (replace in-place):**
   - `db_layer.h` — added `threat_detections` table + insert method
   - `server.cpp` — integrated classifier into processing pipeline
   - `server.conf` — added Phase 4 config keys

3. **No new dependencies.** Phase 4 uses only C++ STL (`<regex>`, `<cmath>`, `<map>`).

4. **No protocol changes.** Client-side files are unchanged from Phase 3.

5. **Database migration:** The new `threat_detections` table is created automatically on server start (`CREATE TABLE IF NOT EXISTS`). No manual SQL needed.

6. **Tuning guide:**
   - Start with defaults — they're calibrated for a typical enterprise environment.
   - If you get too many DDoS false positives, increase `cls_ddos_inbound_z` or `cls_ddos_inbound_abs_bytes`.
   - If you get too many C2 beaconing alerts on legitimate monitoring agents, increase `cls_c2_jitter_max` (e.g. to 0.25).
   - The warmup period prevents cold-start false positives. Reduce `cls_baseline_warmup` for faster (but noisier) detection.

---

### Version History

| Version | Phase | Highlights |
|---------|-------|------------|
| 1.0.1 | — | Initial release: mTLS, binary protocol, CSV output |
| 1.1.0 | 1 | Thread pool, backoff, CLI, async logger |
| 1.2.0 | 2 | PostgreSQL, regex engine, threshold alerting |
| 1.3.0 | 3 | HMAC-SHA256, heartbeat, CRL/OCSP, cert pinning |
| 1.4.0 | 4 | Traffic classification, 6 attack categories, MITRE ATT&CK |
