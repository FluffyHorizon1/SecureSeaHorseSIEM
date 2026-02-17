# 🐴 SecureSeaHorse v1.6.0: The Threat Intelligence & Integrity Update

**Release Date:** February 17, 2026  
**Status:** Major Update (Phase 6)

SecureSeaHorse is a lightweight SIEM (Security Information and Event Management) system built from scratch in C++17. It consists of a telemetry agent (client) deployed on endpoints and a central analysis server that collects, processes, stores, and classifies security data in real time over mutual TLS.

---

## 🚀 Feature Overview by Phase

### Phase 1 — Core Infrastructure (v1.1.0)
The foundation: secure transport, telemetry collection, and operational reliability.

* **Binary Protocol v1:** Compact fixed-size struct transmitted over mTLS (mutual TLS 1.2+).
* **Dynamic Thread Pool:** Server scales worker threads to handle concurrent agents with min/max bounds.
* **Async Logger:** Non-blocking, rotating log writer with configurable size limits.
* **Exponential Backoff:** Client reconnects with jitter to prevent thundering herd after outages.
* **CLI Interface:** Both client and server accept `--port`, `--config`, `--verbose`, `--version` flags.
* **CSV Fallback:** If PostgreSQL is unavailable, telemetry is written to a local CSV file.

### Phase 2 — Analysis & Persistence (v1.2.0)
Server-side intelligence: parse logs, detect patterns, persist everything.

* **Regex Analysis Engine:** Configurable `rules.conf` with named patterns (e.g. `failed_login`, `privilege_escalation`) scanned against every log chunk.
* **Threshold Alerting:** "5 failed logins in 30 seconds" style rules with per-device state, cooldowns, and a dedicated alert log.
* **PostgreSQL Persistence:** Auto-schema creation for `telemetry`, `security_events`, and all subsequent tables. Parameterized queries throughout.

### Phase 3 — Protocol Security (v1.3.0)
Hardened protocol with cryptographic authenticity and certificate lifecycle management.

* **HMAC-SHA256 Payload Signing:** Every v2 packet is cryptographically signed. Keys derived via RFC 5705 (TLS Keying Material Exporters) — never stored on disk or transmitted.
* **Constant-Time Verification:** `CRYPTO_memcmp` eliminates timing side-channel attacks.
* **CRL & OCSP Stapling:** Revoke compromised device certificates instantly without reissuing the entire CA.
* **Certificate Pinning:** SHA-256 fingerprint pinning protects against rogue CA attacks.
* **Heartbeat Engine:** Bidirectional signed ping/pong with configurable timeout. Server reaps zombie sockets automatically.

### Phase 4 — Traffic Classification (v1.4.0)
Behavioral analysis with adaptive baselines and attack taxonomy.

* **6 Attack Categories:** DDoS, port scanning, brute force, data exfiltration, C2 beaconing, lateral movement.
* **Adaptive Baselines (EWMA):** Per-device "normal" profiles with z-score anomaly detection. Warmup period prevents cold-start false positives.
* **Fixed Thresholds:** Absolute ceilings catch attacks on new devices before baselines are ready.
* **25+ Detection Patterns:** Compiled regex signatures for known tools (nmap, Cobalt Strike, Mimikatz, etc.).
* **MITRE ATT&CK Tagging:** 28 technique mappings across all categories. Every detection includes technique ID, name, tactic, and URL.

### Phase 5 — Threat Intelligence Feeds (v1.5.0)
Real-time matching against known-bad indicators from external feeds.

* **7 IoC Types:** IP addresses, CIDR ranges, domains (with subdomain matching), file hashes (MD5/SHA1/SHA256), URLs, emails, user agents.
* **O(1) Lookups:** Hash-map backed indicator store. CIDR ranges use prefix matching.
* **Regex Extraction:** IPs, domains, hashes, URLs, and emails are automatically extracted from raw log chunks and matched against loaded feeds.
* **Feed Auto-Reload:** Polls the feeds directory for file modifications. Drop a new `.csv` file in and it's loaded on the next check cycle — no restart required.
* **Thread-Safe:** `std::shared_mutex` allows concurrent matching during feed reload.
* **Sample Feeds Included:** 45 indicators across 3 feeds (malicious IPs, domains, hashes) with MITRE technique IDs.

### Phase 6 — File Integrity Monitoring (v1.6.0)
Detect unauthorized file changes across your fleet.

* **Client-Side Scanner:** Recursive directory walker with SHA-256 hashing (OpenSSL EVP). Configurable watch paths, exclusion patterns, file size limits, and recursion depth.
* **Server-Side Monitor:** Per-device baseline storage. Detects file additions, modifications, and deletions by diffing against the stored baseline.
* **Severity Classification:** Changes to OS-critical files (`/etc/passwd`, `System32\config`) are automatically classified as `critical`. Web roots and service configs as `high`. Everything else configurable.
* **MITRE ATT&CK Tagging:** Additions → Persistence/Collection, Modifications → Impact/Defense Evasion, Deletions → Defense Evasion.
* **New Protocol Message:** `MSG_FIM_REPORT (0x03)` — text-serialized snapshot sent over the existing v2 TLS channel.

---

## 🏗 Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         ENDPOINTS (Clients)                         │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────────────┐ │
│  │  Telemetry   │  │  Log Scraper │  │  FIM Scanner (Phase 6)     │ │
│  │  (CPU/RAM/   │  │  (Win Events │  │  SHA-256 file hashing,     │ │
│  │   Disk/Net)  │  │   + syslog)  │  │  recursive watch paths     │ │
│  └──────┬───────┘  └──────┬───────┘  └────────────┬───────────────┘ │
│         └──────────────────┼──────────────────────┘                  │
│                            │  mTLS + HMAC-SHA256 (v2 Protocol)      │
└────────────────────────────┼────────────────────────────────────────┘
                             │
┌────────────────────────────┼────────────────────────────────────────┐
│                        SERVER (Central)                              │
│                            ▼                                         │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │                    Message Dispatcher                            │ │
│  │  MSG_TELEMETRY(0x00) │ MSG_HEARTBEAT(0x01/02) │ MSG_FIM(0x03)  │ │
│  └──────────┬────────────────────┬──────────────────────┬─────────┘ │
│             │                    │                      │            │
│  ┌──────────▼─────────┐  ┌──────▼──────┐  ┌───────────▼──────────┐ │
│  │  Processing Chain   │  │  Heartbeat  │  │  FIM Monitor         │ │
│  │  ├ Regex Engine     │  │  Ping/Pong  │  │  Per-device baselines│ │
│  │  ├ Alert Engine     │  │  + Reaping  │  │  Add/Mod/Del detect  │ │
│  │  ├ Traffic Classif. │  └─────────────┘  │  Severity classif.   │ │
│  │  └ Threat Intel     │                   └──────────────────────┘ │
│  └──────────┬──────────┘                                             │
│             │                                                        │
│  ┌──────────▼──────────────────────────────────────────────────────┐ │
│  │                     PostgreSQL                                   │ │
│  │  telemetry │ security_events │ threat_detections │ ioc_matches  │ │
│  │                              │ fim_events                        │ │
│  └──────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 🔒 Security Architecture

| Threat | Defense |
| :--- | :--- |
| **Data Tampering** | HMAC-SHA256 signing (RFC 5705 derived keys) |
| **Timing Attacks** | `CRYPTO_memcmp` constant-time verification |
| **Stolen Devices** | CRL + OCSP instant certificate revocation |
| **Fake Servers** | SHA-256 certificate fingerprint pinning |
| **Zombie Sockets** | Signed heartbeat with timeout-based reaping |
| **DDoS / Port Scans** | Adaptive baselines + fixed threshold detection |
| **C2 Beaconing** | Report interval jitter analysis + framework signatures |
| **Lateral Movement** | Internal scan pattern + credential abuse detection |
| **Known Bad Actors** | IoC feed matching (IPs, domains, hashes, CIDRs) |
| **File Tampering** | SHA-256 FIM with per-device baselines |

---

## 📂 Repository Structure

```
SecureSeaHorse/
├── CMakeLists.txt              # Build configuration (v1.6.0)
├── README.md
├── .gitignore
│
├── src/
│   ├── client.cpp              # Telemetry agent + FIM scanner
│   ├── client_protocol.h       # Client-side protocol structures
│   ├── server.cpp              # Central analysis server
│   ├── server_protocol.h       # Server-side protocol structures
│   ├── crypto_utils.h          # HMAC, CRL, OCSP, heartbeat, v2 framing
│   ├── regex_engine.h          # Configurable log pattern matching
│   ├── alert_engine.h          # Threshold-based alerting
│   ├── db_layer.h              # PostgreSQL persistence (5 tables)
│   ├── traffic_classifier.h    # 6-category attack detection
│   ├── baseline_tracker.h      # EWMA per-device baselines
│   ├── mitre_map.h             # 28 MITRE ATT&CK technique mappings
│   ├── threat_intel.h          # IoC feed engine + real-time matching
│   ├── fim_common.h            # FIM data structures + SHA-256 hashing
│   ├── fim_scanner.h           # Client-side file integrity scanner
│   └── fim_monitor.h           # Server-side FIM baseline + change detection
│
├── config/
│   ├── server.conf             # Server configuration (all phases)
│   ├── client.conf             # Client configuration (all phases)
│   ├── rules.conf              # Regex analysis rules
│   └── feeds/                  # Threat intelligence feed CSVs
│       ├── malicious_ips.csv
│       ├── malicious_domains.csv
│       └── malicious_hashes.csv
│
├── certs/                      # mTLS certificates (gitignored)
│   ├── ca.crt
│   ├── server.crt / server.key
│   └── client.crt / client.key
│
└── docs/
    ├── PHASE1_CHANGELOG.md
    ├── PHASE2_CHANGELOG.md
    ├── PHASE3_CHANGELOG.md
    ├── PHASE4_CHANGELOG.md
    ├── PHASE5_CHANGELOG.md
    └── PHASE6_CHANGELOG.md
```

---

## 📦 Database Schema (5 Tables)

All tables are auto-created on server start (`CREATE TABLE IF NOT EXISTS`).

| Table | Phase | Purpose | Key Columns |
| :--- | :--- | :--- | :--- |
| `telemetry` | 2 | Raw device metrics | device_id, CPU, RAM, disk, network, logs |
| `security_events` | 2 | Regex-matched log events | device_id, rule_name, severity, matched_text |
| `threat_detections` | 4 | Traffic classifier alerts | category, sub_type, confidence, MITRE ID |
| `ioc_matches` | 5 | Threat intel feed hits | ioc_type, ioc_value, feed_source, MITRE ID |
| `fim_events` | 6 | File integrity changes | change_type, file_path, old/new hash, severity |

---

## 📋 Prerequisites

* **C++17** compiler (MSVC 2019+, GCC 8+, Clang 7+)
* **OpenSSL 3.0+** (required for HMAC, OCSP, SHA-256 hashing)
* **PostgreSQL 14+** (optional — CSV fallback if unavailable)
* **CMake 3.15+**
* **vcpkg** (recommended on Windows)

---

## 📦 Build Instructions

### Windows (vcpkg + MSVC)

```powershell
# Install dependencies
.\vcpkg install openssl:x64-windows libpq:x64-windows

# Build
mkdir build && cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=[path_to_vcpkg]/scripts/buildsystems/vcpkg.cmake
cmake --build . --config Release
```

### Linux (apt + GCC)

```bash
# Install dependencies
sudo apt install libssl-dev libpq-dev postgresql cmake g++

# Build
mkdir build && cd build
cmake ..
make -j$(nproc)
```

---

## ⚙️ Quick Start

### 1. Generate Certificates

```bash
# CA
openssl req -x509 -newkey rsa:4096 -keyout ca.key -out ca.crt -days 365 -nodes -subj "/CN=SeaHorseCA"

# Server
openssl req -newkey rsa:2048 -keyout server.key -out server.csr -nodes -subj "/CN=server"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365

# Client
openssl req -newkey rsa:2048 -keyout client.key -out client.csr -nodes -subj "/CN=agent001"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365
```

### 2. Configure & Run

```bash
# Edit configs
vi config/server.conf   # Set cert paths, DB credentials, alert thresholds
vi config/client.conf   # Set server_ip, device_id, FIM watch paths

# Start server
./SeaHorseServer --config config/server.conf

# Start client (on each endpoint)
./SeaHorseClient --config config/client.conf
```

### 3. Add Threat Intel Feeds

Drop `.csv` files into the `feeds/` directory. Format:
```
# type | value | severity | description | mitre_id | tags
ip     | 198.51.100.23 | critical | C2 server | T1071.001 | c2,apt
domain | evil.com      | high     | Phishing   | T1566.002 | phishing
```

Feeds auto-reload every 5 minutes (configurable via `feeds_reload_interval_s`).

---

## 📊 Version History

| Version | Phase | Highlights |
|---------|-------|------------|
| 1.0.1 | — | Initial release: mTLS, binary protocol, CSV output |
| 1.1.0 | 1 | Thread pool, backoff, CLI, async logger |
| 1.2.0 | 2 | PostgreSQL, regex engine, threshold alerting |
| 1.3.0 | 3 | HMAC-SHA256, heartbeat, CRL/OCSP, cert pinning |
| 1.4.0 | 4 | Traffic classification, 6 attack categories, MITRE ATT&CK |
| 1.5.0 | 5 | Threat intelligence feeds, IoC matching, auto-reload |
| **1.6.0** | **6** | **File Integrity Monitoring, per-device baselines, SHA-256 hashing** |

---

## 🗺 Roadmap

| Phase | Feature | Status |
|-------|---------|--------|
| 7 | REST API & Web Dashboard | Planned |
| 8 | Incident Response Automation | Planned |
| 9 | Agent Fleet Management | Planned |
| 10 | Network Deep Inspection | Planned |

---

## 📜 License

This project is proprietary. All rights reserved.
