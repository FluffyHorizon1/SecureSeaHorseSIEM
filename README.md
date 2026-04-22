# 🐴 SecureSeaHorse v3.1.2: Complete SIEM Platform

**Release Date:** April 22, 2026
**Status:** Hardening & Security Audit Release (Phase 15)

SecureSeaHorse is a lightweight, enterprise-grade SIEM (Security Information and Event Management) system built from scratch in C++17. It consists of a telemetry agent (client) deployed on endpoints and a central analysis server that collects, processes, stores, classifies, correlates, and automatically responds to security data in real time over mutual TLS.

**What's new in v3.1.1 (April 2026):** Comprehensive 7-round security audit. Fixed 5 critical bugs (shutdown deadlock in IR engine, correlator callback deadlock, FIM TOCTOU race, TLS protocol-downgrade exposure, stored XSS in the web dashboard) and added 12 DoS-hardening controls across the HTTP parser, database layer, regex engine, and feed loaders. Zero new features — every change is defensive.

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
* **v3.1.1 hardening:** Feed loader now caps at 5 million entries per feed, 8 KB per line, 2 KB per field, and 16 columns — a malformed or malicious feed file can no longer exhaust memory.

### Phase 6 — File Integrity Monitoring (v1.6.0)
Detect unauthorized file changes across your fleet.

* **Client-Side Scanner:** Recursive directory walker with SHA-256 hashing (OpenSSL EVP). Configurable watch paths, exclusion patterns, file size limits, and recursion depth.
* **Server-Side Monitor:** Per-device baseline storage. Detects file additions, modifications, and deletions by diffing against the stored baseline.
* **Severity Classification:** Changes to OS-critical files (`/etc/passwd`, `System32\config`) are automatically classified as `critical`. Web roots and service configs as `high`. Everything else configurable.
* **MITRE ATT&CK Tagging:** Additions → Persistence/Collection, Modifications → Impact/Defense Evasion, Deletions → Defense Evasion.
* **New Protocol Message:** `MSG_FIM_REPORT (0x03)` — text-serialized snapshot sent over the existing v2 TLS channel.
* **v3.1.1 hardening:** The file size check and hash computation now share a single file handle with on-the-fly size enforcement, eliminating a TOCTOU race where a file could be swapped between the `fs::file_size()` probe and the read.

### Phase 7 — REST API & Web Dashboard (v1.7.0)
Browser-based visibility with a full JSON query layer.

* **Embedded HTTP/1.1 Server:** Zero external dependencies. Runs alongside the mTLS listener on a separate port.
* **Bearer Token Authentication:** All `/api/*` endpoints require `Authorization: Bearer <token>`. Dashboard HTML is unauthenticated (serves the login form).
* **Single-Page Dashboard:** Real-time stat cards (fleet, threats, IoC, FIM, incidents, correlations), 4 tables (threats, IoC, FIM, events), auto-refresh every 15 seconds.
* **JSON Endpoints:** `/api/stats`, `/api/threats`, `/api/ioc`, `/api/fim`, `/api/events`, `/api/devices`, `/api/correlations`, `/api/ir/actions`, `/api/ir/blocklist`, `/api/ir/quarantined`.
* **v3.1.1 hardening:** All `limit` query parameters clamped to `[1, 1000]` to prevent DoS via oversized result sets. HTTP parser rewritten with slowloris caps, header count/length limits (100 headers, 8 KB each), and exception-safe Content-Length parsing. **Stored XSS vulnerability fixed** — every user-controlled field rendered in the dashboard (log lines, file paths, IoC values, descriptions) is now HTML-escaped before insertion.

### Phase 8 — Incident Response Automation (v1.8.0)
Automated containment actions triggered by detection events.

* **7 Built-in Playbooks:** `critical_response`, `brute_force_block`, `c2_containment`, `exfil_throttle`, `ioc_critical_block`, `fim_critical_quarantine`, `general_log`.
* **7 Action Types:** `log`, `block_ip`, `quarantine`, `webhook`, `script`, `rate_limit`, `disable_user`.
* **IP Blocklist:** In-memory set with optional expiry timestamps (30 min to 24 hr). Accessible via REST at `/api/ir/blocklist`.
* **Device Quarantine:** Tagged devices can be isolated from further processing. Exposed at `/api/ir/quarantined`.
* **Cooldowns & Dedup:** Prevents action storms — each rule has a configurable cooldown (default 300 s per device+category+rule).
* **Audit Trail:** Every executed action logged with timestamp, target, success flag, and detail. Trail capped at 10,000 entries.
* **Async Worker Thread:** Actions queued and processed off the main ingestion path so a slow webhook never blocks telemetry.
* **v3.1.1 hardening:** **Shutdown deadlock fixed** — the drain loop previously held the engine mutex while calling `execute_action()` which re-acquires the same mutex for block/quarantine operations. Server would hang on stop. Now drains under proper lock-ordering.

### Phase 9 — Agent Fleet Management (v1.9.0)
Central inventory and health tracking for every connected agent.

* **Device Inventory:** Auto-registration on first contact. Tracks hostname, IP, OS, agent version, first/last seen, per-device counters (reports, alerts, threats, IoC hits, FIM changes).
* **Health Scoring:** 0.0–1.0 computed from connectivity freshness, quarantine state, and threat history.
* **3 Status Tiers:** `online` (< 5 min), `stale` (< 15 min), `offline` (≥ 15 min). Thresholds configurable.
* **Tags & Groups:** Label devices (`production`, `web-server`, `dc-east`) for filtering and scoped playbooks.
* **JSON Export:** Full inventory at `/api/devices`, single-device drill-down at `/api/devices?device_id=N`.

### Phase 10 — Network Deep Inspection (v2.0.0)
Content-aware analyzers that spot advanced threats buried in log text.

* **DNS Analysis:** DGA detection (Shannon entropy + consonant ratio + label length), DNS tunneling (subdomain depth > 5, label length > 40), suspicious TLDs (.xyz, .tk, .ml, .ga, .cf) with high-entropy subdomains. MITRE T1568.002 / T1071.004.
* **Protocol Anomaly:** Unusual HTTP methods (CONNECT, TRACE, PROPFIND), suspicious user agents (python-requests, curl, powershell, certutil, bitsadmin), base64 URL payloads > 40 chars, oversized URLs > 300 chars. MITRE T1190 / T1071.001.
* **Connection Tracking:** SYN flood detection (half-open ratio > 50%), RST storm detection (reset ratio > 40% indicates port scanning). MITRE T1498.001 / T1046.
* **Entropy Analysis:** Shannon entropy > 7.2 bits/byte flags encrypted C2 payloads; > 6.5 flags data encoding. Scans for base64 blobs in logs. MITRE T1573.001 / T1132.
* **Unified Facade:** `NetworkInspector::inspect(log_chunk, device_id, ip)` runs every enabled analyzer in one call.

### Phase 11 — Process Monitor (v2.1.0 · Client-Side)
Real-time process enumeration and suspicious-tool detection.

* **Cross-Platform Enumeration:** Windows uses `CreateToolhelp32Snapshot` + `QueryFullProcessImageNameW`; Linux reads `/proc/[pid]/{stat,exe,cmdline,status}`.
* **Full Process Detail:** PID, PPID, name, full path, command line, memory (working set / RSS), CPU %, user owner, elevation status.
* **Change Detection:** Between each scan, reports new, terminated, and suspicious processes.
* **Suspicious Process Library:** Built-in watch list for mimikatz, lazagne, procdump, psexec, nmap, certutil, bitsadmin, rundll32, xmrig, minerd, and others. Extensible via config.
* **New Protocol Message:** `MSG_PROCESS_REPORT (0x04)`.

### Phase 12 — Network Connection Inventory (v2.2.0 · Client-Side)
Live TCP/UDP connection visibility, server-side correlation.

* **netstat-Equivalent Coverage:** All active TCP and UDP sockets with local/remote address, port, state (LISTEN/ESTABLISHED/SYN_SENT/TIME_WAIT/CLOSE_WAIT), and owning PID.
* **Windows:** `GetTcpTable2` / `GetUdpTable`. Linux: parses `/proc/net/{tcp,tcp6,udp}` including hex IP/port decoding.
* **Change Detection:** New, closed, and suspicious connections reported between scans.
* **Suspicious Port Detection:** Flags connections to common reverse-shell / C2 ports (4444, 5555, 6666, 1337, 31337, 6667, 6697).
* **New Protocol Message:** `MSG_CONN_REPORT (0x05)`.

### Phase 13 — User Session & Auth Tracker (v2.3.0 · Client-Side)
Login/logout and privilege-escalation visibility.

* **Active Session Enumeration:** Console, RDP, SSH, and TTY sessions with username, source IP (for remote), terminal, login time, and elevation status.
* **Windows:** WTS session enumeration (`WTSEnumerateSessions`, `WTSQuerySessionInformation`) plus parsing of Windows Event IDs 4624 / 4625 / 4672.
* **Linux:** `utmp`/`wtmp` for sessions; regex parses `/var/log/auth.log` for `Failed password`, `Accepted password/publickey`, `sudo COMMAND=`, and `su session opened`.
* **5 Event Types:** `login_success`, `login_failed`, `logout`, `priv_escalation`, `account_lockout`.
* **Correlation Feed:** Failed logins and privilege escalations pushed straight to the Phase 15 correlation engine.
* **New Protocol Message:** `MSG_SESSION_REPORT (0x06)`.

### Phase 14 — Software & Patch Inventory (v2.4.0 · Client-Side)
Installed software enumeration with change detection.

* **Installed Package Listing:** Name, version, publisher, install date, install location, size.
* **Windows:** Reads both 32-bit and 64-bit `Uninstall` registry hives (HKLM + WOW6432Node).
* **Linux:** Tries `dpkg-query`, `rpm -qa`, and `pacman -Q` in order depending on the distribution.
* **Change Detection:** New, removed, and version-updated packages reported between scans (default hourly).
* **Deduplication:** Prevents double-counting when the same package appears in multiple registry hives.
* **New Protocol Message:** `MSG_SOFTWARE_REPORT (0x07)`.

### Phase 15 — Correlation Engine (v2.5.0 · Server-Side)
Cross-device event correlation that links individual detections into multi-stage incidents.

* **7 Built-in Correlation Rules:**
  * `brute_force_then_login` — successful auth following a brute force burst (T1110, cross-device)
  * `ioc_then_exfil` — IoC hit followed by exfiltration pattern (T1041, single-device)
  * `fim_and_c2` — file modification paired with C2 beaconing (T1071, single-device)
  * `multi_device_campaign` — 4+ high-severity events across different devices in 5 min (T1486)
  * `privesc_suspicious_proc` — privilege escalation followed by suspicious process execution (T1078)
  * `scan_then_exploit` — port scan followed by exploitation attempt (T1190, cross-device)
  * `dns_tunnel_exfil` — DNS tunneling paired with data exfiltration (T1048.001)
* **Sliding Time Windows:** Each rule has its own window (5–15 min) and minimum event count.
* **Cross-Device vs Single-Device Scoping:** Rules declare whether events must share a device_id.
* **Confidence Scoring:** 0.5 + (event_count × 0.1), capped at 1.0.
* **Cooldowns:** 300 s per rule+scope to prevent duplicate incidents during a sustained attack.
* **IR Feedback Loop:** Correlated incidents feed back into the incident response engine as `source=correlation` events, so a `multi_device_campaign` can trigger `block_ip` + `quarantine` automatically.
* **REST Endpoint:** `/api/correlations?limit=50` returns active + historical correlated incidents as JSON.
* **v3.1.1 hardening:** **Callback deadlock fixed** — alert callback was previously invoked while holding the correlator's mutex. Since the callback calls `ir_engine->report_incident()` (which takes its own mutex), this was a latent lock-ordering deadlock that also froze the correlator if the callback was slow. Alerts are now queued locally and fired after the mutex is released.

---

## 🛡 v3.1.1 Security Audit (April 2026)

Seven-round audit of the entire codebase. All fixes are backward-compatible and require no config or protocol changes.

### Critical fixes

| # | Severity | Component | Description |
|---|---|---|---|
| 1 | **Critical** | `incident_response.h` | Shutdown deadlock — drain loop held the engine mutex while calling `execute_action()`, which re-acquires the same mutex for `ACT_BLOCK_IP` and `ACT_QUARANTINE`. Server would hang on SIGTERM. |
| 2 | **High** | `correlation_engine.h` | Alert callback invoked while holding `mutex_`. Since the callback calls `ir_engine->report_incident()` (its own mutex), this was a lock-ordering deadlock risk and froze the correlator on slow callbacks. |
| 3 | **High** | `fim_common.h` + `fim_scanner.h` | TOCTOU race — `fs::file_size()` check and the subsequent `sha256_file()` open were two separate syscalls, so a file could be swapped between them. Now single-open with streaming size enforcement. |
| 4 | **High** | `server.cpp` + `client.cpp` | TLS downgrade exposure — server did not pin TLS 1.2, disable SSLv2/3, or restrict ciphers. Now both sides pin TLS 1.2+, disable compression, disable renegotiation, and use only AEAD ciphers (AES-GCM, ChaCha20-Poly1305). |
| 5 | **High** | `dashboard_html.h` | Stored XSS — every dashboard table interpolated DB fields directly into `innerHTML`. A compromised endpoint could inject `<script>` into a log line that would execute in the admin's browser. All 4 tables now HTML-escape every user-controlled field. |

### DoS / hardening controls added

1. REST API `limit=` clamped to `[1, 1000]` on all 6 query endpoints
2. SQL INTERVAL parameter clamped to `[1, 86400]` seconds
3. HTTP parser recv iteration cap (1024) — slowloris protection
4. HTTP parser header count cap (100)
5. HTTP parser header length cap (8 KB each)
6. HTTP parser request line cap (8 KB)
7. HTTP parser Content-Length range check with exception-safe parse
8. Threat intel feed loader: 5M entries / 8 KB line / 2 KB field / 16 columns
9. Rules.conf loader: 10K rules / 8 KB line / 4 KB pattern
10. Regex engine input line cap (4 KB) — ReDoS protection
11. Regex engine wraps `regex_search` in try/catch
12. CIDR prefix parse wrapped in try/catch with safe default

### Code-quality cleanups

* 30+ struct members given in-class default initializers (MSVC `/analyze` C26495)
* Wire-protocol POD structs (`PacketHeader`, `PacketHeaderV2`, `RawTelemetry`, `HeartbeatPayload`) zero-initialized by default
* Signal handlers: `(void)sig;` to silence unused-parameter warnings
* 4 ignored `std::rename()` return values explicitly cast to `(void)`
* `config_file.h` gained a `get_int_clamped(key, default, min, max)` helper
* Fixed case-sensitivity bug (`IOC_IP` → `IoC_IP`) that prevented clean build

---

## 🏗 Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                         ENDPOINTS (Clients)                           │
│  ┌───────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌───────────┐ │
│  │ Telemetry │ │ Log Scrp │ │ FIM Scan │ │ Process  │ │ Conn Inv  │ │
│  │ CPU/RAM/  │ │ Win Evt/ │ │ SHA-256  │ │ Enum +   │ │ TCP/UDP   │ │
│  │ Disk/Net  │ │ syslog   │ │ Recurse  │ │ Suspicio │ │ Listening │ │
│  └────┬──────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ └─────┬─────┘ │
│       │             │            │            │             │        │
│  ┌────▼──────┐ ┌────▼────────────▼────────────▼─────────────▼──┐    │
│  │ Session   │ │          mTLS 1.2+ / HMAC-SHA256 (v2)         │    │
│  │ + Auth    │ │    MSG_TELEMETRY  MSG_HEARTBEAT  MSG_FIM      │    │
│  │ tracker   │ │    MSG_PROCESS    MSG_CONN       MSG_SESSION  │    │
│  │           │ │    MSG_SOFTWARE                                │    │
│  └────┬──────┘ └────────────────────┬──────────────────────────┘    │
│       │ ┌──────────┐                │                                │
│       │ │ Software │                │                                │
│       └─┤ Inventory│                │                                │
│         └──────────┘                │                                │
└─────────────────────────────────────┼────────────────────────────────┘
                                      │
┌─────────────────────────────────────┼────────────────────────────────┐
│                           SERVER (Central)                           │
│                                     ▼                                │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │                      Message Dispatcher                        │  │
│  └───┬─────────┬─────────┬─────────┬─────────┬─────────┬─────────┘  │
│      ▼         ▼         ▼         ▼         ▼         ▼             │
│  ┌─────────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────────────┐   │
│  │ Regex + │ │ FIM  │ │ Proc │ │ Conn │ │ Sess │ │ Software Inv │   │
│  │ Alert   │ │ Mon  │ │ Proc │ │ Proc │ │ Proc │ │ Processor    │   │
│  └────┬────┘ └──┬───┘ └──┬───┘ └──┬───┘ └──┬───┘ └──────┬───────┘   │
│       └────┬────┴────────┴────────┴────────┴────────────┘            │
│            ▼                                                         │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │  Traffic Classifier  │  Threat Intel  │  Network Inspector    │  │
│  │  (6 attack cats)     │  (7 IoC types) │  (DNS/Proto/Entropy)  │  │
│  └──────────┬─────────────────┬──────────────────┬───────────────┘  │
│             └─────────────────┼──────────────────┘                   │
│                               ▼                                      │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │              Correlation Engine (Phase 15)                     │  │
│  │   7 rules · sliding windows · cross-device · kill-chain logic  │  │
│  └──────────┬──────────────────────────────────┬──────────────────┘  │
│             ▼                                  ▼                      │
│  ┌──────────────────────┐       ┌─────────────────────────────────┐  │
│  │  Fleet Manager (9)   │       │ Incident Response Engine (8)    │  │
│  │  Device inventory,   │◄──────┤ 7 playbooks · IP blocklist ·    │  │
│  │  health scoring      │       │ quarantine · async worker       │  │
│  └──────────────────────┘       └──────────────┬──────────────────┘  │
│             ▼                                  ▼                      │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │                         PostgreSQL                              │  │
│  │ telemetry │ security_events │ threat_detections │ ioc_matches  │  │
│  │              │ fim_events (schema auto-created)                 │  │
│  └────────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │             REST API Server (Phase 7) · Port 8080               │  │
│  │   Bearer token auth · 10 endpoints · Web dashboard (SPA)        │  │
│  │   v3.1.1: slowloris caps, header limits, limit clamping, XSS    │  │
│  │   escaping on all user-rendered fields                          │  │
│  └────────────────────────────────────────────────────────────────┘  │
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
| **File Tampering** | SHA-256 FIM with per-device baselines + TOCTOU-safe hashing |
| **Malicious Processes** | Process monitor with built-in suspicious-tool library |
| **Rogue Connections** | TCP/UDP inventory with reverse-shell port flagging |
| **Credential Compromise** | Session + auth tracker with correlation of brute-force → login |
| **Unauthorized Software** | Software inventory with change detection |
| **Multi-Stage Attacks** | 7-rule correlation engine linking events across devices |
| **Automated Containment** | IR playbooks with IP blocking + device quarantine |
| **DNS Tunneling / DGA** | Entropy + structural DNS analysis |
| **Encrypted C2** | Shannon entropy analysis on payload data |
| **TLS Downgrade** *(v3.1.1)* | TLS 1.2+ pinned, SSLv2/3/TLS1.0/1.1 disabled, modern ciphers only |
| **HTTP Slowloris** *(v3.1.1)* | Recv iteration cap + Content-Length bounds check |
| **Dashboard XSS** *(v3.1.1)* | HTML-escape all database-sourced fields before `innerHTML` |
| **Memory Exhaustion** *(v3.1.1)* | Feed / rules loader caps (entries, line, field, column) |
| **API DoS** *(v3.1.1)* | All `limit=` query params clamped to `[1, 1000]` |
| **ReDoS** *(v3.1.1)* | Input lines capped at 4 KB before regex evaluation |

---

## 📂 Repository Structure

Source files are split into `src/server/` and `src/client/`. Six headers used by both targets are duplicated into each directory so the two can be compiled independently.

```
SecureSeaHorse-v3.0.0/
├── CMakeLists.txt              # Build configuration (v3.0.0)
├── README.md
├── LICENSE.txt
├── .gitignore
│
├── src/
│   ├── server/                 # Server sources (22 files)
│   │   ├── server.cpp                   # Main entry
│   │   ├── server_protocol.h            # Wire protocol + thread pool
│   │   ├── alert_engine.h               # Threshold alerting (Phase 2)
│   │   ├── baseline_tracker.h           # EWMA baselines (Phase 4)
│   │   ├── correlation_engine.h         # Cross-device correlation (Phase 15)
│   │   ├── dashboard_html.h             # Web dashboard SPA (Phase 7)
│   │   ├── db_layer.h                   # PostgreSQL persistence
│   │   ├── fim_monitor.h                # Server-side FIM processor (Phase 6)
│   │   ├── fleet_manager.h              # Device inventory (Phase 9)
│   │   ├── incident_response.h          # Playbook engine (Phase 8)
│   │   ├── mitre_map.h                  # MITRE ATT&CK mappings
│   │   ├── network_inspector.h          # DNS/proto/entropy (Phase 10)
│   │   ├── regex_engine.h               # Log pattern matching (Phase 2)
│   │   ├── rest_server.h                # Embedded HTTP server (Phase 7)
│   │   ├── threat_intel.h               # IoC feed engine (Phase 5)
│   │   ├── traffic_classifier.h         # 6-category detection (Phase 4)
│   │   └── [shared] crypto_utils.h, fim_common.h, process_monitor.h,
│   │               connection_inventory.h, session_tracker.h,
│   │               software_inventory.h
│   │
│   └── client/                 # Client sources (9 files)
│       ├── client.cpp                   # Main entry + all scanners
│       ├── client_protocol.h            # Wire protocol + backoff
│       ├── fim_scanner.h                # Client-side FIM (Phase 6)
│       └── [shared] crypto_utils.h, fim_common.h, process_monitor.h,
│                   connection_inventory.h, session_tracker.h,
│                   software_inventory.h
│
├── config/
│   ├── server.conf             # Server configuration (all 15 phases)
│   ├── client.conf             # Client configuration (all agent modules)
│   ├── rules.conf              # Regex analysis rules
│   └── feeds/                  # Threat intelligence feed CSVs
│
├── certs/                      # mTLS certificates (gitignored)
│   ├── ca.pem
│   ├── server.pem / server-key.pem
│   └── client.pem / client-key.pem
│
├── scripts/                    # Incident response scripts
│
├── installer/
│   ├── install_linux.sh        # Full installer (build/install/certs/uninstall)
│   └── installer_windows.nsi   # NSIS script for Windows Setup.exe
│
└── docs/
    └── USER_MANUAL.md          # 900-line operations manual
```

---

## 📦 Database Schema

All tables are auto-created on server start (`CREATE TABLE IF NOT EXISTS`).

| Table | Phase | Purpose | Key Columns |
| :--- | :--- | :--- | :--- |
| `telemetry` | 2 | Raw device metrics | device_id, CPU, RAM, disk, network, logs |
| `security_events` | 2 | Regex-matched log events | device_id, rule_name, severity, matched_text |
| `threat_detections` | 4 | Traffic classifier alerts | category, sub_type, confidence, MITRE ID |
| `ioc_matches` | 5 | Threat intel feed hits | ioc_type, ioc_value, feed_source, MITRE ID |
| `fim_events` | 6 | File integrity changes | change_type, file_path, old/new hash, severity |

Client-side inventory data (processes, connections, sessions, software) and server-side correlation incidents are currently kept in-memory and exposed via the REST API. PostgreSQL persistence for those tables is on the v3.5 roadmap.

---

## 📡 Wire Protocol Message Types

| Msg Type | Hex | Direction | Phase | Description |
| :---: | :---: | :---: | :---: | :--- |
| TELEMETRY | 0x00 | C → S | 1 | Core metrics + log chunk |
| HEARTBEAT_PING | 0x01 | C → S | 3 | Signed keep-alive |
| HEARTBEAT_PONG | 0x02 | S → C | 3 | Signed keep-alive reply |
| FIM_REPORT | 0x03 | C → S | 6 | File integrity snapshot + diff |
| PROCESS_REPORT | 0x04 | C → S | 11 | Running processes + suspicious |
| CONN_REPORT | 0x05 | C → S | 12 | TCP/UDP connection inventory |
| SESSION_REPORT | 0x06 | C → S | 13 | Sessions + auth events |
| SOFTWARE_REPORT | 0x07 | C → S | 14 | Installed software + changes |

---

## 📋 Prerequisites

* **C++17** compiler (MSVC 2019+, GCC 9+, Clang 7+)
* **OpenSSL 3.0+** (required for HMAC, OCSP, SHA-256 hashing, TLS 1.2+)
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

### One-Shot Installer (Linux)

```bash
# Build from source and install both server + client as systemd services
sudo ./installer/install_linux.sh build

# Generate self-signed TLS certs for testing
sudo ./installer/install_linux.sh certs

# Or install server/client separately
sudo ./installer/install_linux.sh server
sudo ./installer/install_linux.sh client
```

### Windows Installer

```powershell
# Build the installer .exe (requires NSIS)
cd installer
makensis installer_windows.nsi
# Produces SecureSeaHorse-v3.0.0-Setup.exe
```

The Windows installer creates services (`SeaHorseServer`, `SeaHorseClient`), opens firewall ports (9443, 8080), and adds Start Menu shortcuts.

---

## ⚙️ Quick Start

### 1. Generate Certificates

```bash
# CA
openssl req -x509 -newkey rsa:4096 -keyout ca.key -out ca.pem -days 365 -nodes -subj "/CN=SeaHorseCA"

# Server
openssl req -newkey rsa:2048 -keyout server-key.pem -out server.csr -nodes -subj "/CN=server"
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.pem -days 365

# Client
openssl req -newkey rsa:2048 -keyout client-key.pem -out client.csr -nodes -subj "/CN=agent001"
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out client.pem -days 365
```

### 2. Configure & Run

```bash
# Edit configs
vi config/server.conf   # Set cert paths, DB credentials, alert thresholds, API token
vi config/client.conf   # Set server_ip, device_id, FIM watch paths

# Start server
./SeaHorseServer --config config/server.conf

# Start client (on each endpoint)
./SeaHorseClient --config config/client.conf

# Open the dashboard
open http://localhost:8080/      # Enter your rest_api_token at the login prompt
```

### 3. Add Threat Intel Feeds

Drop `.csv` files into the `feeds/` directory. Format:
```
# type | value | severity | description | mitre_id | tags
ip     | 198.51.100.23 | critical | C2 server | T1071.001 | c2,apt
domain | evil.com      | high     | Phishing   | T1566.002 | phishing
```

Feeds auto-reload every 5 minutes (configurable via `feeds_reload_interval_s`). Loader caps enforce 5M entries, 8 KB/line, 2 KB/field.

### 4. Try the REST API

```bash
TOKEN="your-api-token-from-server.conf"

# System stats
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/stats | jq .

# Recent threats
curl -H "Authorization: Bearer $TOKEN" "http://localhost:8080/api/threats?limit=20"

# Fleet inventory
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/devices

# Cross-device correlated incidents
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/correlations
```

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
| 1.6.0 | 6 | File Integrity Monitoring, per-device baselines, SHA-256 |
| 1.7.0 | 7 | REST API, web dashboard, JSON query layer, bearer auth |
| 1.8.0 | 8 | Incident response automation, playbooks, IP blocklist |
| 1.9.0 | 9 | Agent fleet management, device inventory, health scoring |
| 2.0.0 | 10 | Network deep inspection, DNS analysis, entropy detection |
| 2.1.0 | 11 | Process monitor, parent-child tracking, suspicious detection |
| 2.2.0 | 12 | Connection inventory, TCP/UDP scanning, reverse-shell ports |
| 2.3.0 | 13 | Session/auth tracker, SSH/RDP visibility, sudo tracking |
| 2.4.0 | 14 | Software inventory, dpkg/rpm/registry, change detection |
| 2.5.0 | 15 | Correlation engine, 7 kill-chain rules, cross-device linking |
| 3.0.0 | 15 | Split `src/server` + `src/client`, installers, user manual |
| **3.1.1** | — | **Security audit: 5 critical fixes, 12 DoS-hardening controls** |

---

## 🗺 Roadmap (Phases 16–25)

| Phase | Feature | Target |
|-------|---------|--------|
| 16 | **Sigma Rule Engine** — import and evaluate community Sigma YAML detection rules | v3.5 |
| 17 | **Agent Self-Protection & Auto-Update** — tamper detection, watchdog, signed updates | v3.5 |
| 18 | **Reporting & Compliance** — scheduled PDF/HTML reports (PCI-DSS, HIPAA, SOC 2) | v3.5 |
| 19 | **USB & Peripheral Monitor** — device insertion detection, whitelist enforcement | v4.0 |
| 20 | **Multi-Tenancy & RBAC** — tenant isolation, 4 roles, JWT auth, audit log | v4.0 |
| 21 | **SOAR Integration** — bidirectional Splunk SOAR / Cortex XSOAR / TheHive hooks | v4.0 |
| 22 | **Syslog Ingestion & Forwarding** — RFC 5424 listener, CEF/LEEF output | v4.5 |
| 23 | **Threat Hunting Query Language** — SPL-like DSL, saved searches, CSV export | v4.5 |
| 24 | **ML Anomaly Detection** — isolation forest + beaconing scorer (pure C++) | v4.5 |
| 25 | **Full React Web UI** — multi-page SPA, WebSocket live stream, incident workflow | v5.0 |

---

## 📜 License

This project is proprietary. All rights reserved.
