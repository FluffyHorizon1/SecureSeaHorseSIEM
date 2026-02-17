# SecureSeaHorse SIEM — Phase 5 Changelog

## Version 1.5.0 — Threat Intelligence Feeds

### Summary

Phase 5 adds a real-time threat intelligence engine that matches incoming telemetry against Indicator of Compromise (IoC) feeds. The engine loads CSV feed files from a configurable directory, extracts IPs, domains, file hashes, URLs, and emails from log chunks using regex, and performs O(1) hash-map lookups against loaded indicators. Feeds auto-reload on file modification without server restart. Every IoC hit is persisted to PostgreSQL and tagged with the originating feed source and MITRE ATT&CK technique ID.

---

### Capabilities

**Supported IoC Types (7):**

| Type | Lookup Method | Extraction From Logs |
|---|---|---|
| IP Address | O(1) hash map | IPv4 regex extraction |
| CIDR Range | Linear scan (typically small) | Matched against extracted IPs |
| Domain | O(1) exact + suffix matching | FQDN regex extraction |
| File Hash | O(1) hash map (MD5/SHA1/SHA256) | 32/40/64 hex char regex |
| URL | O(1) hash map | `http(s)://` pattern extraction |
| Email | O(1) hash map | Email address regex |
| User Agent | Substring search | Direct field comparison |

**Feed Features:**
- Pipe-delimited CSV format (consistent with `rules.conf`)
- Comments (`#`) and blank lines supported
- Case-insensitive matching (all values normalized to lowercase)
- Subdomain matching: feed entry `evil.com` matches `sub.evil.com`
- CIDR range support: feed entry `5.188.86.0/24` matches any IP in that range
- Deduplication: same IoC from multiple feeds uses last-loaded entry

**Runtime Features:**
- Auto-reload: polls feed directory every N seconds for file modifications
- Hot-add: drop a new `.csv` into the feeds directory — loaded on next check
- Read-write lock: concurrent matching continues uninterrupted during reload
- Feed directory auto-created if it doesn't exist

---

### Architecture

**New files (4):**

1. **`threat_intel.h`** — Complete threat intelligence engine in a single header:
   - `IoCStore`: Hash-map backed indicator database with per-type lookup methods
   - `ThreatIntelEngine`: Feed management, log extraction, matching, auto-reload
   - CIDR range parsing and matching
   - Regex-based indicator extraction from raw log text
   - `std::shared_mutex` for lock-free concurrent reads during matching

2. **`feeds/malicious_ips.csv`** — Sample feed: 14 known-bad IPs + 2 CIDR ranges
3. **`feeds/malicious_domains.csv`** — Sample feed: 17 known-bad domains
4. **`feeds/malicious_hashes.csv`** — Sample feed: 14 known-bad file hashes

**Updated files (3):**

5. **`db_layer.h`** — Added `ioc_matches` table and `insert_ioc_match()` method
6. **`server.cpp`** — Integrated threat intel matching into processing pipeline
7. **`server.conf`** — Added Phase 5 config keys

---

### Feed File Format

```
# Comment lines start with #
# Format: type | value | severity | description | mitre_id | tags
ip     | 198.51.100.23      | critical | Cobalt Strike C2 server     | T1071.001 | c2,cobaltstrike
domain | evil-update.com     | critical | APT28 C2 domain             | T1071.001 | apt28,c2
hash   | 7b2e5f0c8a1d...    | critical | WannaCry ransomware         | T1486     | ransomware,wannacry
cidr   | 5.188.86.0/24       | high     | Bulletproof hosting block   | T1583.003 | bulletproof
url    | http://malware.com  | high     | Malware download URL        | T1204.001 | malware
email  | phisher@evil.com    | medium   | Known phishing sender       | T1566.001 | phishing
```

**Fields:**
- `type` (required): ip, domain, hash, cidr, url, email, useragent
- `value` (required): The indicator value
- `severity` (optional, default "high"): low, medium, high, critical
- `description` (optional): Human-readable explanation
- `mitre_id` (optional): MITRE ATT&CK technique ID
- `tags` (optional): Comma-separated labels for grouping

---

### Processing Pipeline (Updated)

```
Telemetry → Decode → CPU calc → Regex scan → DB persist events → Alert eval
  → Traffic classify → DB persist threats
  → IoC match → DB persist matches → Log IoC hits
  → CSV → Standard log
```

The threat intel engine runs **after** the traffic classifier so both detection systems can fire independently on the same report.

---

### Database Schema Addition

```sql
ioc_matches
├── id (BIGSERIAL PK)
├── device_id, timestamp_ms, machine_ip
├── ioc_type (VARCHAR 32) — "ip", "domain", "hash", etc.
├── ioc_value (VARCHAR 256) — The matched indicator
├── severity, feed_source, matched_in
├── mitre_id, description, tags
└── received_at (TIMESTAMPTZ, auto)

Indexes:
├── idx_ioc_device_ts (device_id, timestamp_ms DESC)
├── idx_ioc_type      (ioc_type, received_at DESC)
└── idx_ioc_feed      (feed_source, received_at DESC)
```

---

### Configuration Reference

```ini
# Master switch
threat_intel_enabled = true

# Feed directory (all .csv files loaded automatically)
feeds_dir = feeds

# Auto-reload interval (0 = disabled)
feeds_reload_interval_s = 300
```

---

### Server Log Output

IoC matches are logged with color-coded severity:

```
[IoC HIT] device=1001 ip=10.0.0.5 | ip=198.51.100.23 | critical | feed=malicious_ips | found_in=log_chunk_ip | MITRE T1071.001 | Cobalt Strike C2 server
```

---

### Creating Custom Feeds

1. Create a `.csv` file in the `feeds/` directory
2. Use pipe-delimited format: `type | value | severity | description | mitre_id | tags`
3. The feed is auto-loaded on next reload check (default every 5 minutes)
4. To force immediate reload, restart the server

**Recommended feed sources to convert:**
- abuse.ch (URLhaus, MalwareBazaar, ThreatFox)
- AlienVault OTX pulse exports
- Emerging Threats blocklists
- MISP CSV exports

---

### Migration Guide from v1.4.0

1. **New files to add:**
   - `threat_intel.h` → alongside other server headers
   - `feeds/` directory with sample `.csv` files

2. **Updated files (replace in-place):**
   - `db_layer.h` — added `ioc_matches` table + insert method
   - `server.cpp` — integrated threat intel into processing pipeline
   - `server.conf` — added Phase 5 config keys

3. **No new dependencies.** Uses C++17 `<filesystem>` (already required by the toolchain) and `<shared_mutex>`.

4. **No protocol changes.** Client-side files unchanged from Phase 3.

5. **Database migration:** Auto-created on server start (`CREATE TABLE IF NOT EXISTS`).

6. **C++17 requirement:** `threat_intel.h` uses `std::filesystem` and `std::shared_mutex`. Ensure your compiler flags include `-std=c++17` (CMake: `set(CMAKE_CXX_STANDARD 17)`).

---

### Version History

| Version | Phase | Highlights |
|---------|-------|------------|
| 1.0.1 | — | Initial release: mTLS, binary protocol, CSV output |
| 1.1.0 | 1 | Thread pool, backoff, CLI, async logger |
| 1.2.0 | 2 | PostgreSQL, regex engine, threshold alerting |
| 1.3.0 | 3 | HMAC-SHA256, heartbeat, CRL/OCSP, cert pinning |
| 1.4.0 | 4 | Traffic classification, 6 attack categories, MITRE ATT&CK |
| 1.5.0 | 5 | Threat intelligence feeds, IoC matching, auto-reload |
