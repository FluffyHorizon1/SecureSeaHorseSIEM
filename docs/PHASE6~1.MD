# SecureSeaHorse SIEM — Phase 6 Changelog

## Version 1.6.0 — File Integrity Monitoring (FIM)

### Summary

Phase 6 adds full-stack File Integrity Monitoring. The client periodically scans configured directories, computes SHA-256 hashes of each file, and sends a FIM snapshot to the server over TLS using a new `MSG_FIM_REPORT` message type. The server maintains per-device baselines and detects file additions, modifications, and deletions. Each change is classified by severity (based on file path criticality), tagged with MITRE ATT&CK technique IDs, persisted to PostgreSQL, and logged at the appropriate level.

---

### Architecture

**Client-side (scanner):**
1. Recursively walks configured watch paths
2. Computes SHA-256 hash of every file (via OpenSSL EVP API)
3. Builds a `FimReport` with all entries
4. Serializes and sends to server as `MSG_FIM_REPORT` (v2 protocol)
5. Maintains local baseline for change logging

**Server-side (monitor):**
1. Deserializes incoming `FimReport`
2. Compares against stored per-device baseline
3. Detects additions, modifications, deletions
4. Classifies severity by matching file path against critical/high patterns
5. Tags with MITRE ATT&CK technique
6. Persists to `fim_events` table
7. Logs with color-coded severity

---

### New Files (3)

| File | Lines | Description |
|---|---|---|
| `fim_common.h` | ~170 | Shared types: `FimEntry`, `FimReport`, `FimChange`, serialization, `sha256_file()` |
| `fim_scanner.h` | ~240 | Client scanner: recursive walk, hashing, diff, exclusions, limits |
| `fim_monitor.h` | ~230 | Server monitor: per-device baselines, severity classification, MITRE tagging |

### Updated Files (6)

| File | Change |
|---|---|
| `crypto_utils.h` | Added `MSG_FIM_REPORT = 0x03` to `MsgType` enum |
| `client.cpp` | FIM scanner init, `send_fim_report()`, periodic scan in main loop |
| `client.conf` | Phase 6 config keys (watch paths, exclusions, limits) |
| `server.cpp` | `process_fim_report()`, `MSG_FIM_REPORT` dispatch, FIM monitor init |
| `server.conf` | Phase 6 config keys (severity paths, default severity) |
| `db_layer.h` | `fim_events` table, `insert_fim_event()` method, 3 new indexes |

---

### Wire Protocol

New message type `MSG_FIM_REPORT = 0x03` sent over the existing v2 protocol:

```
PacketHeaderV2 (44 bytes, msg_type=0x03, HMAC signed)
Payload (text, variable length):
  FIM|<device_id>|<timestamp_ms>|<entry_count>
  <path>|<sha256>|<size_bytes>|<mtime_epoch>
  <path>|<sha256>|<size_bytes>|<mtime_epoch>
  ...
  FIM_END
```

---

### Detection Logic

**Change Types:**

| Type | Trigger | MITRE (critical path) | MITRE (other) |
|---|---|---|---|
| Added | File exists in scan but not baseline | T1505.003 Persistence | T1074 Collection |
| Modified | File exists in both but SHA-256 differs | T1565.001 Impact | T1027 Defense Evasion |
| Deleted | File in baseline but missing from scan | T1070.004 Defense Evasion | T1070.004 Defense Evasion |

**Severity Classification:**

Built-in critical paths (changes always `critical`):
- `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/ssh/sshd_config`
- `/boot/`, `/usr/sbin/`, `/etc/crontab`, `/etc/pam.d/`
- `System32\config\`, `System32\drivers\`, `\Windows\System32\`

Built-in high paths (changes always `high`):
- `/etc/nginx/`, `/etc/apache2/`, `/var/www/`, `/etc/systemd/`
- `\inetpub\`, `\Program Files\`, `\ProgramData\`

Everything else uses `fim_default_severity` (default: `medium`).

User-configurable additional patterns via `fim_critical_paths` and `fim_high_paths`.

---

### Database Schema

```sql
fim_events
├── id (BIGSERIAL PK)
├── device_id, timestamp_ms, machine_ip
├── change_type (VARCHAR 16) — "added", "modified", "deleted"
├── file_path (VARCHAR 512)
├── old_hash, new_hash (VARCHAR 64)
├── old_size, new_size (BIGINT)
├── severity, mitre_id, description
└── received_at (TIMESTAMPTZ, auto)

Indexes:
├── idx_fim_device_ts (device_id, timestamp_ms DESC)
├── idx_fim_change    (change_type, received_at DESC)
└── idx_fim_path      (file_path, received_at DESC)
```

---

### Client Configuration Reference

```ini
fim_enabled         = true
fim_scan_interval_s = 300          # Scan every 5 minutes
fim_watch_paths     = /etc,/usr/sbin,/boot    # Comma-separated
fim_exclude_ext     = .tmp,.log,.swp           # Skip these extensions
fim_max_file_size   = 104857600    # 100MB — skip larger files
fim_max_files       = 50000        # Safety cap per scan
fim_max_depth       = 20           # Max directory recursion
```

### Server Configuration Reference

```ini
fim_enabled          = true
fim_default_severity = medium
fim_critical_paths   = /opt/myapp/config     # Additional critical patterns
fim_high_paths       = /opt/myapp/data       # Additional high patterns
```

---

### Migration Guide from v1.5.0

1. **New files (3):** `fim_common.h`, `fim_scanner.h`, `fim_monitor.h` → `src/` alongside other headers

2. **Updated files (6) — replace in-place:**
   - `crypto_utils.h` — new message type
   - `client.cpp`, `client.conf` — scanner integration
   - `server.cpp`, `server.conf` — monitor integration
   - `db_layer.h` — new table + insert method

3. **No new dependencies.** Uses OpenSSL EVP (already linked) and C++17 `<filesystem>`.

4. **Protocol change:** New `MSG_FIM_REPORT = 0x03`. Old clients (pre-Phase 6) will not send FIM reports — the server gracefully handles this (FIM monitor simply never receives data for those devices). New clients connecting to old servers will get "unknown msg_type" warnings — harmless.

5. **First scan behavior:** On the first FIM report from a device, the server establishes the baseline (no alerts). Subsequent reports generate alerts for any changes detected.

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
| 1.6.0 | 6 | File Integrity Monitoring, per-device baselines, severity classification |
