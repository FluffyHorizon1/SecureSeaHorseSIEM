# SecureSeaHorse SIEM — Phase 2 Changelog

## Version 1.2.0 — Data Intelligence

### Summary

Phase 2 adds three data intelligence subsystems to the server: PostgreSQL persistence, a regex-based log analysis engine, and log-based threshold alerting. All changes are backward-compatible — CSV output continues to work, and the on-wire protocol is unchanged.

---

### 1. PostgreSQL Persistence (`db_layer.h`, `server.cpp`)

**Problem:** Telemetry and security events were written to a flat CSV with no schema, no indexing, and no query capability.

**Solution:** PostgreSQL-backed persistence with auto-schema creation and parameterized queries.

**Schema — two tables:**

```
telemetry
├── id (BIGSERIAL PK)
├── device_id, timestamp_ms
├── machine_name, machine_ip, os_user
├── cpu_usage_pct, ram_total/avail, disk_total/free, net_in/out
└── received_at (TIMESTAMPTZ, auto)

security_events
├── id (BIGSERIAL PK)
├── device_id, timestamp_ms, machine_ip
├── rule_name, severity, category, matched_text
└── received_at (TIMESTAMPTZ, auto)
```

**Key behaviors:**
- Tables and indexes created automatically on first connect (`CREATE TABLE IF NOT EXISTS`).
- All INSERTs use `PQexecParams` (parameterized) to prevent SQL injection.
- Auto-reconnect: if the connection drops mid-session, the next INSERT attempts one reconnect.
- Connection timeout of 5 seconds prevents the server from blocking on a dead DB.
- CSV output continues in parallel — set `csv_output = none` to disable.

**Config keys:**
```
db_enabled  = true
db_host     = 127.0.0.1
db_port     = 5432
db_name     = seahorse
db_user     = seahorse
db_pass     =
```

**New dependency:** `libpq` (PostgreSQL client library). Link with `-lpq` on Linux or `libpq.lib` on Windows.

**Files added:** `db_layer.h`
**Files changed:** `server.cpp` (integration), `server_protocol.h` (added `get_bool()`)

---

### 2. Regex-Based Log Analysis Engine (`regex_engine.h`, `rules.conf`)

**Problem:** The Phase 1 `count_failed_logins()` used basic `string::find()` against four hardcoded signatures. It couldn't distinguish event types, assign severity, or support user-defined patterns.

**Solution:** Full regex engine using `<regex>` (C++11 STL) with 18 built-in detection rules and a user-overrideable rules file.

**Built-in rules (18 total):**

| Category | Rules | Severity |
|---|---|---|
| auth_failure | ssh_failed_password, pam_auth_failure, sshd_invalid_user, win_logon_failure_4625, win_logon_failure_generic, su_failed | high/medium |
| privilege_escalation | sudo_failed, sudo_session_open, win_priv_escalation_4672 | critical/low/medium |
| brute_force | sshd_max_auth_exceeded, sshd_connection_reset | critical/medium |
| service_failure | service_start_failed | medium |
| resource_exhaustion | oom_killer | critical |
| crash | segfault | high |
| account_lockout | win_account_locked_4740 | high |
| account_change | win_password_changed_4723 | low |
| firewall | iptables_drop, ufw_block | medium |

**User rules file (`rules.conf`):**
```
# Format: name | severity | category | regex_pattern
vpn_auth_failure | high | auth_failure | vpn.*authentication failed for user\s+\S+
```

- Rules with the same name as a built-in **override** the built-in.
- The rules file is optional — if missing, only built-ins are used.
- Patterns are compiled at startup with `icase` and `optimize` flags.
- Each log line is tested against every rule — a line can trigger multiple rules.

**Output:** `SecurityEvent { rule_name, severity, category, matched_text }` — fed to both the database and the alert engine.

**Config keys:**
```
rules_file = rules.conf
```

**Files added:** `regex_engine.h`, `rules.conf`
**Files changed:** `server.cpp` (replaces `count_failed_logins()`)

---

### 3. Log-Based Threshold Alerting (`alert_engine.h`, `server.cpp`)

**Problem:** No mechanism to detect and escalate when event counts exceed safe thresholds (e.g., 5 failed logins from the same device in 5 minutes).

**Solution:** Per-device, per-category sliding window alerting with cooldown, writing to a dedicated alert log.

**How it works:**
- Events from the regex engine are fed to `AlertEngine::ingest()`.
- Each event is recorded in a per-device, per-category timeline.
- Old events outside the time window are pruned on each check.
- When the count within the window reaches the threshold, an alert fires.
- After firing, a cooldown period prevents repeat alerts for the same device+category.
- The event window is cleared after firing to prevent immediate re-trigger.

**Default thresholds:**

| Category | Count | Window | Cooldown |
|---|---|---|---|
| auth_failure | 5 | 300s | 600s |
| brute_force | 3 | 60s | 300s |
| privilege_escalation | 2 | 120s | 600s |
| account_lockout | 1 | 60s | 900s |
| resource_exhaustion | 1 | 60s | 600s |
| crash | 2 | 300s | 600s |

**Alert log format:**
```
[2026-02-15 14:30:00] [ALERT] device=7001 ip=10.0.0.5 category=auth_failure severity=high rule=ssh_failed_password count=5/5 window=300s | Failed password for admin from 10.0.0.5
```

**Config keys:**
```
alert_enabled = true
alert_log     = alerts.log

# Override specific thresholds: count,window_sec,cooldown_sec
alert_threshold_auth_failure = 5,300,600
alert_threshold_brute_force  = 3,60,300
```

**Files added:** `alert_engine.h`
**Files changed:** `server.cpp` (integration into processing pipeline)

---

### Migration Guide from v1.1.0

1. **New dependencies:**
   - `libpq-dev` (Debian/Ubuntu: `sudo apt install libpq-dev`)
   - Link: add `-lpq` to your CMake or compile command
   - If you don't want PostgreSQL, set `db_enabled = false` in server.conf

2. **New files to add to your project:**
   - `db_layer.h` → `src/server/` (alongside server_protocol.h)
   - `regex_engine.h` → `src/server/`
   - `alert_engine.h` → `src/server/`
   - `rules.conf` → `config/` (alongside server.conf)

3. **Updated files (replace in-place):**
   - `server_protocol.h` — added `get_bool()` helper
   - `server.cpp` — integrated all three subsystems
   - `server.conf` — added Phase 2 config keys (backward-compatible)

4. **Database setup (one-time):**
   ```bash
   sudo -u postgres createuser seahorse
   sudo -u postgres createdb -O seahorse seahorse
   ```
   Tables are created automatically on first server start.

5. **No protocol changes:** The on-wire binary format is identical. v1.2.0 servers accept v1.0.1 and v1.1.0 clients without modification.

6. **client.cpp and client_protocol.h are unchanged from Phase 1.** No client-side changes needed.

---

### CMakeLists.txt Addition

Add to your existing CMake:
```cmake
find_package(PostgreSQL REQUIRED)
target_include_directories(ssh_server PRIVATE ${PostgreSQL_INCLUDE_DIRS})
target_link_libraries(ssh_server PRIVATE ${PostgreSQL_LIBRARIES})
```

Or manually: `g++ ... -I/usr/include/postgresql -lpq`
