# SecureSeaHorse SIEM — Phases 16-25 Changelog

## Release Series: v3.5 → v5.0

This document covers the ten phases that extend SecureSeaHorse from the
v3.1.4 hardening baseline all the way to the v5.0 multi-tenant platform
with ML-driven detection and a full React SPA. Each phase is released in
a tagged version and is independently deployable.

| Phase | Version | Feature                                    |
|-------|---------|--------------------------------------------|
| 16    | 3.5.0   | Sigma Rule Engine                          |
| 17    | 3.5.1   | Agent Self-Protection & Auto-Update        |
| 18    | 3.5.2   | Reporting & Compliance                     |
| 19    | 4.0.0   | USB & Peripheral Monitor                   |
| 20    | 4.0.1   | Multi-Tenancy & RBAC                       |
| 21    | 4.0.2   | SOAR Integration                           |
| 22    | 4.5.0   | Syslog Ingestion & Forwarding              |
| 23    | 4.5.1   | Threat Hunting Query Language              |
| 24    | 4.5.2   | ML Anomaly Detection                       |
| 25    | 5.0.0   | Full React Web UI                          |

---

## Phase 16 — Sigma Rule Engine (v3.5.0)

### Summary

Imports community Sigma YAML detection rules and evaluates them against every
incoming event. Sigma is the open-standard for SIEM detection content so this
lets operators pull from public repositories (SigmaHQ, Elastic rules, etc.) or
write their own without recompiling.

### New files (1)

| File                        | Purpose                                 |
|-----------------------------|-----------------------------------------|
| `src/server/sigma_engine.h` | Mini YAML parser, rule loader, matcher  |

### What it does

- Loads every `*.yml` in `config/sigma_rules/` at startup
- Reloads on directory modification (auto-detect)
- Supports the subset of Sigma most detection rules actually use:
  - `logsource` filter (product, service, category)
  - `detection` selections with field modifiers
    (`|contains`, `|startswith`, `|endswith`, `|re`, `|all`)
  - `condition` expression with `AND` / `OR` / `NOT` / `1 of sel*` / `all of sel*`
  - Wildcard field names
- Extracts MITRE ATT&CK tags from `tags: attack.tNNNN`
- Returns `SigmaHit` structs that the pipeline persists and feeds to
  the correlation engine

### Config keys (server.conf)

```
sigma_enabled    = true
sigma_rules_dir  = config/sigma_rules
sigma_reload_s   = 300
```

### Wire-up

```cpp
#include "sigma_engine.h"
static std::unique_ptr<SigmaEngine> sigma;
// In main():
if (conf.get_bool("sigma_enabled", true)) {
    SigmaEngineConfig sc;
    sc.rules_dir   = conf.get("sigma_rules_dir", "config/sigma_rules");
    sc.reload_interval_s = conf.get_int("sigma_reload_s", 300);
    sigma = std::make_unique<SigmaEngine>(sc);
    logger->log(AsyncLogger::INFO,
        "Sigma: ENABLED | " + std::to_string(sigma->rule_count()) + " rules loaded");
}
// In process_report(), after regex events:
if (sigma) {
    SigmaEvent se; se.message = raw_log; se.product = "linux";
    auto hits = sigma->evaluate(se);
    for (const auto& h : hits) { /* persist + correlate */ }
}
```

---

## Phase 17 — Agent Self-Protection & Auto-Update (v3.5.1)

### Summary

Keeps the client agent running, verifies its own integrity, and can
self-update from a signed release manifest. Stops an attacker who gains
code execution on an endpoint from silently killing or tampering with the
agent.

### New files (1)

| File                           | Purpose                                     |
|--------------------------------|---------------------------------------------|
| `src/client/self_protection.h` | Tamper baseline, watchdog, signed updates   |

### What it does

- **TamperDetector** — SHA-256 baseline of the agent binary, config, and
  cert files. Re-hashes every `tamper_interval_s`. Escalates via fatal
  log if any monitored file's hash changes at runtime
- **AgentWatchdog** — dedicated thread that monitors a registered
  liveness heartbeat from the main telemetry loop. If the loop stalls
  for longer than `stall_threshold_s`, the stall callback fires
  (default: log + graceful restart signal)
- **AutoUpdater** — fetches `UpdateManifest` from a pinned URL,
  verifies its RSA-SHA256 signature against a pinned public key
  (embedded as PEM), downloads the new binary into a staging dir,
  verifies the per-file signature, and performs an atomic swap
  via `rename`. Rollback support: previous version is kept as
  `seahorse-client.prev`.

### Config keys (client.conf)

```
self_protection_enabled = true
tamper_interval_s       = 60
watchdog_stall_s        = 180
autoupdate_enabled      = false
update_manifest_url     = https://updates.securedcybersolutions.co.uk/agent.json
update_pub_key_pem      = /opt/seahorse/client/update_pubkey.pem
update_staging_dir      = /var/lib/seahorse/staging
```

---

## Phase 18 — Reporting & Compliance (v3.5.2)

### Summary

Generates scheduled PDF / HTML compliance reports mapped to PCI DSS, HIPAA,
SOC 2, and ISO 27001 control sets. Each report pulls the relevant evidence
(FIM changes on critical paths, authentication anomalies, access control
events, threat detections) and formats them with a framework-appropriate
header and control index.

### New files (1)

| File                           | Purpose                                       |
|--------------------------------|-----------------------------------------------|
| `src/server/report_generator.h`| ReportInputs/Report structs, HTML renderer    |

### What it does

- Accepts a `ReportInputs` struct: time range, framework, tenant,
  aggregated stat rollups from the DB
- `render_html()` produces a fully self-contained HTML document
  with inline CSS (no external assets — suitable for archival)
- Framework control maps for `pci`, `hipaa`, `soc2`, `iso27001`, `generic`
- `save()` writes to the configured `reports/` directory with
  `<framework>_<timestamp>.html` naming
- PDF conversion via external `wkhtmltopdf` or `weasyprint` if present
  on the host (optional — HTML is always produced)

### Config keys (server.conf)

```
reports_enabled   = true
reports_dir       = reports
reports_scheduler = cron   # or "off"
reports_frameworks = pci,hipaa,soc2
```

### REST endpoint

`POST /api/reports/generate` — body `{ "framework": "pci" }` → returns
the saved path and download URL.

---

## Phase 19 — USB & Peripheral Monitor (v4.0.0)

### Summary

Client-side USB device insertion and removal detection with optional
VID:PID whitelist enforcement. Reports every hotplug event to the server
as a new `MSG_USB_REPORT (0x08)` message type.

### New files (1)

| File                       | Purpose                                       |
|----------------------------|-----------------------------------------------|
| `src/client/usb_monitor.h` | Device enumeration and change detection      |

### Wire-protocol change

**New message type:** `MSG_USB_REPORT = 0x08`

Add to the `MsgType` enum in both `src/server/crypto_utils.h` and
`src/client/crypto_utils.h`:

```cpp
MSG_USB_REPORT = 0x08,  // Phase 19: USB device snapshot + hotplug events
```

### What it does

- **Windows:** `SetupDiGetClassDevs` + `SetupDiEnumDeviceInterfaces`
  walks USB device tree, pulls VID, PID, device description, driver
  name, friendly name
- **Linux:** walks `/sys/bus/usb/devices/*`, reads `idVendor`,
  `idProduct`, `product`, `manufacturer`, `serial` files
- Compares against previous snapshot to emit `INSERTED` / `REMOVED` events
- Class-code to category mapping: `storage`, `hid`, `network`,
  `audio`, `video`, `composite`
- Optional whitelist (`usb_whitelist_file`) — any device not in the
  list raises a `WHITELIST_VIOLATION` event

### Config keys (client.conf)

```
usb_monitor_enabled = true
usb_scan_interval_s = 30
usb_whitelist_file  = /etc/seahorse/usb_whitelist.conf
```

### Whitelist format

```
# VID:PID  description
046d:c077  Logitech mouse
0781:5567  SanDisk Cruzer (approved)
```

---

## Phase 20 — Multi-Tenancy & RBAC (v4.0.1)

### Summary

Four-role RBAC layer (`VIEWER`, `OPERATOR`, `ANALYST`, `ADMIN`) with
tenant isolation at the database query layer. Every REST API call now
requires a JWT issued by `/api/auth/login`. Every privileged action
writes to the audit log.

### New files (1)

| File                  | Purpose                                            |
|-----------------------|----------------------------------------------------|
| `src/server/rbac.h`   | Role enum, User/Tenant/AuditEntry, JWT HS256      |

### What it does

- **JWT HS256** hand-rolled on top of OpenSSL EVP+HMAC with base64url
  encoding — no new dependencies
- **User storage** — SHA-256 + random 16-byte salt, stored in
  `users.db` (plain text, tab-separated, file-locked)
- **Tenant storage** — `tenants.db` maps tenant_id → display name
  and quota policy
- **Audit log** — every login, logout, and policy-check decision
  writes a line to `audit.log` plus a rolling ring buffer exposed at
  `/api/audit?limit=N`
- **Policy check** — `RbacManager::allow(token, action, tenant_id)`
  returns `bool` — used in route handlers

### Config keys (server.conf)

```
rbac_enabled    = true
rbac_secret     = <long-random-hmac-key>
rbac_users_db   = rbac/users.db
rbac_tenants_db = rbac/tenants.db
rbac_audit_log  = rbac/audit.log
rbac_token_ttl_s = 28800
```

### REST endpoints

| Method | Path                     | Role       |
|--------|--------------------------|------------|
| POST   | `/api/auth/login`        | public     |
| POST   | `/api/auth/logout`       | any        |
| GET    | `/api/auth/me`           | any        |
| GET    | `/api/audit`             | admin      |
| POST   | `/api/admin/users`       | admin      |

### Admin bootstrap

A CLI one-shot to create the first admin:

```bash
./SeaHorseServer --admin-bootstrap --username admin --password <set-a-strong-one>
```

---

## Phase 21 — SOAR Integration (v4.0.2)

### Summary

Bidirectional connectors for Splunk SOAR, Cortex XSOAR, TheHive, and a
generic webhook. Outbound: every IR action plus every correlated
incident is forwarded. Inbound: a callback endpoint lets the SOAR
platform trigger containment actions back in SeaHorse.

### New files (1)

| File                          | Purpose                                      |
|-------------------------------|----------------------------------------------|
| `src/server/soar_connector.h` | Outbound queue + inbound handler             |

### What it does

- **Outbound worker thread** — takes `SoarOutbound` events from an
  internal queue and posts JSON to the configured backend
- **Backend-specific transforms** — each platform receives its
  expected field names
  (Splunk SOAR's `event`, XSOAR's `occurred`, TheHive's `alert`)
- **`BasicHttpPoster`** — OpenSSL BIO-based HTTP/HTTPS client, no new deps
- **Inbound handler** — `POST /api/soar/callback` takes
  `{ "action": "block_ip", "target": "1.2.3.4", "ttl_s": 3600 }` and
  feeds it into the existing IR engine

### Config keys (server.conf)

```
soar_enabled          = true
soar_backend          = splunk_soar   # generic_webhook | splunk_soar | cortex_xsoar | the_hive
soar_url              = https://soar.example.com/rest/container
soar_auth_header      = ph-auth-token: YOUR_TOKEN_HERE
soar_inbound_secret   = <hmac-shared-with-soar-to-verify-callbacks>
```

---

## Phase 22 — Syslog Ingestion & Forwarding (v4.5.0)

### Summary

Listens for RFC 5424 and RFC 3164 syslog messages over UDP and TCP on
port 514 (configurable) and forwards every SeaHorse detection out as CEF,
LEEF, or RFC 5424 to upstream aggregators like Splunk, QRadar, or Graylog.

### New files (1)

| File                      | Purpose                                         |
|---------------------------|-------------------------------------------------|
| `src/server/syslog_io.h`  | Parser, listener, forwarder                     |

### What it does

- **SyslogListener** — spawns UDP receiver + TCP accept loop
  (thread per connection) on configurable ports
- **SyslogParser** — handles RFC 5424 (structured) and RFC 3164
  (legacy BSD) — returns `SyslogEvent` with facility, severity,
  hostname, app_name, msg_id, structured_data, message
- **SyslogForwarder** — emits detections in CEF / LEEF / RFC 5424
  over UDP or TCP
  - Vendor: `SecuredCyberSolutions`
  - Product: `SecureSeaHorse`
  - Version: server version string

### Config keys (server.conf)

```
syslog_listen_udp      = 0.0.0.0:514
syslog_listen_tcp      = 0.0.0.0:514
syslog_forward_enabled = true
syslog_forward_dest    = splunk.example.com:514
syslog_forward_proto   = udp   # or "tcp"
syslog_forward_format  = cef   # cef | leef | rfc5424
```

---

## Phase 23 — Threat Hunting Query Language (v4.5.1)

### Summary

SPL-inspired DSL that compiles to parameterised PostgreSQL for safe ad-hoc
hunting across every SeaHorse data table. Analysts can combine filters,
sorting, field projection, and aggregation in one pipeline expression.

### New files (1)

| File                          | Purpose                                          |
|-------------------------------|--------------------------------------------------|
| `src/server/hunt_query.h`     | Lexer, parser, compiler, executor                |

### DSL grammar

```
search <source>
  | where <predicate> [AND|OR <predicate>] ...
  | sort <field> [asc|desc]
  | limit <N>
  | stats count by <field>
  | fields <f1>, <f2>, ...
```

### Supported sources

| Name            | Backs                  |
|-----------------|------------------------|
| `events`        | `security_events`      |
| `threats`       | `threat_detections`    |
| `ioc`           | `ioc_matches`          |
| `fim`           | `fim_events`           |
| `correlations`  | `correlations_view`    |
| `audit`         | `audit_log`            |

### Operators

`=` `!=` `<` `>` `<=` `>=` `~` (ILIKE `%val%`)

### Example

```
search threats
  | where severity ~ "high" AND mitre_id = "T1110"
  | sort timestamp_ms desc
  | limit 50
```

### REST endpoint

`POST /api/hunt` — body `{ "query": "..." }` → rows of results

### Safety

- Every user-provided literal flows through `$N` parameter placeholders
- Field names checked against the source schema at compile time
- Unknown fields or sources raise an error before SQL is built

---

## Phase 24 — ML Anomaly Detection (v4.5.2)

### Summary

Pure-C++17 machine learning layer combining an extended isolation forest
(multi-dimensional outlier detection on telemetry vectors) and a
beaconing scorer (autocorrelation + coefficient-of-variation analysis on
reporting intervals). No new link-time dependencies — OpenSSL + libpq
remain the only external libraries.

### New files (1)

| File                         | Purpose                                          |
|------------------------------|--------------------------------------------------|
| `src/server/ml_anomaly.h`    | Isolation forest, beaconing scorer, orchestrator |

### What it does

- **AnomalyFeatures** — 7-dimensional telemetry vector per report:
  cpu_pct, ram_pct, net_in_rate, net_out_rate, event_rate,
  auth_fail_rate, interval_ms
- **IsolationForest** — extended iForest with random hyperplane splits
  (Hariri et al., 2018) — handles correlated features better than
  axis-aligned iForest
- **BeaconingScorer** — coefficient of variation + lag-1 autocorrelation
  over a rolling window of inter-report intervals
- **Auto-retrain** — every `retrain_interval_s` the forest rebuilds from
  the rolling `window_size` pool. First training fires once
  `warmup_samples` are collected
- **MITRE tagging** — each finding maps to T1041 (exfiltration), T1496
  (resource hijack), T1110 (credential misuse), T1078 (defense evasion),
  or T1071 (C2) based on which feature(s) drive the anomaly

### Config keys (server.conf)

```
ml_enabled                = true
ml_window_size            = 2048
ml_warmup_samples         = 128
ml_retrain_interval_s     = 300
ml_score_threshold        = 0.65
ml_critical_threshold     = 0.85
ml_forest_trees           = 64
ml_forest_subsample       = 256
ml_beacon_max_jitter      = 0.15
ml_beacon_min_autocorr    = 0.35
ml_beacon_min_samples     = 12
ml_beacon_window          = 64
```

### REST endpoint

`GET /api/anomalies?limit=50` — recent findings (persisted as a specialised
threat_detections row with `category = "ml_anomaly"`)

---

## Phase 25 — Full React Web UI (v5.0.0)

### Summary

Replaces the single-file embedded dashboard with a proper multi-page SPA
that covers every subsystem: fleet, threats, IoC, FIM, correlations, ML
anomalies, incident workflow, hunt queries, compliance reports. The SPA
connects to a new WebSocket endpoint (`/ws/stream`) for live event tailing.

### New files (1)

| File                      | Purpose                                          |
|---------------------------|--------------------------------------------------|
| `src/webui/index.html`    | Single-file React SPA scaffold                   |

### What it does

- React 18 + react-router-dom 6 served via ESM CDN import-map
- Design language: dark electric blue (`#58a6ff`), Orbitron for
  display type, Share Tech Mono for telemetry — matches the
  securedcybersolutions.co.uk aesthetic
- Matrix-rain backdrop on a canvas layer (toggleable)
- Hash router (`/`, `/fleet`, `/threats`, `/incidents/:id`, etc.)
- **Auth context** — login page calls Phase 20 `/api/auth/login`,
  falls back to static-token mode if the endpoint is not wired
- **useLiveStream hook** — subscribes to `/ws/stream?token=...`,
  auto-reconnects on drop, max buffered events configurable
- **Incident workflow** — incident detail page exposes
  Acknowledge / Block / Quarantine / Resolve actions, a timeline,
  and analyst notes

### Build

For production, port each component into a Vite project:

```bash
npm create vite@latest seahorse-ui -- --template react
cd seahorse-ui && npm install react-router-dom
# Copy index.html inline components into src/App.jsx + child files
npm run build
# Serve /dist via the existing rest_server.h static-file route
```

### New server endpoints needed

| Method | Path                          | Role     |
|--------|-------------------------------|----------|
| WS     | `/ws/stream`                  | any      |
| POST   | `/api/incidents/:id/:action`  | analyst+ |
| GET    | `/api/anomalies`              | analyst+ |

---

## Migration Guide from v3.1.4

### Step 1 — new headers

Drop the ten new `*.h` files (and `src/webui/index.html`) into the
matching locations. Build system updates live in `CMakeLists.txt`.

### Step 2 — wire-protocol extension

Add `MSG_USB_REPORT = 0x08` to the `MsgType` enum in **both** copies
of `crypto_utils.h` (server and client). No changes to existing
message types — protocol is strictly additive.

### Step 3 — config migration

All new config keys have sensible defaults and each subsystem has a
master enable flag (`sigma_enabled`, `rbac_enabled`, `ml_enabled`, etc.).
You can roll out phase-by-phase by flipping one flag at a time.

### Step 4 — database schema

Phases 20 (`audit_log`) and 24 persistence rows share the existing
`threat_detections` table (category = `"ml_anomaly"`). A new
`correlations_view` view is created to back the Phase 23 hunt source:

```sql
CREATE OR REPLACE VIEW correlations_view AS
  SELECT incident_id, rule_name, severity, mitre_technique,
         first_seen_ms, last_seen_ms, device_count, event_count
  FROM correlated_incidents;
```

### Step 5 — run order for the new subsystems in `main()`

```
Sigma -> RBAC -> SOAR -> Syslog I/O -> Hunt -> ML -> REST routes -> WebSocket
```

All are optional; each is gated by its own `*_enabled` flag.

---

## Backward compatibility

- No breaking changes to the wire protocol or existing REST endpoints
- Old clients (pre-Phase 19) will not send `MSG_USB_REPORT` — server
  gracefully ignores missing reports
- Legacy token auth still works if `rbac_enabled = false` — REST
  continues to honour `rest_api_token`
- Phase 25 SPA is an **addition** alongside the embedded dashboard;
  operators can run both in parallel until cutover
