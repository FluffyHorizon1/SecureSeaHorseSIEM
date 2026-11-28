# Changelog

All notable changes to SecureSeaHorse SIEM. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

`MAJOR` jumps when the wire protocol, database schema, or REST contract
break. `MINOR` jumps add features. `PATCH` is defensive-only.

---

## [5.1.1] — 2026-11-25 — Windows CI Fix & Docs Truth-Up

**Status:** merged to `main` (#25, 27 Nov 2026). No release tag has been
created and nothing has been published. See `RELEASE_NOTES_v5.1.1.md`.

**Headline.** Patch release restoring the Windows vcpkg CI build, unifying
client and server version reporting under `VERSION`, aligning `ROADMAP.md`,
READMEs, installers, and `docs/USER_MANUAL.md` with the actual v5.1 codebase,
failing REST closed, and adding authentication-log collection from the agent.

### Fixed
- **Windows CI build (`tests/`).** Set `CMAKE_CXX_STANDARD 17` at the root
  superbuild and `cxx_std_17` on test targets so MSVC compiles structured
  bindings in `test_config` and `test_json_escape`.
- **Winsock header ordering.** Added `WIN32_LEAN_AND_MEAN` guards before
  `<windows.h>` in `process_monitor.h`, `session_tracker.h`, and
  `software_inventory.h` (both `server/src` and `client/src`) plus MSVC test
  compile definitions so `test_deserializers` no longer hits `<winsock.h>` vs
  `<winsock2.h>` redefinition errors.
- **Port, certificate, and config key truth-up.** Corrected `docs/USER_MANUAL.md`
  and `installer/installer_windows.nsi` from port `9443` to `65432` (matching
  `DEFAULT_PORT` and `server.conf`/`client.conf`), fixed config key names
  (`port`, `server_ip`, `server_crt`/`server_key`/`ca_path`, `pool_*`, `db_*`,
  `rest_bind = 127.0.0.1`), aligned `install_linux.sh certs` output names
  (`.crt`/`.key`), and scrubbed stale `changeme-*` example values from docs.

- **Windows and Linux auth-log collection (#19).** The agent previously read
  one recent Windows Security event at `Level<=3` (which drops most 4624/4625
  logons) and only `/var/log/syslog` or `/var/log/messages` on Linux. It now
  reads Security Event IDs 4624/4625/4634/4648/4672/4740 by EventID with a
  bookmark (events from the first run onward; no history is back-filled), and
  `/var/log/auth.log` or `/var/log/secure` plus syslog/messages with
  inode/offset tracking and rotation handling. Records travel on the new
  `MSG_LOG_BATCH` (0x0C) message, sent only when HMAC/v2 is active; the
  512-byte `raw_log_chunk` is unchanged and carries a preview of the last
  record. See `docs/AUTH_LOG_PROTOCOL.md`.
- **Auth parsers are now live (#19, #20).** The server routes each batch
  record to the Windows or Linux parser by source tag, feeds `AuthEvent`s to
  `AlertEngine` and `CorrelationEngine`, and adds the `auth_brute_force`
  correlation rule. Parser fixes: real Event ID tokens instead of bare
  `4625` / `failed` substrings, 4624/4648/4740 added, sudo username capture,
  "Accepted" only on the sshd shape, and `\b` on the RegexEngine Event ID
  patterns so `event id: 46250` no longer matches 4625.

### Added
- Failed-login throttle on `POST /api/auth/login`, per username and per client
  IP (HTTP 429 with `Retry-After`), checked before password hashing (#14). New
  keys `login_max_failures`, `login_ip_max_failures`, `login_window_s`,
  `login_lockout_s`. `rest_trusted_proxies` (empty/off by default) honours
  `X-Forwarded-For` only from listed IPv4 exact-address peers; no CIDR, no
  IPv6.
- Sigma YAML subset engine and ingest (`sigma_engine.h`, `sigma_ingest.h`),
  **off by default** (`sigma_enabled = false`). When on, it evaluates the
  agent `raw_log_chunk` against rules in `sigma_rules_dir`. Sample rules under
  `rules/sigma/` (#21). Not a community-rule engine: no `|cidr`,
  aggregations, auto-reload or logsource filtering.
- `SyslogIngestor::parse` and `SyslogForwarder::to_cef` / `to_leef`, with
  unit tests (#20). Live UDP/TCP listeners and the forwarder are still not
  implemented.
- Tests: `test_auth_parsers`, `test_auth_log_ingest`, `test_log_tail`,
  `test_parsers`, `test_rate_limiter`, `test_sigma`, `test_sigma_ingest`,
  `test_conf_honest`, and `tests/check_conf_keys.py` (audit of shipped config
  keys the code never reads). `tests/CMakeLists.txt` registers a test only if
  its `.cpp` exists.

### Changed
- Shipped configs no longer advertise features that are not wired. Flags that
  nothing reads (`sigma_auto_reload`, `reports_enabled`, `usb_enabled`,
  `ws_enabled`, `selfprotect_*`, `usb_monitor_enabled`) are `false`;
  `sigma_enabled` is `false` (#18).
- Wired `SEAHORSE_VERSION` from `VERSION` into `client/CMakeLists.txt` and
  `client/src/client.cpp` and added a `SeaHorseClient --version` check to CI.
- Updated `ROADMAP.md`, `server/README.md`, `client/README.md`,
  `client/config/client.conf`, and `LICENSE` to `5.1.1` and marked wired vs
  planned modules accurately.

### Security
- REST API now fails closed: it starts only with a strong `rest_api_token`
  and/or RBAC. An empty token is no longer accepted on loopback. Values
  containing `changeme` are refused on every bind. `rest_allow_noauth`
  (loopback only) is the development escape hatch. Token comparison is
  constant-time.
- **Fresh install:** the shipped `server.conf` has an empty `rest_api_token`
  and `rbac_enabled = false`, so the dashboard/API will not start until the
  operator sets a token or enables RBAC (or, for local testing only, sets
  `rest_allow_noauth = true` on a loopback bind).
- When `rbac_enabled = true`, `rest_api_token` is ignored and a startup
  warning is logged. The static token has no tenant and would bypass tenant
  scoping; tenant JWTs from `POST /api/auth/login` are the only REST
  credentials.

### CI and docs
- Added a gitleaks secret-scan workflow with project rules and a baseline for
  the historical `changeme-*` placeholders (#16). Do not reintroduce
  real-looking secrets.
- Added `docs/THREAT_MODEL.md` (STRIDE, hosted multi-tenant scope) (#17).
- Added `docs/PILOT_READINESS.md`, design-partner notes for a managed
  service (#22).
- Added `docs/DETECTIONS.md`, an inventory of what the code detects, and
  `RELEASE_NOTES_v5.1.1.md` (#23).

---

## [5.1.0] — 2026-09-18 — Consolidation & Hardening

**Headline.** v5.1 makes the repository build from a clean clone, closes the
security debt from the 2026-09-18 review, adds a test suite and CI, and lands
several engines that had shipped as unwired header stubs. It is a `MINOR` bump:
no wire-protocol change; the REST contract gains endpoints but breaks none.

**Correction to the record.** The v5.0.0 notes below described Phases 16--25 as
shipped. In the split `server/`+`client/` layout they were in fact present only
as declaration-only header stubs that no translation unit compiled or linked
(RBAC, Sigma, SOAR, syslog, hunt DSL, ML, WebSocket, agent-update, USB,
self-protection, report generator). The buildable product was Phases 1--15.
v5.1 begins landing 16--25 for real, honestly tracked.

### Fixed
- **Phase 26 — build restoration.** Un-mangled the 8.3 short filenames from the
  Codespaces export (`CMAKEL~1.TXT` → `CMakeLists.txt`, `GITIGN~1` →
  `.gitignore`, and the CHANGELOG/docs/installer). A fresh clone had not been
  able to configure; `.gitignore` had been inert. Added a root superbuild.
- **Phase 27 — ingest crash (DoS).** The process/connection/session/software
  deserializers called `std::stoi/stoul/...` unguarded; one malformed packet
  from a connected agent reached the worker thread and called `std::terminate()`.
  Added `wire_parse.h` (non-throwing parsers) and a thread-pool task guard.
- **Phase 28 — REST auth fail-closed.** The API skipped auth when the token was
  empty and shipped a known default token bound to `0.0.0.0`. Now refuses to
  start off-loopback without a strong token; default bind is loopback; CORS is
  configurable (no more hard-coded `*`).

### Added
- **Phase 29 — tests + CI.** Dependency-free C++ test suite (deserializers,
  config, JSON escaping, hunt allowlist, ML separation) and a GitHub Actions
  workflow that builds server + client and runs `ctest`.
- **Phase 30 — labeled alert history.** New `alert_history` table with an
  analyst `disposition` label, `GET /api/alerts`, and
  `POST /api/alerts/disposition` — the durable substrate supervised ML needs.
- **Phase 31 — RBAC/JWT for real.** Landed with PBKDF2-HMAC-SHA256 password
  hashing (was single-pass SHA-256), constant-time password/JWT comparison, and
  a `--create-admin` bootstrap. `POST /api/auth/login` and `/api/auth/me`.
- **Phase 33 — Hunt DSL.** `POST /api/hunt` (analyst+): the one-line DSL
  compiles to parameterised SQL with a field allowlist; no user SQL is
  concatenated.
- **Phase 34 — ML anomaly detection.** Isolation forest + beaconing scorer on
  live telemetry; findings persist as `threat_detections` (`ml_anomaly`) and
  surface at `GET /api/anomalies`.

### Changed
- Single `VERSION` file is the source of truth (CMake + banner read it); fixed
  the v5.0.0/v5.0.1 drift. `server.conf` now tags every section as WIRED or
  PLANNED so it never implies a capability the binary lacks.

### Known / not yet wired
- **Phase 32 (Sigma)** is not in this release: the engine's mini-YAML parser
  needs hardening (folded scalars + keyword-list selections) before the shipped
  rules load. Tracked in `docs/ROADMAP_v5.1.md`.
- ML scores on raw features; per-feature normalisation is a pending precision
  follow-up (outlier/normal separation is currently narrow).
- Full per-route RBAC gating is applied to the new sensitive endpoints; the
  legacy read endpoints still use the bearer-token gate.

---

## [5.0.0] — 2026-04-22 — React UI + WebSocket Live Stream

**Headline.** The React single-page UI lands, and every detection engine
now pushes events to subscribers in real time instead of requiring the
15 s dashboard poll loop that shipped in v1.7.0.

This is the first `MAJOR` release since v3.0.0. It bundles the full
contents of phases 16-25 from the prior roadmap. The `MAJOR` jump is
justified by (a) RBAC + multi-tenancy reshaping every REST response, and
(b) the new `/ws/*` WebSocket surface being a first-class public API.

### Added
- **Phase 25 — WebSocket live stream.** New `websocket_stream.h` co-hosts
  RFC 6455 sockets on the REST port; six channels (`/ws/threats`,
  `/ws/ioc`, `/ws/fim`, `/ws/events`, `/ws/correlations`, `/ws/ir`) push
  JSON events at ingestion latency. JWT-authenticated at upgrade time,
  tenant-scoped server-side, 512-message backpressure cap per client.
- **React SPA.** The legacy single-file dashboard (`dashboard_html.h`)
  stays for compatibility but gains a `?ui=react` switch that loads the
  new multi-page UI: fleet view, hunt workbench, correlation timeline,
  IR playbook editor, report archive, admin console.
- **Hunt Query Language API surface at `/api/hunt`.** See v4.5.0.
- **Saved searches at `/api/hunt/searches`.**

### Changed
- REST responses now include a `tenant_id` field when RBAC is enabled.
- Legacy bearer-token authentication is retained but logs a deprecation
  warning when RBAC is configured.
- Dashboard header bumped to `SIEM Dashboard v5.0.0`.

### Protocol
- Reserved `MSG_SIGMA_HIT (0x0A)` for server-internal event tagging (no
  client-side emit yet).

### Rationale for 4.x → 5.x jump
The WebSocket surface and React UI together are the first public-facing
API additions that third-party integrations will build against. They get
a stable major. Phase 21 SOAR + Phase 20 RBAC round out what enterprises
asked for when adopting v3.x; bundling them under a single major marks
the platform as enterprise-ready.

---

## [4.5.0] — 2026-04-22 — Syslog, Hunt DSL, ML Anomaly

### Added
- **Phase 22 — Syslog ingestion & forwarding.** Passive RFC 5424 / 3164
  receiver (UDP 514 + TCP-TLS 6514). Events feed the regex + sigma
  engines just like agent telemetry. Outbound forwarder speaks CEF,
  LEEF, and RFC 5424 so SeaHorse can fan out to Splunk, QRadar,
  Sentinel, or Graylog without a middleware box.
- **Phase 23 — Hunt Query Language.** Splunk-inspired DSL (`search |
  stats | sort | top | limit | table`) compiled to parameterized SQL.
  Every identifier is whitelist-validated before it touches `libpq`;
  every literal is bound via `$N`. 30 s statement timeout, 10 k row
  hard cap, tenant-scoped. Saved searches live in a new `saved_searches`
  table.
- **Phase 24 — ML anomaly detection.** Two pure-C++ detectors: an
  isolation forest over per-device feature vectors (CPU, RAM, disk IOPS,
  net in/out, event rate, failed-login rate) with online re-fit every
  500 samples; a periodogram-based beaconing scorer flagging regular
  C2 heartbeats hidden in connection timing.

### Changed
- New top-level `rules/sigma/` directory (Phase 16) becomes the
  canonical location for YAML detection rules shared between the Sigma
  engine and the Hunt DSL "rule-as-query" compatibility mode.

### Rationale
4.5 is the biggest *feature* release in the history of the project — it
finally closes the parity gap with commercial SIEMs in three classic
features: upstream forwarding, a hunting DSL, and first-party ML
anomaly detection.

---

## [4.0.0] — 2026-04-22 — Multi-Tenancy + SOAR + USB

**Breaking: REST responses gain a `tenant_id` field and all queries are
tenant-scoped when `rbac_enabled = true`. Bearer-token single-tenant
mode still works but emits a deprecation warning.**

### Added
- **Phase 19 — USB / peripheral monitor.** New `MSG_USB_REPORT (0x09)`.
  Client watches `WM_DEVICECHANGE` on Windows and `libudev` on Linux;
  server matches each attach/detach against the per-tenant whitelist
  (`config/usb_whitelist.csv`). Unknown devices inserted within 60 s of
  an interactive login escalate to `high` via correlation.
- **Phase 20 — RBAC + multi-tenancy.** Four roles (admin / operator /
  analyst / auditor), JWT (HS256 on-prem, RS256 with OIDC), per-tenant
  data isolation across every existing table plus a new `audit_log`
  that records every state-changing API call.
- **Phase 21 — SOAR integration.** Bidirectional connectors for Splunk
  SOAR, Cortex XSOAR, TheHive, plus a Generic webhook connector for
  anything else. Outbound pushes every IR action as an enriched case;
  inbound `/api/soar/callback` lets the external SOAR request actions
  back (block_ip, quarantine, disable_user).

### Changed
- `rest_server.h` now resolves each request to `(tenant_id, role)` via
  `rbac_manager.h` before dispatching.
- Data layer gains a universal `AND tenant_id = $N` clause.

### Rationale for 3.x → 4.x jump
RBAC permanently changes the shape of the REST contract. The DB schema
gains a non-null `tenant_id` column on every table. Both qualify as
breaking and therefore a `MAJOR` bump.

---

## [3.5.0] — 2026-04-22 — Sigma Rules, Self-Protection, Compliance

### Added
- **Phase 16 — Sigma rule engine.** Hand-rolled YAML subset parser —
  no external dependency — covering ~90% of community rules. Hot-reload
  on file mtime. Evaluates alongside the Phase 2 regex engine; hits
  become `security_events` rows and feed the correlation engine.
- **Phase 17 — Agent self-protection & auto-update.** Tamper-resistant
  client: watchdog companion (`seahorse-wd`), self-hash verify on
  startup, signed auto-update over the existing mTLS channel. New
  protocol messages `MSG_UPDATE_OFFER (0x08)` and `MSG_TAMPER_EVENT
  (0x0B)`.
- **Phase 18 — Reporting & compliance.** Three built-in HTML templates
  (PCI-DSS, HIPAA, SOC 2) plus an exec-summary template. Cron-driven
  scheduler, no PDF runtime deps — generated HTML prints cleanly to PDF
  via headless Chromium or wkhtmltopdf.

### Protocol additions
- `MSG_UPDATE_OFFER (0x08)` — server → client, carries release metadata.
- `MSG_TAMPER_EVENT (0x0B)` — client → server, self-protection alert.

### Rationale
3.5 was queued from the v3.0.0 roadmap. None of these changes break the
wire or DB contracts, so it's a pure `MINOR`.

---

## [3.2.0] — 2026-04-22 — Pre-v5 consolidation (dev-only)

Consolidation milestone that bundled the v3.1.1 security-audit work,
renamed internal baseline tracker types, and wired `config_file.h`'s
`get_int_clamped` helper everywhere the old `get_int` + manual clamp
pattern was duplicated. No user-visible features. Never released as a
public artifact — development branch only, tagged to separate the v3.1
audit cleanup from the 3.5.0 feature work.

---

## [3.1.2] — 2026-04-22 — Documentation pass (prior release)

Corrected README version badge, updated phase headers in the user
manual. No code changes. *This is the last release shipped before the
current v3.x → v5.0 jump.*

## [3.1.1] — 2026-04-17 — Security hardening

Security audit fixes. See the `v3.1.1 Security Audit` section in the
README for the full table — unchanged in v5.0 and still the definitive
reference for that work.

Critical fixes (reproduced here for completeness):
1. Shutdown deadlock in `incident_response.h`.
2. Correlator callback deadlock in `correlation_engine.h`.
3. FIM TOCTOU race across `fim_common.h` + `fim_scanner.h`.
4. TLS downgrade exposure — pinned TLS 1.2+, modern ciphers only.
5. Stored XSS in the web dashboard — all user-controlled fields now
   HTML-escaped before `innerHTML`.

Plus 12 DoS-hardening controls across the HTTP parser, database layer,
regex engine, and feed loaders.

---

## [3.0.0] — Prior release — Split src tree + installers + user manual

The `src/` tree was split into `src/server/` and `src/client/`. Six
headers used by both targets are duplicated into each directory so the
two binaries can be compiled independently. Bundled `install_linux.sh`
and `installer_windows.nsi`.

## [2.5.0 … 1.0.1]

See the README "Version History" table. The phase 1-15 history is
preserved verbatim there.
