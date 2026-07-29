# Changelog

All notable changes to SecureSeaHorse SIEM. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

`MAJOR` jumps when the wire protocol, database schema, or REST contract
break. `MINOR` jumps add features. `PATCH` is defensive-only.

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
