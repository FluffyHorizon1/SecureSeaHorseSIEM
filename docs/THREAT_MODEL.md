# SecureSeaHorse SIEM — Threat Model (Hosted Multi-Tenant Service)

**Version:** v5.1.1 baseline (targeting v5.2+ hosted SaaS hardening)
**Date:** 2026-11-25
**Methodology:** STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)
**Deployment Context:** Multi-tenant SIEM hosted and managed for design partners and commercial customers, with endpoint agents (`SeaHorseClient`) deployed across customer networks connecting to a central or regional `SeaHorseServer` tier.

---

## 1. Scope & Architecture Overview

SecureSeaHorse SIEM comprises:
1. **Endpoint Agent (`SeaHorseClient`)**: Runs as `SYSTEM` / `root` on monitored Windows and Linux endpoints; collects telemetry, logs, FIM hashes, processes, TCP/UDP connections, user sessions, and installed software; ships protocol v2 packets over mTLS (`port 65432`).
2. **Ingest & Analysis Server (`SeaHorseServer`)**: Terminates mTLS (`OpenSSL 3.x`), dispatches telemetry across a dynamic thread pool (`pool_min`..`pool_max`) through regex/threshold alerting, traffic classifier, threat-intel IoC matcher, FIM monitor, network inspector, correlation engine, IR playbooks, and unsupervised ML anomaly detector (`ml_anomaly.h`).
3. **Control Plane / REST API & Dashboard (`rest_server.h`, `dashboard_html.h`)**: HTTP server (`port 8080`, loopback default) exposing JSON endpoints, Hunt DSL (`POST /api/hunt`), alert dispositioning (`POST /api/alerts/disposition`), and JWT auth (`/api/auth/login`, `/api/auth/me`) via `RbacManager` (`rbac.h`).
4. **Persistence Layer (`db_layer.h`)**: PostgreSQL (`libpq`) primary store with CSV fallback (`s_log.csv`), plus file-backed RBAC stores (`rbac/users.db`, `rbac/tenants.db`, `rbac/audit.log`).
5. **Planned / Unwired Subsystems (v5.2+)**: Sigma YAML engine (`sigma_engine.h`), signed agent auto-update & self-protection (`agent_updater.h`, `agent_selfprotect.h`), WebSocket live stream (`websocket_stream.h`), syslog ingest/forward (`syslog_ingestor.h`), SOAR connectors (`soar_connector.h`), USB monitor (`usb_monitor.h`), compliance reports (`report_generator.h`).

---

## 2. Crown-Jewel Assets

| Asset ID | Asset | Security Properties | Impact if Compromised |
|---|---|---|---|
| **A1** | **Customer Telemetry & Security Alerts** (`threat_detections`, `security_events`, `fim_events`, `ioc_matches`, `alert_history`, `s_log.csv`) | Confidentiality, Integrity, Tenant Isolation | Cross-tenant data leak; attacker blinds SOC or forges false incidents |
| **A2** | **mTLS PKI & Session Keys** (`ca.crt`, `server.key`, `client.key`, TLS EKM-derived HMAC keys) | Confidentiality, Authenticity | Agent impersonation, MitM telemetry injection, fleet-wide compromise |
| **A3** | **Auth Secrets & Credentials** (`rbac_jwt_secret`, `rest_api_token`, `users.db` PBKDF2 hashes, `db_pass`, `ir_webhook_url`) | Confidentiality, Integrity | Account takeover, cross-tenant admin access, DB compromise |
| **A4** | **Endpoint Agent Execution Context** (`SeaHorseClient` running as `root`/`SYSTEM`, planned `agent_updater.h` channel) | Integrity, Availability | Remote Code Execution (RCE) across all customer endpoints |
| **A5** | **Detection Rules, Feeds & ML Models** (`rules.conf`, `sigma/*.yml`, `feeds/*.csv`, `MlAnomalyDetector` state, IR playbooks) | Integrity, Availability | Detection evasion, model poisoning, destructive IR actions (IP block / host quarantine) |
| **A6** | **Audit Logs** (`rbac/audit.log`, PostgreSQL audit tables) | Integrity, Append-only Availability | Loss of forensics / non-repudiation for SOC & compliance audits |

---

## 3. Trust Boundaries

| Boundary | Description | Protocol / Interface |
|---|---|---|
| **TB1: Customer Endpoint ↔ Public Internet / SaaS Ingest** | Untrusted or potentially compromised endpoint running `SeaHorseClient` connecting to hosted `SeaHorseServer` | mTLS (`TCP/65432`), Binary Protocol v2 (HMAC-SHA256 via TLS EKM) |
| **TB2: Operator / Customer Browser / API Client ↔ REST Control Plane** | Browser, reverse proxy, or automation client calling `RestServer` | HTTP (`TCP/8080`, expected behind TLS reverse proxy) + Bearer / JWT |
| **TB3: Tenant A ↔ Tenant B (Logical Multi-Tenancy)** | Shared server process, thread pool, in-memory state (`FleetManager`, `CorrelationEngine`, `IncidentResponseEngine`, `MlAnomalyDetector`), and shared PostgreSQL DB | `RbacManager` JWT `tid` claim, `db_layer.h` SQL queries, `hunt_query.h` |
| **TB4: `SeaHorseServer` ↔ PostgreSQL & Local Disk** | Analysis server reading/writing DB, CSV fallback, `users.db`, `tenants.db`, `audit.log` | `libpq` TCP/5432, POSIX/Win32 filesystem |
| **TB5: Ingest Pipeline ↔ ML Anomaly & Detection Engines** | Telemetry & log strings entering `regex_engine`, `threat_intel`, `ml_anomaly`, and planned `sigma_engine` | In-process C++ calls |
| **TB6: Build / Release Pipeline ↔ Server / Agent Update Channel** | Source repo / CI artifacts / planned `agent_updater.h` manifest & binaries pushed to customer endpoints | GitHub Actions, `updates/manifest.json`, `MSG_UPDATE_OFFER (0x08)` |

---

## 4. STRIDE Threat Analysis

### TB1: Agent ↔ Server mTLS & Wire Protocol (`port 65432`)

| Threat | Category | Existing Mitigations | Identified Gaps |
|---|---|---|---|
| Compromised agent in Tenant A spoofs `device_id` belonging to Tenant B | **S / E** | Mutual TLS (`SSL_VERIFY_PEER \| SSL_VERIFY_FAIL_IF_NO_PEER_CERT`), TLS 1.2+ pinned (`server.cpp`), optional CRL & OCSP stapling (`crypto_utils.h`) | Server validates CA signature only; **no cert-to-device or cert-to-tenant binding** (CN/SAN/fingerprint not mapped to `tenant_id` or `device_id`). Any valid client cert can emit telemetry for any `device_id`. |
| Wire packet tampering or replay | **T** | Protocol v2 uses per-session HMAC-SHA256 derived via `SSL_export_keying_material` (`SEAHORSE_SIEM_HMAC_V1`) and constant-time `CRYPTO_memcmp` (`crypto_utils.h`) | Protocol v1 (CRC32) fallback still accepted if `hmac_enabled` is off or legacy header (`MsgType` v1) arrives unless disabled; no explicit sequence-number / anti-replay counter beyond TLS record layer. |
| Malformed telemetry causes server crash or thread exhaustion | **D** | Phase 27 `wire_parse.h` non-throwing integer parsers, `DynamicThreadPool` exception catch, `test_deserializers` regression tests | No per-IP/per-agent connection rate limit or max concurrent TLS handshake cap; `connection_timeout_s` exists, but pre-auth TLS handshake or slowloris/oversized frame flood is not bounded per tenant; no automated fuzzing in CI. |
| Rogue server impersonation to agent | **S / I** | Agent verifies server cert against `ca.crt` and supports optional `cert_pin_sha256` (`verify_cert_pin`) & `ocsp_must_staple` | `cert_pin_sha256` and `ocsp_must_staple` are off by default; `server_ip` / DNS mismatch check (`SSL_set1_host` / X509 hostname verification) is not enforced by default in `client.cpp`. |

### TB2: REST API, JWT & Web Dashboard (`port 8080`)

| Threat | Category | Existing Mitigations | Identified Gaps |
|---|---|---|---|
| Unauthenticated access via empty token or reverse-proxy loopback | **S / E** | Phase 28 refuses non-loopback `rest_bind` when `rest_api_token` is empty or contains `"changeme"`; default bind is `127.0.0.1` | **Empty-token loopback bypass**: on `127.0.0.1`, `rest_server.h:483` skips auth when `api_token` is empty. Behind a reverse proxy (`nginx`/`Caddy`/sidecar) on `127.0.0.1`, external requests become unauthenticated. Also `rbac_enabled` defaults to `false`. |
| Legacy token timing oracle / weak transport | **I / S** | `rbac.h` uses `CRYPTO_memcmp` for PBKDF2 password hashes and JWT signatures, and rejects `rbac_jwt_secret` < 32 bytes or containing `"changeme"` | `rest_server.h:484` compares `rest_api_token` with `!=` (non-constant-time). `RestServer` speaks plaintext HTTP only (relies entirely on external reverse proxy for TLS). |
| Brute-force against `/api/auth/login` | **S / D** | PBKDF2-HMAC-SHA256 password hashing in `rbac.h` | **No rate limiting / account lockout / IP throttling** on `/api/auth/login` or any REST endpoint; attacker can flood PBKDF2 verification (CPU DoS + credential stuffing). |
| Incomplete per-route RBAC & JSON injection in hand-rolled responses | **E / I / T** | `/api/alerts/disposition` and `/api/hunt` enforce `rbac_require(..., Role::ANALYST)` (`server.cpp`); `dashboard_html.h` HTML-escapes fields; `test_json_escape` tests `HttpResponse::json_escape` | **Legacy read routes lack RBAC checks**: `/api/stats`, `/api/threats`, `/api/ioc`, `/api/fim`, `/api/events`, `/api/devices`, `/api/ir/*`, `/api/correlations`, `/api/alerts`, `/api/anomalies` do not call `rbac_require()`. Some JSON builders in `server.cpp` (`/api/auth/login`, `/api/auth/me`, `/api/ir/actions`, `/api/ir/blocklist`) interpolate fields without `json_escape()`. |
| Historical default credentials still active in deployments | **S / I** | `v5.1.1` removes remaining `changeme-*` examples from docs/`old/` and `server.cpp` rejects `"changeme"` substrings | Git history contains historical default strings (`changeme-seahorse-token-2026`, `changeme-generate-a-long-random-hmac-key` prior to Phase 28 / v5.1.1). Any environment seeded with older configs must rotate immediately. |

### TB3: Multi-Tenant Isolation

| Threat | Category | Existing Mitigations | Identified Gaps |
|---|---|---|---|
| Cross-tenant data access via REST or Hunt DSL | **I / E** | `RbacManager` embeds `tid` (`tenant_id`) in JWT claims (`rbac.h`); `hunt_query.h` validates table/column names against an allowlist and binds values via `$N` | **No tenant isolation enforcement in queries or in-memory engines**: `db_layer.h` tables/queries, `server.cpp` REST handlers, `FleetManager`, `CorrelationEngine`, `IncidentResponseEngine`, and `POST /api/hunt` do not filter by `claims.tenant_id`. Any authenticated user in Tenant A can read Tenant B's alerts, devices, and hunt results. Zero automated tenant-isolation tests exist. |
| Cross-tenant IR blast radius | **T / D / E** | IR engine (`incident_response.h`) tracks blocklist and quarantined `device_id`s | IR state (`blocked_ips`, `quarantined`, scripts/webhooks) is global rather than tenant-scoped; an alert or false positive in one tenant could trigger global IP blocking or shared webhook notifications. |

### TB4: Persistence (`db_layer.h`, `users.db`, `audit.log`) & Secrets Management

| Threat | Category | Existing Mitigations | Identified Gaps |
|---|---|---|---|
| SQL injection in dynamic queries / Hunt DSL | **T / I** | `hunt_query.h` uses strict allowlists + `$N` parameterized `PQexecParams`; `server.cpp` clamps `limit` `[1..1000]` | `hunt_statement_timeout_ms` and `hunt_row_cap` config keys are not yet wired into `PgStore` execution; DB user privileges / PostgreSQL RLS (Row-Level Security) are not yet enforced. |
| Plaintext secrets in config & unencrypted DB/RBAC files | **I** | `install_linux.sh` sets `chmod 600` on `server.conf` and `700` on `certs/`; `rbac.h` hashes user passwords with PBKDF2-HMAC-SHA256 | `db_pass`, `rest_api_token`, `rbac_jwt_secret`, and planned `soar_api_key` live as plaintext in `server.conf` with no env-var (`SEAHORSE_*`) or secrets-manager integration; `db_layer.h` does not enforce `sslmode=verify-full` for PostgreSQL connections. |
| Tampering or incomplete coverage of audit logs | **R** | `rbac.h` logs `login` attempts to `rbac/audit.log` | Only login events are audited in `rbac.h`; disposition changes, hunt queries, IR actions, user/tenant admin changes, and failed REST auth are not centrally recorded in an immutable/append-only audit stream. |

### TB5: ML Anomaly Engine (`ml_anomaly.h`) & Detection Pipeline

| Threat | Category | Existing Mitigations | Identified Gaps |
|---|---|---|---|
| Cross-tenant model poisoning / threshold masking | **T / D** | `MlAnomalyDetector` bounds `window_size` and runs seeded isolation forest + beaconing scorer; ReDoS caps exist in `regex_engine.h` | **Single global `MlAnomalyDetector` instance** shared across all devices and tenants (`server.cpp`). A noisy or compromised endpoint in Tenant A shifts the training window and anomaly scores for Tenant B; raw unnormalized features narrow outlier/normal separation. |
| Unhardened Sigma YAML parsing (when Phase 32 lands) | **D / T** | Phase 32 intentionally deferred wiring `sigma_engine.h` pending YAML parser hardening | Folded scalars, keyword-list selections, and regex limits in `sigma_engine.h` must be fuzzed and capped before enabling untrusted or tenant-uploaded rules. |

### TB6: Supply Chain & Planned Update Channel (`agent_updater.h`, CI/CD)

| Threat | Category | Existing Mitigations | Identified Gaps |
|---|---|---|---|
| Compromised release artifact or malicious update push | **T / E** | `agent_updater.h` (planned) designs RSA-PSS over SHA-256 manifest verification; `updates_enabled = false` by default | **No signed releases, checksums attestation, or SBOM** in CI yet; no branch protection on `main` or secret scanning/push protection enabled on GitHub yet; CI runs on Ubuntu/Windows without ASan/UBSan or continuous fuzzing. |

---

## 5. Prioritized Remediation Roadmap

| Priority | Gap | Target Milestone | Issue Focus |
|---|---|---|---|
| **P0 (Critical)** | Enforce per-route RBAC + `tenant_id` isolation across all REST, Hunt, DB (`PgStore`), and in-memory engines; add tenant-isolation regression suite | `v5.2` | Full RBAC coverage + tenant isolation tests |
| **P0 (Critical)** | Set `rbac_enabled = true` by default (secure-by-default) and remove empty-token loopback auth bypass (or isolate strictly to explicit `--dev-no-auth` flag) + constant-time `rest_api_token` check | `v5.1.1` / `v5.2` | Fail-closed auth & RBAC default-on |
| **P0 (Critical)** | Bind agent mTLS client certs (CN/SAN/fingerprint) to registered `(tenant_id, device_id)` and enforce server hostname verification on agents | `v5.2` | Per-tenant mTLS identity binding |
| **P0 (Critical)** | Rotate any historical `changeme-*` defaults in live/staging configs; remove secrets from plaintext `server.conf` via env-var / secrets manager support & enforce Postgres TLS | `v5.1.1` / `v5.2` | Credential rotation & secrets management |
| **P1 (High)** | Add rate limiting / lockout on `/api/auth/login` and REST endpoints; wrap remaining JSON fields with `json_escape()` | `v5.2` | Auth rate limiting & JSON escape hardening |
| **P1 (High)** | Partition `MlAnomalyDetector` per tenant (and normalize features) so tenants cannot poison each other's baselines | `v5.2` | Per-tenant ML isolation & calibration |
| **P1 (High)** | Expand structured audit logging to all state-changing & query operations (`hunt`, `disposition`, `IR`, `RBAC admin`, failed auth) | `v5.2` | Comprehensive security audit log |
| **P2 (Medium)** | Add LibFuzzer / OSS-Fuzz targets (wire deserializers, HTTP parser, Hunt DSL, Sigma YAML) + ASan/UBSan to CI | `v5.2` | Continuous fuzzing & sanitizers in CI |
| **P2 (Medium)** | Add signed releases, provenance (`SLSA`), and CycloneDX/SPDX SBOM generation before enabling `agent_updater.h` | `v5.2` | Signed releases & SBOM |
