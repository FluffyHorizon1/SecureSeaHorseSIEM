# Pilot Readiness — Design-Partner Pilots (Managed Service)

**Audience:** operators running a design-partner pilot of SecureSeaHorse SIEM
as a service we manage (we operate the analysis server and its datastore; the
partner deploys agents on agreed endpoints).

**Version this document is written against:** v5.1.1-prep, plus the 26 Nov 2026
hardening and threat-model work (see §2). This is not a customer contract, a
pricing sheet, or an SLA.

**Related:** [USER_MANUAL.md](USER_MANUAL.md), [ROADMAP_v5.1.md](ROADMAP_v5.1.md),
and `docs/THREAT_MODEL.md` on branch `security/threat-model-v511` (not yet
merged into `v5.1.1-prep` at the time of writing).

---

## 1. Purpose and scope

A design-partner pilot is a time-boxed, operator-run deployment used to learn
whether the product is operable as a hosted service. This document lists
prerequisites, the intended topology, the security posture we are willing to
stand behind, token and backup practice, known limitations, and a go / no-go
checklist.

It does **not** name customers, quote prices, or commit a support tier. Items
that are not yet decided are marked **TBD**.

---

## 2. What is in the pilot baseline

| Item | Status as of 26–27 Nov 2026 (Europe/London) |
|---|---|
| `v5.1.1-prep` (Windows CI fix, docs truth-up, Phase 28 fail-closed auth, RBAC present but off by default) | On the branch. Linux and Windows CI already green on the remote tip. |
| `hardening/rest-auth-fail-closed` | Pushed 26 Nov. Linux + Windows CI green. PR not opened yet. Makes REST fail closed; when RBAC is on, the static `rest_api_token` is ignored and cleared (dashboard uses a JWT). |
| `hardening/login-rate-limit` | Pushed 26 Nov. Linux + Windows CI green. PR not opened yet. Failed-login throttle + optional `rest_trusted_proxies` (IPv4 exact addresses only). |
| `ci/secret-scan-gitleaks` | Pushed 26 Nov. Linux + Windows CI and the gitleaks workflow green. PR not opened yet. |
| `security/threat-model-v511` | Pushed 26 Nov. Linux + Windows CI green. PR not opened yet. Adds `docs/THREAT_MODEL.md` rebased onto `v5.1.1-prep`. Do not use or force-update the older `security/threat-model` tip (based on `main`). |
| Overnight local work (`feature/sigma-rules`, `test/parser-coverage`) | Local only; not part of the pilot baseline until reviewed and merged. |

A managed pilot should not go live on `v5.1.1-prep` alone if the two hardening
branches and the threat-model document are still unmerged: those close
fail-closed auth, login throttling, and the written model the checklist below
refers to. Merging is a morning / review step; this document does not authorize
it.

---

## 3. Prerequisites

### 3.1 Partner (endpoints we do not operate)

- Endpoints running a supported agent OS: Windows 10+, Ubuntu 18.04+, or RHEL 7+
  (see User Manual §2).
- Network path from each agent to the managed server on **TCP 65432** (mTLS).
  No other inbound ports need to be opened on the partner side for a standard
  agent-only pilot.
- A named technical contact and a change window for agent install / uninstall.
- Agreement on which hosts are in scope, and that the agent runs as
  `SYSTEM` / `root` (it has to, to read the telemetry it collects).

### 3.2 Operator (the service we manage)

Minimum and recommended server sizing is the User Manual §2 table (2 cores /
2 GB RAM / 10 GB disk minimum; 4+ cores / 8 GB / 50 GB with a database
recommended). For a managed pilot also require:

- Ubuntu 22.04 or 24.04 LTS (or an equivalent Linux we already operate).
  Windows Server is supported by the product; Linux is the operator default
  until stated otherwise.
- OpenSSL 1.1.1+ (3.x preferred) and CMake 3.15+ if we build from source.
- **PostgreSQL 14+ (16 recommended), required for a managed pilot** even
  though the binary can run with the CSV fallback. The CSV path is a
  development convenience, not a hosted-service store.
- A dedicated non-root service user (the Linux installer creates `seahorse`).
- Config, certificates, and the Postgres password file at mode `600`.
- A TLS CA plus server and client certificates (User Manual §3.4). Self-signed
  material is for lab testing only.
- Strong, unique values for `rest_api_token` (if RBAC is off) and
  `rbac_jwt_secret` (32+ random bytes, if RBAC is on). No default, empty, or
  `changeme`-like values in a reachable deployment.
- A reverse proxy terminating TLS in front of the REST dashboard (port 8080
  is HTTP). Do not expose 8080 directly to the internet.

### 3.3 What we do not require on day one

- OIDC (`rbac_oidc_*` is documented as planned and is not read yet).
- Syslog ingest from partner appliances (`syslog_listener_enabled` defaults
  to false; live UDP/TCP listeners were still a stub on `v5.1.1-prep`).
- The planned agent auto-update channel (`agent_updater.h`) — the threat model
  calls out signed releases and an SBOM as prerequisites. Partners install a
  pinned agent build we give them.

---

## 4. Deployment and topology

```
Partner endpoints                        Operator-managed VPC / host
+----------------------+                 +----------------------------------+
| SeaHorse Client      |  mTLS TCP/65432 | SeaHorse Server (non-root)       |
| (SYSTEM / root)      | ==============> |   thread pool, detection, REST   |
|                      |  binary proto   |                                  |
+----------------------+                 |   HTTP 8080 (loopback)           |
                                         |        ^                         |
                                         |        | loopback only           |
                                         |   TLS reverse proxy :443         |
                                         |        ^                         |
                                         |        | operators / partner SOC |
                                         |   PostgreSQL 16 (TLS, private)   |
                                         +----------------------------------+
```

- **Agent channel (TB1):** mutual TLS on TCP 65432. Firewall this port to
  known agent addresses or an agreed partner egress range. Protocol v2
  HMAC-SHA256 over TLS EKM is the expected mode; do not disable HMAC for a
  pilot.
- **Dashboard / API (TB2):** bind `rest_bind = 127.0.0.1`. Operators (and, if
  agreed, the partner SOC) reach it only through the reverse proxy with HTTPS
  and a locked-down source list. CORS stays empty unless a specific origin is
  required; never `*` with an auth token.
- **Database (TB4):** Postgres on a private interface, TLS required, a
  dedicated least-privilege role. The server and the database should not be
  internet-reachable.
- **Syslog 514/6514:** leave disabled unless a specific appliance feed is in
  the pilot scope and has been reviewed.
- **Tenancy:** a design-partner pilot is **one tenant per server process**
  until the P0 tenant-isolation work in the threat model (cert-to-device
  binding, RBAC on every route, per-tenant ML) is done. Do not colocate two
  partners on one process.

A typical lab install (from the User Manual) still applies for bringing the
binary up; the difference here is that we own the server host, the certs, the
database, and the proxy, and the partner only installs the agent we issue.

---

## 5. Security posture

This section summarises the hosted-service threat model (`docs/THREAT_MODEL.md`
on `security/threat-model-v511`) and the 26 Nov hardening, in operator terms.

### 5.1 What we already rely on

- Mutual TLS (TLS 1.2+, peer cert required) on the agent port; optional CRL
  and OCSP stapling in `crypto_utils.h`.
- Protocol v2 per-session HMAC-SHA256 via TLS EKM, compared in constant time.
- Phase 28 fail-closed REST: the server refuses to start off-loopback without
  a strong non-default token; default bind is loopback; default tokens
  containing `changeme` are rejected.
- RBAC exists (JWT, users DB, tenants DB, audit log) but defaults **off** on
  `v5.1.1-prep`. Bearer-token single-tenant mode is the legacy path.
- After `hardening/rest-auth-fail-closed` is merged: unauthenticated REST is
  loopback-only; when RBAC is enabled the static `rest_api_token` is ignored
  and cleared so a leftover token cannot bypass JWT; the dashboard authenticates
  with a pasted JWT.
- After `hardening/login-rate-limit` is merged: `POST /api/auth/login` is
  throttled per username and per client IP (429 + Retry-After) before password
  hashing. `rest_trusted_proxies` is empty/off by default; if we put the proxy
  on that list, X-Forwarded-For is taken from the right-most untrusted hop and
  spoofed XFF from any other peer is ignored. IPv4 exact addresses only — no
  CIDR, no IPv6.
- After `ci/secret-scan-gitleaks` is merged: CI scans the tree; historical
  `changeme-*` placeholders are baselined and must not be reintroduced as
  real-looking secrets.

### 5.2 Gaps that constrain the pilot (from the threat model)

These are open, documented limitations, not things to hand-wave in a partner
conversation:

- **No cert-to-device / cert-to-tenant binding.** Any client certificate
  signed by our CA can present any `device_id`. Mitigation for a pilot:
  issue a unique client cert per partner (or per host), keep the CA private,
  and run one partner per server process.
- **Protocol v1 (CRC32) may still be accepted** if HMAC is off or a legacy
  header arrives. Mitigation: keep `hmac_enabled` on; do not issue v1 agents.
- **RBAC is not on by default and is not yet complete per-route / per-tenant
  in the Hunt path, `PgStore`, and in-memory engines.** Mitigation: one
  partner per process; treat RBAC as a dashboard login, not as a multi-tenant
  isolation boundary.
- **ML baselines are not partitioned per tenant.** Same mitigation: one
  partner per process.
- **Secrets still live in `server.conf`.** Mitigation: mode 600, no shared
  filesystem with the partner, rotate on the schedule in §6. Env-var / secret
  manager support is a threat-model P0, not shipped.
- **Postgres TLS is not forced by the product.** We must set it in our
  deployment, not rely on a default.
- **Audit logging is not yet comprehensive** for Hunt, IR, and every failed
  auth path.
- **No signed releases or SBOM yet** — do not enable `agent_updater.h`.
- **Fuzzing / ASan in CI** is still a P2 in the model.

### 5.3 Fresh-install auth behaviour (after the rest-auth branch)

A fresh install with an empty `rest_api_token` and `rbac_enabled = false`
will not start the dashboard/API on a non-loopback bind. That is intentional.
For a managed pilot, either set a strong static token (single-tenant, RBAC
off) or enable RBAC, create the first admin with `--create-admin`, and leave
the static token unset.

---

## 6. Token and certificate rotation

Historical default tokens (`changeme-*` and the pre-Phase-28 published
examples) must never appear in a live or staging config. If any environment
we operate ever used a pre-Phase-28 default, rotate `rest_api_token` and
`rbac_jwt_secret` before the pilot starts (see the 25 Nov token audit). The
public git history still contains those placeholder strings; they are
rejected at startup and baselined in gitleaks. Do not rewrite history unless
a real secret (not a placeholder) was committed.

**Rotate, at minimum:**

| Secret / material | When | Notes |
|---|---|---|
| `rest_api_token` | Before go-live; after any suspected leak; when staff with access leave | Only meaningful if RBAC is off. After the rest-auth branch, enabling RBAC ignores and clears this value. |
| `rbac_jwt_secret` | Before go-live; after any suspected leak | 32+ random bytes. Rotating it invalidates outstanding JWTs — plan a short re-login window. The config comment says "rotate via API"; treat a documented operator procedure as **TBD** if that API path is not yet exercised in our runbooks. |
| TLS CA, server cert/key, per-partner client certs | Before go-live; on expiry; after a CA incident | Re-issue partner client certs from a CA they do not hold. |
| Postgres password (`db_pass`) | Before go-live; on staff change | Not in world-readable files. |
| Reverse-proxy TLS cert | Per the proxy's own expiry | Off-box, but part of the pilot surface. |

Record the rotation in the operator runbook (location **TBD**). Never put
live values in tickets, chat, or this repository.

---

## 7. Backup and retention

The product **does not ship a backup scheduler or a retention policy**. Those
are operator responsibilities for a managed pilot.

**Back up (from User Manual §11.3, plus the RBAC files):**

- `config/server.conf`
- `certs/` (CA, server and client keys — store the backup with the same
  tightness as the live keys)
- PostgreSQL: `pg_dump` of the pilot database (and a tested restore)
- `users.db` / `tenants.db` and `rbac/audit.log` if RBAC is on
- `config/rules.conf` and any Sigma / feed files we have customised
- Partner-side `client.conf` is held by the partner; keep a copy of the
  issued agent config **without** embedding secrets in this repo

**Retention (TBD — no product default):**

- Telemetry / incident retention period: **TBD** (agree with the partner
  before ingest starts; enforce with Postgres and filesystem rotation).
- Backup frequency and off-host copy: **TBD**.
- Audit-log retention: **TBD**.
- Server log rotation exists (`logs/server.log`); the interval and keep-count
  are whatever the running build is configured for, not a contractual period.

Do not promise a retention figure that is not in the product or in a signed
pilot agreement.

---

## 8. Support and SLA

All of the following are **TBD**. They will be filled in when a pilot
agreement exists; this document must not invent them.

| Item | Status |
|---|---|
| Support hours / time zone | **TBD** |
| Severity definitions and response / restore targets | **TBD** |
| Planned-maintenance window | **TBD** |
| Escalation path (operator on-call, engineering) | **TBD** |
| Partner-facing status page | **TBD** |
| Data-return and end-of-pilot deletion procedure | **TBD** (must exist before go-live; content not specified here) |
| Pricing, packaging, or commercial terms | Not in scope of this document |

Until those are written, a pilot should only start if a named operator
contact is agreed in writing and both sides accept that there is **no SLA**.

---

## 9. Known limitations

- **Single-partner isolation is a deployment choice, not a completed
  product boundary.** See §5.2.
- **Sigma** on `v5.1.1-prep` is a declaration-only stub (`sigma_engine.h`)
  and is not wired into the live ingest path. Groundwork for a YAML subset
  loader lives on the unmerged `feature/sigma-rules` branch and is out of
  pilot scope until it is reviewed.
- **Syslog ingest** is off by default; listener start/stop was not
  implemented on `v5.1.1-prep`. Do not sell appliance syslog as a pilot
  feature until that path is finished and tested.
- **OIDC** config keys are not read.
- **Agent auto-update** is not ready (no signed releases / SBOM).
- **Login rate limiting and trusted-proxy XFF** are on an unmerged branch
  until the 26 Nov hardening is reviewed and landed.
- **Trusted proxies** understand IPv4 exact addresses only.
- **No JSON log ingest parser** ships as a first-class source (JSON appears
  on the REST/API side, not as a partner log format).
- **Windows Event Log and Linux auth parsers** historically over-matched
  (bare event IDs, `failed`, `sudo` username). Fixes live on the unmerged
  `test/parser-coverage` branch; until that lands, treat those parsers as
  best-effort.
- Dashboard and API are HTTP; TLS is the reverse proxy's job.
- There is no in-product backup or retention job (§7).
- Fuzzing, signed provenance, and a complete security audit trail are
  roadmap items, not pilot features.

---

## 10. Go / no-go checklist

A managed design-partner pilot may start only when every **Go** box is
checked and no **No-go** item is still open.

### Go

- [ ] `v5.1.1-prep` plus the 26 Nov hardening and threat-model branches are
      reviewed, merged as agreed, and deployed from a tag we can re-build.
- [ ] Linux and Windows CI were green on the commit we are deploying.
- [ ] One partner per server process. No shared ML, Hunt, or DB tenancy.
- [ ] Postgres is in use, reachable only privately, with TLS on and a
      least-privilege role.
- [ ] Agent port 65432 is firewalled to the agreed range; HMAC is on; we
      issue unique client certs; the CA key is not on the partner site.
- [ ] REST is loopback-bound and only reachable via an HTTPS reverse proxy
      from agreed operator / SOC addresses. CORS is not `*`.
- [ ] Auth is fail-closed: either a strong unique `rest_api_token` (RBAC
      off) or RBAC on with a unique `rbac_jwt_secret` and the static token
      unset. No `changeme` / empty / documented-default values.
- [ ] Login throttling is in the running build (or an equivalent control
      sits on the proxy) and `rest_trusted_proxies` is either empty or lists
      only our proxy.
- [ ] Mode `600` on config, keys, and DB password material; service runs as
      a non-root user.
- [ ] Backup of config, certs, and a Postgres dump has been taken **and a
      restore has been tested**.
- [ ] Retention, support hours, and the end-of-pilot deletion procedure are
      either written in the pilot agreement or explicitly accepted as **TBD**
      with a named owner and a date.
- [ ] The partner has a pinned agent build, install/uninstall instructions,
      and a named technical contact.
- [ ] `agent_updater`, OIDC, multi-tenant hosting, and appliance syslog are
      explicitly out of scope for this pilot.

### No-go (any one of these blocks start)

- [ ] A historical default token or a real secret is still in the running
      config, or we cannot confirm they were rotated.
- [ ] The dashboard or Postgres is reachable on the public internet without
      the controls above.
- [ ] Two design partners would share one server process.
- [ ] We would need auto-update, OIDC, or unfinished syslog ingest to call
      the pilot successful.
- [ ] CI on the deploy commit is red, or we cannot say which commit is
      running.
- [ ] No tested backup restore.
- [ ] No named operator contact, and no written acknowledgement that there
      is no SLA.

---

## 11. Document history

| Date (Europe/London) | Notes |
|---|---|
| 2026-11-27 | First draft on `docs/pilot-readiness`, based on `v5.1.1-prep`, User Manual §§2 / 3.4 / 11 / 12, the 26 Nov hardening branches, and `docs/THREAT_MODEL.md` on `security/threat-model-v511`. No customer or pricing facts. SLA/support left **TBD**. |
