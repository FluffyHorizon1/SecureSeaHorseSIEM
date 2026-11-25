# SecureSeaHorse SIEM — Roadmap

_Last updated: 2026-11-25, anchored to v5.1.1._

This roadmap is forward-looking from the v5.1.1 release. For the history
of everything up to and including v5.1.1, see `CHANGELOG.md` and `docs/ROADMAP_v5.1.md`.

Every line has a one-line rationale. We treat the roadmap as a
promissory hint, not a contract — timing slips on every serious SIEM
project and we'd rather ship well than ship on time. Each entry is
tagged with one of four priorities: `P0` (ship-blocker for the target
version), `P1` (committed), `P2` (planned), `P3` (exploratory).

---

## Done @ v5.1.1 (current)

Phases 1–15 plus the hardened v5.1 modules (Phases 26–31, 33–34) are live
in the buildable codebase. Unwired Phase 16–19, 21–22, 25 stubs remain
clearly marked `PLANNED` in `server/config/server.conf` and `client/config/client.conf`.

- **Collection.** mTLS telemetry agent on port `65432` (Windows / Linux,
  protocol v2 HMAC-SHA256), FIM, process / connection / session / software
  inventory.
- **Analysis.** Regex + threshold alerting, 6-category traffic classifier
  with MITRE ATT&CK tags, 7-type threat-intel feeds, deep network inspection
  (DNS/proto/entropy), unsupervised ML anomaly detection (isolation forest +
  beaconing scorer at `GET /api/anomalies`).
- **Correlation & response.** 7 cross-device correlation rules, IR engine
  with 7 playbooks and 7 action types, fleet staleness tracking.
- **Persistence & Auth.** PostgreSQL `libpq` layer with labeled
  `alert_history` (`GET /api/alerts`, `POST /api/alerts/disposition`),
  PBKDF2-HMAC-SHA256 + JWT RBAC (`rbac_enabled`, `--create-admin`,
  `/api/auth/login`, `/api/auth/me`), fail-closed loopback REST API on port
  `8080`.
- **Hunt.** Parameterized Hunt DSL (`POST /api/hunt`, field allowlist +
  `$N` SQL binding).
- **UI & Build.** Embedded HTML dashboard (`dashboard_html.h`), Linux +
  Windows CMake superbuild, 6 CTest regression suites, GitHub Actions CI.

---

## Near-term — v5.x (patch + minor)

Small, incremental improvements, all backward-compatible on the wire
and in the DB. Ordered by priority for design-partner and hosted-service readiness.

### v5.1.1 — Windows CI + docs truth-up (shipped)

- **Windows vcpkg CI green.** Root C++17 standard propagation and
  `WIN32_LEAN_AND_MEAN` header hygiene so MSVC builds and passes all CTests.
- **Version & docs truth-up.** Unified `VERSION` across server + client
  binaries, corrected port (`65432`) and config keys across `docs/USER_MANUAL.md`
  and installers, and separated wired vs planned features.

### v5.2 — Hosted multi-tenant readiness & core engines (in priority order)

1. **Sigma YAML engine (P0 — Phase 32).** Harden `sigma_engine.h` mini-YAML
   parser (folded scalars, keyword-list selections, `|cidr`/`|endswith`/
   `|startswith`), wire `sigma/*.yml` into the live pipeline, and add
   regression tests. Rationale: unlocks community detection rules without
   hand-coding regexes.
2. **Full RBAC coverage & default-on multi-tenancy (P0 — Security).**
   Enforce per-route RBAC and `tenant_id` scoping across all legacy read/write
   endpoints (including WebSocket/export routes), turn `rbac_enabled = true`
   by default for hosted deployments, remove empty-token loopback bypass for
   sensitive operations, and add tenant-isolation tests + rate limiting +
   structured audit logging. Rationale: mandatory for multi-tenant SaaS
   hosting with real design partners.
3. **ML calibration & precision (P1).** Per-feature normalization, per-tenant
   isolation-forest thresholds, and an analyst false-positive feedback loop
   on `alert_history`. Rationale: widens outlier/normal score separation and
   prevents noisy tenants from masking quiet ones.
4. **UI & hunt polish (P2).** Hunt DSL `join` on `device_id`, tenant-shared
   saved searches, keyboard-navigable incident timeline, per-user alert mute
   rules, and completing remaining unwired stubs (WebSocket live stream,
   syslog ingestor/forwarder, compliance reports, USB, SOAR, signed agent
   updates) as scoped.

---

## Mid-term — v6.0 (major, 2026 H2)

v6 is where we tackle the things we've been deferring because they'd
require a schema or protocol break. We plan exactly one major bump per
year to keep operators sane.

### eBPF agent collector (P0 for v6.0)

Linux agent gains an eBPF back-end for process / network / file
telemetry. Rationale: polling `/proc` every 60 s misses short-lived
exec events that are the backbone of modern attacks. eBPF is the
current commercial-tier standard; shipping it removes the last
"why not pick us" conversation.

### Wire protocol v3 (P0 for v6.0)

Replace the fixed-size struct with length-prefixed Protobuf messages.
Rationale: every new `MSG_*` since Phase 11 has required custom
serialization. Protobuf gets us forward-compat fields + schema
evolution + smaller payloads for free, at the cost of a build-time
dep. We'll still accept v2 for two minor cycles for smooth rollover.

### Windows Event Channel provider (P1 for v6.0)

Native ETW subscriber instead of polling `wevtutil`. Rationale: ETW
removes the 60-second poll gap on Windows endpoints and gives us
real-time 4688 / 4624 / 4625 coverage.

### Agent macOS support (P1 for v6.0)

Endpoint Security Framework back-end mirroring the eBPF collector.
Rationale: we get steady ask from Mac-heavy design / engineering
tenants; supporting it expands the TAM without reopening the protocol.

### Kafka / NATS ingest adapter (P2 for v6.0)

Drop-in source alongside syslog / agent. Rationale: organizations with
a message-bus-first architecture don't want syslog spillover; reading
directly from Kafka lets SeaHorse slot into existing pipelines.

### SSO hardening (P2 for v6.0)

- SAML 2.0 (right now only OIDC via Phase 20)
- Per-user MFA enforcement (today: handled at the IdP only)
- Just-in-time tenant provisioning on first IdP login

Rationale: enterprises buy on SSO checkbox completeness; we have a
third of the checklist today.

### Deprecated in v6.0

- **Protocol v1 (CRC32).** Rationale: v2 has been the default since
  Phase 3 and only legacy agents still speak v1. Drop saves ~400 lines
  of dual-path code.
- **Legacy bearer-token REST auth.** Rationale: warned-on since v4.0;
  time to stop.
- **`dashboard_html.h` single-file dashboard.** Rationale: React SPA
  has been default since v5.0 and the HTML SPA has no path for the
  WebSocket features.

---

## Long-term — v7.0 (2027)

These are the bets, not commitments. If any of them are critical to
your deployment, open a discussion so we can prioritize.

### Deception / canary engine (v7.0, P2)

Planted credentials, fake database endpoints, deceptive files. Any
touch triggers a hard-severity incident. Rationale: signal-to-noise is
higher than any detection engine we run; the hard part is a scalable
UI for managing decoy inventory.

### Kubernetes-native deployment (v7.0, P1)

Official Helm chart, operator for CRD-driven tenant lifecycle,
Prometheus metrics endpoint. Rationale: most of our new deployments
target k8s; packaging that path as first-class saves every team from
reinventing the same chart.

### Cloud-trail connectors (v7.0, P1)

AWS CloudTrail, Azure Activity Log, GCP Audit Log ingest. Rationale:
closes the "cloud SIEM" gap without forcing a separate product.
Shipping this alongside v6.0 syslog-forwarder parity turns SeaHorse
into a viable primary SIEM for cloud-heavy orgs.

### Graph-based attacker-path analysis (v7.5, P2)

Build an in-memory attack graph (device → account → service) from the
fleet inventory + session data; surface "shortest path to domain
admin" as a dashboard. Rationale: this is the one commercial-tier
analytic feature we don't have today; doing it right requires v6.0's
eBPF process-lineage data.

### Built-in vulnerability scanner (v7.5, P2)

Phase 14 software inventory + a periodic NVD/OSV feed match surfaces
CVEs per device. Rationale: half the time analysts pivot from
SeaHorse to a separate scanner to answer "is this host vulnerable to
X?"; closing that loop saves a tool.

### Confidential computing / SGX / Nitro agent (P3 exploratory)

Agent key material held in an enclave so even a root-compromised host
can't forge telemetry. Rationale: high-assurance customers ask; gated
on platform availability maturing.

### LLM-assisted triage (P3 exploratory)

Co-pilot that drafts incident summaries, suggests correlation rules
from raw events, and writes postmortem skeletons. Rationale: this is
where the market is heading; exploratory because we don't want to
build something that hallucinates during an incident. We'll ship it
only when the evals prove it strictly reduces analyst workload in a
controlled cohort.

---

## v8.0 — Scale-Out & High Availability (2027 H2 – 2028)

The single-server architecture tops out around ~20k agents on big
hardware. v8 removes that ceiling.

### Clustered server (P0)

Raft-coordinated multi-node ingest tier; any node can accept any
agent, no single point of failure. Rationale: HA is the #1 blocker in
enterprise procurement conversations once fleet size passes five
digits.

### Federated search (P1)

One hunt query fans out across regional clusters and merges results.
Rationale: global orgs must keep event data resident per region but
still hunt globally.

### Columnar analytics store as first-class (P1)

Promote the v5.4 Parquet cold-storage adapter to the primary event
store (DuckDB / ClickHouse back-end options). Rationale: 13-month
compliance retention at interactive query speed is not achievable on
row-store Postgres alone.

### Detection-as-code (P1)

Rules (regex, Sigma, correlation, playbooks) live in git; CI validates
and stage-deploys them per tenant. Rationale: mature SOCs want
detections reviewed like code, with rollbacks.

### OpenTelemetry ingest + export (P2)

Accept OTLP signals and emit SeaHorse events as OTLP. Rationale:
unifies security and observability pipelines and rides an ecosystem
we don't have to maintain.

---

## v9.0 — Autonomous SOC (2028 – 2029)

v9 graduates the v7 AI explorations into supervised production
features. Human-in-the-loop is the design constraint everywhere.

### LLM triage GA (P1)

Incident summaries, enrichment, and next-step suggestions with strict
grounding in retrieved events — no free generation during incidents.
Rationale: ships only because the v7 exploratory cohort proved it
reduces time-to-triage; guardrails carry over.

### Natural-language hunting (P1)

English → Hunt DSL translation with a preview-before-run gate.
Rationale: lowers the skill floor so tier-1 analysts can hunt without
learning the DSL; the compiled query stays inspectable.

### Feedback-trained correlation (P2)

Analyst dispositions (true/false positive) auto-tune correlation
windows and propose new rules for review. Rationale: closes the loop
that v5.3's ML feedback started, at the rule layer.

### Case management workspace (P1)

Native investigation cases: evidence pinning, timelines, hand-offs,
disposition tracking. Rationale: today every SeaHorse SOC pastes
findings into an external ticket system and loses context.

### UEBA / risk-based scoring (P2)

Per-entity (user, host, service) risk scores that weight alerts by
blast radius, not just raw severity. Rationale: alert fatigue is the
top complaint in every user interview; ordering by risk is the fix.

---

## v10.0 — Converged Platform (2029 – 2030)

The horizon release: SeaHorse as an extensible detection platform
rather than a single product.

### Identity threat detection (P1)

First-class AD / Entra ID / Okta signal ingestion with identity-centric
detections (golden ticket, MFA fatigue, impossible travel).
Rationale: identity is the modern perimeter; every serious incident we
studied in 2027-2028 pivoted through an IdP.

### Plugin marketplace + analyzer SDK (P1)

Stable C ABI + WASM sandbox for third-party analyzers, feeds, and UI
panels, with a signed marketplace. Rationale: the community requests
integrations faster than we can build them; a sandboxed SDK scales us
horizontally.

### Managed control plane (P2)

Optional SaaS control plane coordinating self-hosted data planes —
config, rules, and fleet health in the cloud; events never leave the
customer network. Rationale: gets us SaaS convenience without losing
the data-sovereignty stance that differentiates SeaHorse.

### Zero-trust posture integration (P2)

Feed device health scores to ZTNA brokers (Tailscale, Cloudflare
Access, Zscaler) so a failing endpoint loses access automatically.
Rationale: turns detection into prevention using infrastructure
customers already run.

### Data-lake-native architecture (P3 exploratory)

Query events in place in customer-owned lakes (Iceberg / Delta)
instead of ingesting copies. Rationale: the "security data lake"
pattern may obsolete SIEM-owned storage; we'd rather cannibalize
ourselves than be cannibalized.

---

## How to influence the roadmap

Open an issue with the `roadmap` label and the target version. We
treat roadmap items as living — anything with `P2` or `P3` can be
promoted based on adoption signal.
