# SecureSeaHorse SIEM v5.1.0 — Consolidation & Hardening

Released: 2026-09-18
Line: v5.1 (Phases 26–35). Full plan in `docs/ROADMAP_v5.1.md`; full history in
`CHANGELOG.md`.

## Why this release exists

The 2026-09-18 code review found three things that outranked everything else: a
fresh clone did not build (8.3-mangled filenames; `.gitignore` inert), a single
malformed agent packet crashed the server, and the REST API could run
unauthenticated with a shipped default token. It also found that Phases 16–25,
advertised as complete, shipped as unwired header stubs — the buildable product
was Phases 1–15.

v5.1 fixes the foundation and begins landing those engines for real, honestly.

## What changed

**Remediation (Phases 26–28)**
- Build restored: filenames un-mangled, root superbuild added, `.gitignore` active.
- Ingest crash fixed: non-throwing wire parsers + a thread-pool task guard.
- REST auth fails closed: no off-loopback start without a strong token; loopback
  default; configurable CORS (no hard-coded `*`); shipped token removed.

**Substrate & tests (Phases 29–30)**
- Dependency-free test suite + GitHub Actions CI (build server+client, run ctest).
- `alert_history` table + `GET /api/alerts` + `POST /api/alerts/disposition` —
  the durable, analyst-labeled data supervised ML will train on.

**Engines landed (Phases 31, 33, 34)**
- RBAC/JWT: PBKDF2-HMAC-SHA256, constant-time compares, `--create-admin`
  bootstrap, `POST /api/auth/login` and `/api/auth/me`.
- Hunt DSL: `POST /api/hunt` (analyst+), allowlisted fields, parameterised SQL.
- ML anomaly: isolation forest + beaconing on live telemetry → `GET /api/anomalies`.

**Truth-up (Phase 35)**
- Single `VERSION` file drives the build and banner; version drift fixed.
- `server.conf` tags every section WIRED or PLANNED.

## Not in this release
- **Sigma (Phase 32):** the engine's mini-YAML parser needs hardening (folded
  scalars + keyword-list selections) before the shipped rules load. Deferred to
  its own branch (spec in the roadmap).
- ML runs on raw features; per-feature normalisation is a pending precision
  follow-up (outlier/normal separation is currently narrow).

## Verification (reference build)

Toolchain: Ubuntu 24.04, gcc 13.3.0, OpenSSL 3.0.13, libpq 16. Superbuild
(`cmake -S . -B build && cmake --build build -j`) is clean; `ctest` is 6/6.
Auth, alert-history and hunt paths were verified against a live PostgreSQL 16.

SHA-256 of this reference Release build (regenerate with
`./scripts/generate_sums.sh build`; binary hashes are build/platform-specific):

```
42e98b981a792734951e01669a7a97b3dc88239371fb605d5c920e2c3377cd1e  SeaHorseServer
229c828071bfdcfd0d33bc9ba3043e525893f402072decde74ea56ee93eb674c  SeaHorseClient
```

## Upgrade notes
- No wire-protocol change; agents need no update.
- RBAC stays **off** by default (legacy bearer token). To enable: set a 32+ byte
  `rbac_jwt_secret`, `rbac_enabled=true`, and bootstrap an admin with
  `SeaHorseServer --create-admin <email>`.
- `alert_history` is created automatically on first start against PostgreSQL.
