# SecureSeaHorse SIEM -- Roadmap: the next 10 phases (v5.1 line, Phases 26--35)

**Theme: Consolidation & Hardening.** Grounded in the code review of 2026-09-18.
Before the platform can credibly claim the AI-forward roadmap (Phases 28--43 in the
prior plan), it has to (a) build from a clean clone, (b) not crash on a malformed
packet, (c) fail closed on auth, (d) have a test net and CI, and (e) actually contain
the Phase 16--25 features it advertises -- which today ship as unwired header stubs.

These ten phases do exactly that, in dependency order. Phases 26--30 are remediation and
the data substrate; 31--34 land the previously-stubbed engines into the buildable tree
for real; 35 tells the truth in the docs and cuts v5.1.0.

Each phase is one builder branch and one patch. "Landed" means: compiles under
`-Wall -Wextra`, wired into `server.cpp`/`client.cpp`, and covered by at least one test
in the Phase 29 harness.

---

## Phase 26 -- Build restoration & repo hygiene  `(fix, v5.0.2)`
**Goal:** a fresh `git clone` builds by following the README.
**Scope:** un-mangle the 8.3 filenames committed by the Codespaces export
(`CMAKEL~1.TXT` -> `CMakeLists.txt` x2, `GITIGN~1` -> `.gitignore`,
`CHANGE~1.MD` -> `CHANGELOG.md`, `docs/PHASE*~1.MD`, `docs/USER_M~1.MD`,
`installer/INSTAL~1.*`); add a root superbuild `CMakeLists.txt` that builds both
targets; confirm `.gitignore` is active again.
**Acceptance:** `cmake -S server -B build && cmake --build build` succeeds from a clean
clone; `git check-ignore server.log` returns a match; `git status` clean after a build.
**Review refs:** §3.1, §3.2.

## Phase 27 -- Crash-harden the ingest path  `(fix, v5.0.2)`
**Goal:** no single packet can terminate the server.
**Scope:** wrap the numeric parses in the four text deserializers
(`process_monitor.h`, `connection_inventory.h`, `session_tracker.h`,
`software_inventory.h`) in `try/catch` returning an empty/invalid report (mirroring the
already-correct `FimReport::deserialize`); add a belt-and-braces `try/catch` around
`task()` in `DynamicThreadPool::worker_func` so no future handler bug can reach
`std::terminate`.
**Acceptance:** the Phase 29 test feeding `PROC|7001|123|notanumber` returns an empty
report instead of throwing; fuzz of 10k random report bodies causes zero aborts.
**Review refs:** §4.1 (proven crash).

## Phase 28 -- REST auth fail-closed  `(fix, v5.0.2)`
**Goal:** the API is never unauthenticated-by-accident, and never ships a known token.
**Scope:** in `main()`, refuse to start the REST server when `rest_api_token` is empty
or a known-default AND `rest_bind` is not loopback; default `rest_bind = 127.0.0.1`;
remove the shipped default token from `server.conf`; make the CORS
`Access-Control-Allow-Origin` configurable (`rest_cors_origin`, default same-origin/none)
instead of hard-coded `*`.
**Acceptance:** starting with an empty token on `0.0.0.0` exits non-zero with a clear
message; loopback + empty token still starts (dev convenience) with a warning.
**Review refs:** §4.2, §4.3.

## Phase 29 -- Test harness + CI  `(feature, v5.1.0)`
**Goal:** a regression net, and a build that can't silently break again.
**Scope:** a dependency-free C++17 test target (`tests/`) with a tiny assert macro,
covering: all five wire deserializers (happy path + malformed/crash inputs), config
parsing/clamping, `HttpResponse::json_escape`, and the hunt-DSL field allowlist; a
GitHub Actions workflow (`.github/workflows/ci.yml`) that builds server + client on
`ubuntu-latest` (and configures on `windows-latest`) and runs the tests; `-Werror` once
the current four warnings are cleared.
**Acceptance:** `ctest` green locally; CI green on a pushed branch; a reintroduced
`std::stoi` without guard turns CI red.
**Review refs:** §7 (highest-leverage gap).

## Phase 30 -- Persisted, labeled alert history (data substrate)  `(feature, v5.1.0)`
**Goal:** create the substrate supervised ML needs -- durable, analyst-labeled alerts.
**Scope:** new `alert_history` table (alert metadata + `disposition` enum
`unset|true_positive|false_positive|benign` + `analyst_id` + `labeled_at`); an insert
on every persisted threat/IoC/correlation; `POST /api/alerts/{id}/disposition` to record
an analyst's label; `GET /api/alerts` to list with disposition. In-memory architecture
stays; this table is the one durable thing the ML phases will train on.
**Acceptance:** dispositioning an alert round-trips through PostgreSQL; schema created on
startup; endpoint covered by a test with a stubbed store.
**Rationale:** the memory-noted precondition -- "supervised ML requires persisted labeled
alert history, which the current in-memory architecture cannot provide."

## Phase 31 -- RBAC/JWT for real, hardened  `(feature, v5.1.0)`
**Goal:** land Phase 20 into the buildable tree, without the review's auth bugs.
**Scope:** bring the `old/` RBAC implementation into `server/src`, wire
`/api/auth/login` + `/api/auth/me` + per-route role gates; replace single-pass
`SHA256(salt||pw)` with **PBKDF2-HMAC-SHA256** via OpenSSL `PKCS5_PBKDF2_HMAC`
(>=600k iters, no new dependency); make JWT-signature and password comparisons
constant-time (`CRYPTO_memcmp`); add a `--create-admin <email>` CLI bootstrap so the
first admin can exist; refuse to start with a weak/short JWT secret (already the pattern
in `old/`).
**Acceptance:** create-admin -> login -> authorized call works end-to-end; tampered JWT
rejected; PBKDF2 verified by a known-answer test.
**Review refs:** §4.4, §4.5, §4.6.

## Phase 32 -- Sigma engine landed  `(feature, v5.1.0)`
**Goal:** land Phase 16 -- evaluate Sigma rules in the live pipeline.
**Scope:** bring the working `sigma_engine.h` into the build, load `config/sigma/*.yml`
at startup, evaluate each ingested log chunk alongside the regex engine, persist hits as
`security_events`, feed them to correlation. Enforce the existing loader caps.
**Acceptance:** the three shipped sample rules load; a crafted log line matching
`ps_encoded_command.yml` produces a security event; malformed YAML is skipped, not fatal.
**Review refs:** §2 (stub -> real), §8 (config keys wired).

## Phase 33 -- Hunt DSL endpoint landed (safe)  `(feature, v5.1.0)`
**Goal:** land Phase 23 -- analyst hunt queries, injection-safe.
**Scope:** wire `compile_hunt()` behind `POST /api/hunt` (RBAC: analyst+); enforce the
field allowlist and `$N` parameterisation that already exist; apply statement timeout and
row cap; require DB connectivity. Every literal is bound, never concatenated.
**Acceptance:** allowlist tests (a query naming a non-whitelisted column is rejected at
compile time); a valid query returns rows; an injection attempt in a value is bound as a
parameter, not executed.
**Review refs:** §2, and the injection-boundary tests in §7.

## Phase 34 -- ML anomaly detection landed (unsupervised)  `(feature, v5.1.0)`
**Goal:** land Phase 24 -- isolation forest + beaconing scorer on live telemetry.
**Scope:** bring `ml_anomaly.h` into the build (fixing the `old/` default-arg
portability bug), feed each telemetry sample's numeric features to `observe()`, score it,
and persist scores >= threshold as `threat_detections` with `category='ml_anomaly'`; run
the beaconing scan on the diagnostics thread; surface via `GET /api/anomalies`. This is
unsupervised only -- supervised training on the Phase 30 substrate is a later phase.
**Acceptance:** a synthetic anomalous sample scores above threshold and lands as a
threat; the detector trains in-process without blocking ingestion.
**Review refs:** §2, §6 (the ml_anomaly default-arg fix).

## Phase 35 -- Version/doc truth-up + v5.1.0 release  `(release, v5.1.0)`
**Goal:** the docs describe the software that exists; cut an honest release.
**Scope:** a single `VERSION` file as the source of truth, consumed by CMake and asserted
in CI; fix the v5.0.0/v5.0.1 drift; rewrite `CHANGELOG.md`'s v5.0.0 entry to state
plainly that 16--25 shipped as stubs and were landed across v5.1; regenerate `server.conf`
so every key maps to code that reads it (drop or wire the ~40 dead keys, fix the
name mismatches like `rbac_jwt_secret` vs `rbac_secret`); `RELEASE_NOTES_v5.1.0.md`;
`SHA256SUMS` computed from the real artifacts.
**Acceptance:** CI version-consistency check passes; every `server.conf` key is read by
the code; `SHA256SUMS` verifies against built binaries.
**Review refs:** §8.

---

### Sequencing & dependencies
- 26 unblocks everything (nothing builds until the filenames are fixed).
- 27, 28 are independent hardening, parallelisable after 26.
- 29 depends on 26 (needs a build) and gives 30--34 their test net.
- 30 is the substrate; the *supervised* ML phase (future v6.0) depends on it.
- 31 gates 33 (hunt is analyst-only) and should precede 32/34 so new endpoints are
  authenticated as they land.
- 35 closes the line once 26--34 are in.

### Out of scope for v5.1 (deferred to v6.0+)
Supervised online logistic-regression scorer trained on Phase 30 labels; guarded LLM
triage assistant (Ollama/llama.cpp); OCSF normalisation; horizontal scale / federated
learning. These are sound goals -- they just sit on top of a foundation that has to be
real first.
