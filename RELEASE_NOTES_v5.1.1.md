# SecureSeaHorse SIEM v5.1.1 — Windows CI Fix & Docs Truth-Up

**DRAFT: not released.** This describes branch `v5.1.1-prep` as of 27 Nov 2026
(Europe/London), after PRs #13, #16, #17 and #22 were merged into it. It has
no release tag and is not a shipping announcement. Open PRs #14, #18, #19,
#20 and #21 are listed separately below and are not part of this description
until they merge. Full history: `CHANGELOG.md`. Detection inventory:
`docs/DETECTIONS.md`.

Line: v5.1 patch (defensive / docs / CI only on this branch).

## Why this patch exists

v5.1.0 restored the Linux build, closed the 2026-09-18 security debt, and
landed tests plus CI. The Windows vcpkg CI job was still red (C++17 flags
and Winsock header order). Docs and installers also still mentioned port
9443, stale config keys, and `changeme-*` examples. This patch fixes those
and unifies client/server version reporting from the top-level `VERSION`
file.

## What is actually on `v5.1.1-prep`

**Fixed**
- Windows CI: C++17 on the superbuild and test targets; `WIN32_LEAN_AND_MEAN`
  before `<windows.h>` in `process_monitor.h`, `session_tracker.h`, and
  `software_inventory.h` (server and client); MSVC test compile definitions.
- Docs and installer truth-up: port `65432` (not 9443), real config key
  names, `rest_bind = 127.0.0.1`, installer cert names, stale `changeme-*`
  examples removed from docs.

**Security / CI / docs (merged 27 Nov 2026)**
- REST API fails closed (#13): it starts only with a strong `rest_api_token`
  and/or RBAC; an empty token is no longer accepted on loopback; values
  containing `changeme` are refused on every bind; `rest_allow_noauth`
  (loopback only) is the dev escape hatch. With `rbac_enabled = true` the
  static token is ignored, so it cannot bypass tenant scoping.
- gitleaks secret-scan workflow with a baseline for the historical
  `changeme-*` placeholders (#16).
- `docs/THREAT_MODEL.md` (#17) and `docs/PILOT_READINESS.md` (#22).

**Changed**
- `SEAHORSE_VERSION` from `VERSION` is wired into the client as well as the
  server; CI checks `SeaHorseClient --version`.
- Roadmap, READMEs, `client.conf`, and `LICENSE` say 5.1.1 and mark wired vs
  planned modules accurately.

**Not in this branch (still unwired or incomplete, as in v5.1.0)**
- Sigma (Phase 16 / 32): `sigma_engine.h` is a declaration-only stub;
  `server.cpp` does not include it. `server.conf` has `sigma_enabled = true`
  but that flag is not read. See `docs/DETECTIONS.md`.
- Live syslog UDP/TCP listeners: `syslog_ingestor.h` declares `parse` and
  listeners; there is no implementation and `server.cpp` does not include it.
- USB monitor, reporting/compliance, agent auto-update, OIDC: config sections
  exist and are marked planned / not wired.

## Fresh-install token note (current `v5.1.1-prep` behaviour)

Fresh installs need a REST credential before the dashboard/API will start:

- Default `rest_bind` is `127.0.0.1`. The shipped `rest_api_token` is empty
  and `rbac_enabled` defaults to false.
- With no strong token and no RBAC, the REST API / dashboard **does not
  start**, on any bind, including loopback (`server/src/server.cpp`). The rest
  of the SIEM keeps ingesting. `rest_allow_noauth = true` is a local-testing
  escape hatch and is honoured only on a loopback bind.
- A token containing `changeme` is treated as a shipped default and refused on
  every bind. The RBAC JWT secret is similarly refused if empty or
  `changeme`.
- With `rbac_enabled = true`, `rest_api_token` is ignored. Use a tenant JWT
  from `POST /api/auth/login`.
- Do not expose port 8080 directly; put TLS and access control on a reverse
  proxy if the dashboard is needed off-box.

To bring the dashboard up on a managed host: set a strong unique
`rest_api_token`, **or** enable RBAC, set a 32+ byte `rbac_jwt_secret`, and
bootstrap an admin with `--create-admin`.

## Token rotation advice

If any live or staging install ever used a pre-Phase-28 config (published
`changeme-*` examples, empty token on `0.0.0.0`):

1. Rotate `rest_api_token` and, if RBAC is on, `rbac_jwt_secret` (rotating
   the JWT secret invalidates outstanding sessions).
2. Rotate TLS keys and the Postgres password if they may have been copied
   from examples.
3. The public git history still contains those placeholder strings. They are
   rejected at startup. Do not rewrite history unless a **real** secret (not
   a placeholder) was committed.
4. Do not put live values in this repository, tickets, or chat.

A gitleaks scan and baseline for the historical placeholders now runs in CI
(#16).

## Breaking changes

On `v5.1.1-prep` as merged today: no change to the wire protocol, database
schema or REST routes. Behaviour changes from #13 that operators will notice:

- An empty `rest_api_token` is no longer accepted on loopback; set a token,
  enable RBAC, or opt in with `rest_allow_noauth = true` (loopback only).
- With RBAC on, a static `rest_api_token` is ignored. Anything that used
  RBAC and the static token together must switch to a JWT.

## Open PRs into `v5.1.1-prep` (not merged, not in the description above)

| PR | Branch | What it does | Notes for operators |
|---|---|---|---|
| #14 | `hardening/login-rate-limit` | Failed-login throttle (per username and per IP, 429 + Retry-After) before password hashing. Optional `rest_trusted_proxies` (IPv4 exact addresses, right-most untrusted XFF hop). | New keys `login_max_failures`, `login_ip_max_failures`, `login_window_s`, `login_lockout_s`. Proxies empty/off by default. |
| #18 | `fix/config-honest-flags` | Shipped configs no longer set unwired features (Sigma, reports, USB, WebSocket) to true; adds a config-key audit test. | Config-only. |
| #19 | `fix/auth-log-inputs` | Windows 4624/4625 and Linux `auth.log`/`secure` collection, sent as `MSG_LOG_BATCH`. | Needed before any claim of logon detection. Agent and server must both be updated. |
| #20 | `test/parser-coverage` | Parser unit tests, syslog parser, `session_tracker.h` / `regex_engine.h` fixes. | Overlaps #19 in `session_tracker.h`. |
| #21 | `feature/sigma-rules` | Sigma YAML subset engine and ingest behind `sigma_enabled` (default false). | Off by default. |

Do not treat this table as permission to merge or to push further. If these
merge before the v5.1.1 cut, move them into "What is actually on" and
update `docs/DETECTIONS.md`, which still describes `v5.1.1-prep` without them.

## Verification

Re-run `ctest` and the Linux and Windows CI jobs on the exact commit you tag;
the numbers in earlier drafts of this file referred to older tips. This draft
does not republish binary hashes; regenerate them at release time with
`./scripts/generate_sums.sh`.
