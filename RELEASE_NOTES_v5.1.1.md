# SecureSeaHorse SIEM v5.1.1 — Windows CI Fix & Docs Truth-Up

**DRAFT: not released.** This describes branch `v5.1.1-prep` as of 27 Nov 2026
(Europe/London). It is not on `main`, has no release tag, and is not a
shipping announcement. Full history: `CHANGELOG.md`. Detection inventory:
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

This is unchanged from v5.1.0 Phase 28, but it still bites a first boot:

- Default `rest_bind` is `127.0.0.1`. The shipped `rest_api_token` is empty.
  `rbac_enabled` defaults to false.
- The server **refuses to start the REST API / dashboard on a non-loopback
  bind** if `rest_api_token` is empty or contains `changeme`
  (`server/src/server.cpp`). The rest of the SIEM continues.
- On a loopback bind, an empty token is allowed with a warning. Do not
  expose port 8080; put TLS and access control on a reverse proxy if the
  dashboard is needed off-box.
- A value containing `changeme` is treated as a shipped default and rejected
  off-loopback. JWT secret empty-or-`changeme` is similarly rejected for
  RBAC (`server/src/server.cpp`).

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

A gitleaks scan and baseline for the historical placeholders exists only on
the pending `ci/secret-scan-gitleaks` branch (below).

## Breaking changes

On `v5.1.1-prep` itself: **none beyond v5.1.0**. This patch does not change
the wire protocol, database schema, or REST contract. Operators who skipped
the v5.1.0 fail-closed REST change should still read the fresh-install token
note above.

Pending review branches (not in this tree) do include behavioural breaks;
see below.

## Pending review (not released, not in this tree)

Four branches were pushed 26 Nov 2026, all Linux + Windows CI green, and
have **not** been merged. They are listed so reviewers and a future release
can see what is queued. They are not part of `v5.1.1-prep`.

| Branch | Remote tip | What it does | Notes for operators |
|---|---|---|---|
| `hardening/rest-auth-fail-closed` | `25b97615` | Tightens fail-closed REST. When RBAC is on, the static `rest_api_token` is ignored and cleared (no tenant-bypass). | **Breaking if you use RBAC + a static token together today.** Fresh install with empty token + RBAC off will not start the API off-loopback (already true on prep); `rest_allow_noauth` is loopback-only. |
| `hardening/login-rate-limit` | `3a633886` | Failed-login throttle (per username and per IP, 429 + Retry-After) before password hashing. Optional `rest_trusted_proxies` (IPv4 exact addresses, right-most untrusted XFF hop). | New config keys. Default proxies empty/off. Merging with the rest-auth branch needs a manual `RestConfig` conflict resolution (keep both auth fields and `trusted_proxies`). |
| `ci/secret-scan-gitleaks` | `c2bb3a7c` | Gitleaks workflow, project rules, baseline for historical `changeme-*`. | CI-only; no runtime behaviour change. |
| `security/threat-model-v511` | `3c2d4ef2` | `docs/THREAT_MODEL.md` rebased onto `v5.1.1-prep`. | Docs only. Do not force-update `security/threat-model` on `main`. |

Do not treat this table as permission to merge or to push further.

## Verification

Linux tests on `v5.1.1-prep`: 6/6 ctest (existing suite). Windows CI is
green on the remote tip `fc9bdb0c` (run 45715978761, 25 Nov). The four
pending branches are also Linux + Windows green; see the 26–27 Nov overnight
notes. This draft does not republish binary hashes; regenerate them at
release time with `./scripts/generate_sums.sh`.
