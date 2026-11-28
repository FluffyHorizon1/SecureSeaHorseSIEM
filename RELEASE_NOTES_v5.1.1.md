# SecureSeaHorse SIEM v5.1.1 — Windows CI Fix & Docs Truth-Up

**Status: merged to `main` (#25, 27 Nov 2026). Not tagged, not released,
not published.** This file describes `main` after that merge. Do not treat it
as a shipping announcement until a release has actually been cut. Full
history: `CHANGELOG.md`. Detection inventory: `docs/DETECTIONS.md`.

Line: v5.1 patch. Mostly defensive, docs and CI, plus agent auth-log
collection, a login throttle and an off-by-default Sigma subset.

## Why this patch exists

v5.1.0 restored the Linux build, closed the 2026-09-18 security debt, and
landed tests plus CI. The Windows vcpkg CI job was still red (C++17 flags
and Winsock header order). Docs and installers also still mentioned port
9443, stale config keys, and `changeme-*` examples. This patch fixes those
and unifies client/server version reporting from the top-level `VERSION`
file.

## What is in v5.1.1

**Fixed**
- Windows CI: C++17 on the superbuild and test targets; `WIN32_LEAN_AND_MEAN`
  before `<windows.h>` in `process_monitor.h`, `session_tracker.h`, and
  `software_inventory.h` (server and client); MSVC test compile definitions.
- Docs and installer truth-up: port `65432` (not 9443), real config key
  names, `rest_bind = 127.0.0.1`, installer cert names, stale `changeme-*`
  examples removed from docs.
- Agent log collection (#19). Windows: Security Event IDs
  4624/4625/4634/4648/4672/4740 are read by EventID with a bookmark (the old
  scrape read one `Level<=3` event and missed most logons). The first run
  sets the bookmark and sends no history. Linux: `/var/log/auth.log` or
  `/var/log/secure` plus syslog/messages, with inode/offset tracking and
  rotation handling. Records go to the server on `MSG_LOG_BATCH` (0x0C);
  `raw_log_chunk` stays 512 bytes and carries a preview of the last record.
- Auth parsers are live on the server (#19, #20): batch records are parsed by
  source tag (a Linux server can parse Windows XML) and feed `AlertEngine` and
  `CorrelationEngine`, including a new `auth_brute_force` rule. Parser fixes:
  real Event ID tokens, 4624/4648/4740 added, sudo user capture, "Accepted"
  only on the sshd shape, and `\b` on RegexEngine Event ID patterns.

**Security / CI / docs**
- REST API fails closed (#13): it starts only with a strong `rest_api_token`
  and/or RBAC; an empty token is no longer accepted on loopback; values
  containing `changeme` are refused on every bind; `rest_allow_noauth`
  (loopback only) is the dev escape hatch. With `rbac_enabled = true` the
  static token is ignored, so it cannot bypass tenant scoping.
- Failed-login throttle on `POST /api/auth/login` (#14), per username and per
  client IP, HTTP 429 with `Retry-After`, before password hashing. Keys
  `login_max_failures`, `login_ip_max_failures`, `login_window_s`,
  `login_lockout_s`. `rest_trusted_proxies` is empty/off by default and
  honours `X-Forwarded-For` only from listed IPv4 exact-address peers.
- gitleaks secret-scan workflow with a baseline for the historical
  `changeme-*` placeholders (#16).
- `docs/THREAT_MODEL.md` (#17), `docs/PILOT_READINESS.md` (#22),
  `docs/DETECTIONS.md` and this file (#23).

**Changed**
- Shipped configs no longer set unwired features to true (#18): flags that
  nothing reads are `false`, and `tests/check_conf_keys.py` plus
  `test_conf_honest` guard against regressions.
- `SEAHORSE_VERSION` from `VERSION` is wired into the client as well as the
  server; CI checks `SeaHorseClient --version`.
- Roadmap, READMEs, `client.conf`, and `LICENSE` say 5.1.1 and mark wired vs
  planned modules accurately.

**Added, off by default or partial**
- Sigma YAML subset (#21): `sigma_enabled = false`. When enabled it matches
  keyword rules against the 512-byte `raw_log_chunk` only; it does not see the
  full `MSG_LOG_BATCH` records. Field-map rules need structured fields that
  are not populated. No `|cidr`, aggregations, auto-reload or logsource
  filtering. The samples under `rules/sigma/` are examples, not a detection
  pack.
- Syslog parse / CEF / LEEF helpers (#20), unit-tested. There are no live
  UDP/TCP listeners and no forwarder.

**Not in v5.1.1 (unwired or incomplete)**
- Live syslog UDP/TCP listeners and forwarding.
- USB monitor, reporting/compliance, agent auto-update, OIDC, SOAR,
  WebSocket live stream, agent self-protection: config sections exist and are
  marked planned / not wired.
- Shipped IoC feeds (the loader reads pipe-delimited CSV and none ship).
- Cert-to-device binding on the agent mTLS connection.
- macOS agent.

**Limits of the auth-log path**
- `MSG_LOG_BATCH` is sent only when HMAC/v2 is active (`hmac_enabled = true`,
  the shipped default on both sides). Without it the agent keeps only the
  512-byte preview.
- `auth_log_enabled = false` also leaves `raw_log_chunk` empty, so it turns
  off the regex pack's log input as well as batch collection.
- Agent and server must both be on v5.1.1; an older server has no message
  type for the batch.

## Fresh-install token note

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

No change to the database schema or REST routes. The wire protocol gains one
message type (`MSG_LOG_BATCH`, 0x0C), additive and v2/HMAC only; `raw_log_chunk`
is unchanged. Behaviour changes operators will notice:

- An empty `rest_api_token` is no longer accepted on loopback; set a token,
  enable RBAC, or opt in with `rest_allow_noauth = true` (loopback only) (#13).
- With RBAC on, a static `rest_api_token` is ignored. Anything that used
  RBAC and the static token together must switch to a JWT (#13).
- Repeated failed logins now return 429 with `Retry-After` (#14). Behind a
  reverse proxy that is not in `rest_trusted_proxies`, all clients share the
  proxy's IP, so keep `login_ip_max_failures` well above `login_max_failures`.
- Agents now read `/var/log/auth.log` / `/var/log/secure` and the Windows
  Security log, so the service account needs read access to them.
- Shipped configs flip several flags from `true` to `false` (#18). Installs
  that copied the old config keep their old values; the flags were not read
  either way.

## Verification

`main` at `5458745` (the #25 merge): Linux, Windows and Secret scan CI green.
Re-run `ctest` and the CI jobs on the exact commit you tag. This file does not
republish binary hashes; regenerate them at release time with
the sums generator (currently `old/generat_sums.sh`).
