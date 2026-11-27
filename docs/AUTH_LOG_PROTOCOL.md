# Auth-log collection protocol (MSG_LOG_BATCH)

**Branch:** `fix/auth-log-inputs` (off `v5.1.1-prep`). Live only once this
branch is merged. The 512-byte `RawTelemetry.raw_log_chunk` layout is
**unchanged**.

## Decision: backward-compatible extension, not a breaking bump

A single 512-byte telemetry field cannot hold more than a sliver of one
Windows Event XML document, and the previous agent re-sent the same syslog
tail every cycle. Expanding `raw_log_chunk` would break every v1/v2 peer
that sizes the telemetry struct at 512 bytes.

So this branch:

1. Still fills `raw_log_chunk` with a **truncated preview** (the tail of the
   newest record) so existing regex rules keep working on old and new
   servers.
2. Adds **`MSG_LOG_BATCH = 0x0C`**, a variable-length HMAC v2 message.
   Payload cap 256 KiB, default 32 records per cycle. The format is documented
   in `server/src/log_batch.h` (`SSH-LOGBATCH/1`, length-prefixed records,
   each tagged `windows-security`, `linux-auth`, or `linux-syslog`).
3. Servers that do not know `0x0C` already read the payload and hit the
   existing “Unknown v2 msg_type” default — the stream stays in sync. Old
   agents never send `0x0C`. HMAC-off / v1 sessions send only the 512-byte
   preview (no batch), same as today.

## What is collected

| Platform | Source | Cursor | Notes |
|---|---|---|---|
| Windows | Security channel, XPath `Event/System[EventID=4624 or 4625 or 4634 or 4648 or 4672 or 4740]` | Evt bookmark in `auth_log_state_dir/evt_security.bookmark` | **Not** `Level<=3`. Audit Success / Information logons are included. First run baselines at the newest event (no historical flood). Bookmark is persisted only after a successful send, except the first-run anchor. |
| Linux | `/var/log/auth.log` or `/var/log/secure` (all that exist), **and** `/var/log/syslog` or `/var/log/messages` (first that exists) | inode + offset in `auth_log_state_dir/log_tail.state` | Rotation: inode change or shrink, leftover drain from `path.1` when the inode matches. First sight of a path baselines at EOF. |

The server parses each record with `SessionScanner` using the **source tag**,
not the server OS, so a Linux server can parse Windows Event XML. Parsed
`AuthEvent`s are fed to `AlertEngine` (auth_failure / brute_force /
privilege_escalation / account_lockout) and `CorrelationEngine` (including
the new `auth_brute_force` rule: 3 `session/login_failed` events in 60s).

UTF-16 Event XML is converted with `WideCharToMultiByte(CP_UTF8)` (the old
narrowing `string(ws.begin(), ws.end())` path is gone for this collector).
