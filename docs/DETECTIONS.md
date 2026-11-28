# Detections inventory (v5.1.1, `main`)

**Audience:** Lead Researcher, before any design-partner outreach.

**Rule:** this list is taken from the code on `main` (v5.1.1) unless a
section says otherwise. File paths are the source of truth. Config flags that exist
but are not read, and headers that are not included by `server.cpp` /
`client.cpp`, are **not** live. Do not quote this as a complete Sigma, syslog,
or USB product.

Date of inventory: 27 Nov 2026 (Europe/London), updated after v5.1.1 was
merged to `main` (#25, `5458745`). Earlier drafts of this file described
`v5.1.0` / `v5.1.1-prep`, where the auth parsers were not called and the
agent scrape missed most Windows logons. That is no longer true; see §1 and
§2.3. Not tagged or released.

---

## 1. How telemetry reaches the detectors

| Source | What is collected | Path |
|---|---|---|
| Agent auth-log collection (Windows) | Security channel Event IDs 4624 / 4625 / 4634 / 4648 / 4672 / 4740 by EventID XPath (not Level), up to `auth_log_max_events_per_cycle` (default 32) and `auth_log_max_bytes_per_cycle` per cycle, with an Evt bookmark so events are not re-sent. The first run only sets the bookmark; no history is back-filled. Sent as `MSG_LOG_BATCH` (0x0C), **HMAC/v2 only**. The last record is also rendered into the 512-byte `raw_log_chunk` preview. | `client/src/client.cpp` (`scrape_logs`, `send_log_batch`), `client/src/win_event_log.h`, `client/src/log_batch.h` |
| Agent auth-log collection (Linux) | `/var/log/auth.log` and/or `/var/log/secure` (each if present) plus the first existing of `/var/log/syslog`, `/var/log/messages`, with inode + offset tracking and rotation handling. First run baselines to end-of-file. Same `MSG_LOG_BATCH` path and 512-byte preview. | `client/src/client.cpp` (`scrape_logs`), `client/src/log_tail.h` |
| Agent metrics | CPU, RAM, disk, net counters on the same telemetry report | `client/src/client.cpp` |
| Process / connection / session / software / FIM reports | Separate wire messages, deserialized on the server | `server/src/process_monitor.h`, `connection_inventory.h`, `session_tracker.h`, `software_inventory.h`, `fim_common.h`; dispatch in `server/src/server.cpp` |

Two server paths consume this telemetry:

- `process_report` (`server/src/server.cpp`) runs the log-oriented detectors
  (regex pack, traffic and network heuristics, IoC match, and Sigma when
  enabled) on `RawTelemetry.raw_log_chunk`, which is only the **512-byte
  preview** of the last collected record.
- `process_log_batch` handles `MSG_LOG_BATCH`: every record goes to the auth
  parsers (§2.3). Batch records are **not** passed through the regex pack or
  Sigma.

With `hmac_enabled = false` (or an HMAC/v2 handshake that fails) the agent
sends no batch and only the preview reaches the server. With
`auth_log_enabled = false` the agent also leaves `raw_log_chunk` empty. There
is no separate JSON log parser and no live syslog listener in this tree.

---

## 2. Live on `main`

### 2.1 Built-in regex rules

`server/src/regex_engine.h` (`RegexEngine::load_builtin_rules`, always on
when the server starts; `server/src/server.cpp` constructs `RegexEngine` with
`rules_file`, default `rules.conf`). Matching is per line of `raw_log_chunk`,
case-insensitive ECMAScript, lines truncated to 4 KiB, `matched_text` to 512
bytes.

User rules in `server/config/rules.conf` (pipe-delimited
`name|severity|category|pattern`) override a built-in of the same name.
The shipped `rules.conf` is comments and examples only; no extra user rules
are active unless an operator adds them.

| Rule name | Severity | Category | Detects (pattern intent) | Data source |
|---|---|---|---|---|
| `ssh_failed_password` | high | auth_failure | `failed password for … from …` (IPv4 dotted-quad) | Linux auth / syslog chunk |
| `pam_auth_failure` | high | auth_failure | `pam_unix(…): authentication failure` | Linux auth / syslog chunk |
| `sshd_invalid_user` | high | auth_failure | `invalid user … from …` (IPv4) | Linux sshd / syslog chunk |
| `win_logon_failure_4625` | high | auth_failure | `<EventID>4625</EventID>` or `event id[: ] 4625` | Windows Event XML / text in the chunk |
| `win_logon_failure_generic` | medium | auth_failure | `audit failure` … `logon` | Windows Event text |
| `su_failed` | high | auth_failure | `su[…]: failed su for …` | Linux su / syslog chunk |
| `sudo_failed` | critical | privilege_escalation | `sudo:` … `NOT in sudoers` | Linux sudo / syslog chunk |
| `sudo_session_open` | low | privilege_escalation | `sudo:` … `session opened for user root` | Linux sudo / syslog chunk |
| `win_priv_escalation_4672` | medium | privilege_escalation | Event ID 4672 (same two shapes as 4625) | Windows Event XML / text |
| `service_start_failed` | medium | service_failure | systemd unit failed to start | Linux syslog chunk |
| `oom_killer` | critical | resource_exhaustion | kernel OOM killer | Linux syslog chunk |
| `segfault` | high | crash | `segfault at <hex>` | Linux syslog chunk |
| `sshd_max_auth_exceeded` | critical | brute_force | sshd max auth attempts exceeded | Linux sshd / syslog chunk |
| `sshd_connection_reset` | medium | brute_force | connection reset/closed by … `[preauth]` | Linux sshd / syslog chunk |
| `win_account_locked_4740` | high | account_lockout | Event ID 4740 | Windows Event XML / text |
| `win_password_changed_4723` | low | account_change | Event ID 4723 | Windows Event XML / text |
| `iptables_drop` | medium | firewall | `iptables` … `DROP` | Linux syslog chunk |
| `ufw_block` | medium | firewall | `[UFW BLOCK]` | Linux syslog chunk |

The `event id[: ] NNNN` alternatives carry a trailing `\b` (fixed in #20), so
`event id: 46250` no longer matches the 4625 rule. The `<EventID>4625</EventID>`
form is exact. Oversized `rules.conf` patterns are rejected, not truncated.

### 2.2 Threshold alerts

`server/src/alert_engine.h`, fed from regex `SecurityEvent`s in
`process_report`. These are counts-in-a-window, not extra detectors. Defaults
(`AlertConfig::load_defaults`): auth_failure 5/300s, brute_force 3/60s,
privilege_escalation 2/120s, account_lockout 1/60s, resource_exhaustion
1/60s, crash 2/300s. Written to `alert_log` (default `alerts.log`).

### 2.3 Auth line parsers (live via `MSG_LOG_BATCH`)

`server/src/session_tracker.h` (`SessionScanner::parse_auth_record`) and
`server/src/auth_log_ingest.h`. The server picks the parser from the record's
source tag (`windows-security` -> Windows XML parser; `linux-auth` /
`linux-syslog` -> Linux parser), so a Linux server can parse Windows Event XML.
`client/src/session_tracker.h` is an identical copy.

- Windows: real `<EventID>` tokens or `Event ID: NNNN` text for 4624, 4625,
  4634, 4648, 4672, 4740; user and source IP from `TargetUserName` /
  `IpAddress`.
- Linux: sshd `Failed password for … from …` (failure), sshd `Accepted
  <method> for … from …` (success), any `sudo:` line containing `COMMAND`
  (privilege escalation; the user is captured, not the `sudo` token), and
  `su` lines with `Successful` / `session opened` (privilege escalation).
  Failed `su` and sshd `Invalid user` lines are **not** parsed here; they are
  only caught by the regex pack on the preview (§2.1).
- Each failed logon is forwarded twice to `AlertEngine` as `auth_failure`
  (medium) and `brute_force` (high), so the 5/300s and 3/60s thresholds in
  §2.2 apply. Privilege escalation and account lockout events map to their
  categories.
- Every auth event is ingested by `CorrelationEngine` (source `session`);
  that includes the new `auth_brute_force` rule (3 failed logons in 60s,
  per device). The second stage of `brute_force_then_login` accepts any
  `session` event, so a failed logon also satisfies it; do not describe it
  as "brute force then confirmed successful login".

Limits:
- Auth parsing runs only on `MSG_LOG_BATCH` records. If the batch is not
  sent (HMAC/v2 off, older agent or server), `process_report` still runs
  only the regex pack over the 512-byte preview.
- Parsers are `std::regex` with a 64 KiB input cap per record.
- Windows collection starts at the first run; earlier events are not
  imported. A first-run baseline also applies to Linux files.
- Usernames and IPs are only as good as the log line. A host that writes the
  same sshd/sudo line to both `auth.log` and `syslog` is read from both files,
  so the same event can arrive twice.

### 2.4 Traffic classification

`server/src/traffic_classifier.h`, called from `process_report` when
`classifier_enabled` is true (default true in `server/config/server.conf`).
Uses per-device baselines plus the raw log and regex events:

- `detect_ddos` — inbound volume vs baseline / absolute cap
- `detect_portscan` — refused connections / log patterns
- `detect_bruteforce` — auth-failure counts from regex events + log
- `detect_exfiltration` — outbound volume vs baseline / absolute cap
- `detect_c2_beaconing` — regular outbound interval / low jitter
- `detect_lateral_movement` — log-pattern heuristics

Threshold keys are `cls_*` in `server.conf`. Findings can carry a MITRE
technique from a lookup table in the same header.

### 2.5 Network deep inspection

`server/src/network_inspector.h`, used from `server/src/server.cpp` when
configured. Categories (from the header): `dns_tunnel`, `dga`,
`proto_anomaly`, `syn_flood`, `entropy`. DNS analysis looks at queries
extracted from the raw log (DGA-ish entropy/consonant ratio, deep
subdomains, a short list of suspicious TLDs). This inspects telemetry and
log text, not a packet capture TAP.

### 2.6 Threat intelligence

`server/src/threat_intel.h` (`ThreatIntelEngine::match`). Matches the agent
client IP and IPs / domains / hashes / URLs / user-agents / email / CIDR
extracted from `raw_log_chunk` against loaded feeds
(`server/src/server.cpp` loads configured feeds). The loader only reads
**`.csv` files** and the format is **pipe-delimited**
`type|value|severity|description|mitre_id|tags` (`server/src/threat_intel.h`).
It is not a JSON loader, despite `server/config/feeds/README.md` mentioning
“CSV/JSON”. The shipped `feeds/` directory has that README only — **no
indicator files ship**, so a default install matches nothing until an
operator adds CSVs. Types: `IoCType` in the header. Machine name and OS
user are accepted by the API but reserved and unused.

### 2.7 File integrity monitoring

`server/src/fim_monitor.h` (`FimMonitor::process`): compares successive
agent FIM reports and emits add/modify/delete alerts, with path-based
severity and MITRE tags in the same file. First report is a baseline, not
an alert. Data source: agent FIM reports, not the log chunk.

### 2.8 Suspicious processes and connections

- **Processes:** `server/src/process_monitor.h` (`ProcessScanner`). If
  `detect_suspicious` is true, flags names containing a default list
  (`mimikatz`, `lazagne`, `procdump`, `psexec`, `nc.exe`, `ncat`,
  `netcat`, `nmap`, `powershell_ise`, `wscript`, `cscript`, `mshta`,
  `certutil`, `bitsadmin`, `regsvr32`, `rundll32`, `whoami`,
  `systeminfo`, `tasklist`, `net.exe`, `cryptominer`, `xmrig`,
  `minerd`, `cgminer`). `server/src/server.cpp` feeds those to the
  correlator and can open a high-severity incident. Data source: agent
  process reports. Name-contains heuristics will also match some
  legitimate admin tools (`whoami`, `tasklist`, `certutil`, …).
- **Connections:** `server/src/connection_inventory.h` flags remote ports
  in a default set (4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337,
  6667, 6697, 4443, 8443). Data source: agent connection reports.
  `server/src/server.cpp` can ingest those as `suspicious_connection`.

### 2.9 Correlation

`server/src/correlation_engine.h` (`load_default_rules`), wired when
`correlation_enabled` is true. Built-in multi-stage rules (names from the
header):

| Rule | Intent (from `description` in code) | Window |
|---|---|---|
| `brute_force_then_login` | Brute force then a successful login | 600s |
| `ioc_then_exfil` | IoC match then exfil pattern | 900s |
| `fim_and_c2` | FIM change then C2 beaconing | 600s |
| `multi_device_campaign` | Multiple high-severity events across devices | 300s |
| `privesc_suspicious_proc` | Privilege escalation + suspicious process | 300s |
| `scan_then_exploit` | Port scan + exploitation attempt | 600s |
| `dns_tunnel_exfil` | DNS tunneling + exfil | 900s |

These fire only if the upstream detectors in this document actually emit
the stage events.

### 2.10 ML anomaly

`server/src/ml_anomaly.h`, landed in v5.1.0, called from `process_report`.
Isolation forest on per-device telemetry features, plus a beaconing scorer
on inter-report intervals. Output is anomaly scores / findings (exposed via
`GET /api/anomalies` in v5.1.0), not the regex alert log. Features are raw
(not per-feature normalised); the v5.1.0 notes already call that a
precision limitation. Baselines are not partitioned per tenant.

---

## 3. In v5.1.1 but off by default or partial

Do not describe these as active detections for a customer unless an operator
has turned them on and checked them.

### 3.1 Sigma subset (`sigma_enabled = false` by default)

- Header-only Sigma YAML *subset* in `server/src/sigma_engine.h`, wired by
  `server/src/sigma_ingest.h` and `process_report`. `server.cpp` reads
  `sigma_enabled` (default false) and `sigma_rules_dir`.
- When enabled, hits go to `AlertEngine::raise_sigma` (rule id, title, level)
  and to `security_events` when Postgres is up.
- It evaluates `raw_log_chunk` only (the 512-byte preview). It never sees the
  full `MSG_LOG_BATCH` records.
- Keyword-style rules can match the raw log line. Field-map rules
  (`Image|endswith`, …) need structured fields that `process_report` does not
  populate today.
- Unsupported: most community-rule features (`|cidr`, aggregations,
  auto-reload, logsource filtering, …). `sigma_auto_reload` and
  `sigma_reload_s` are not read; rules load once at startup. The older
  `server/config/sigma/README.md` claims (“~90% of community rules”, periodic
  reload) are not true of this subset.
- Sample rules under `rules/sigma/`; the existing `server/config/sigma/*.yml`
  load as keyword lists.

### 3.2 Syslog parse / CEF / LEEF helpers (no listeners)

`SyslogIngestor::parse` and `SyslogForwarder::to_cef` / `to_leef` in
`server/src/syslog_ingestor.h` are implemented and unit-tested. `add_listener`
only stores config; `start()` only flips a flag and `send()` is a no-op.
`server.cpp` does not include the header and `syslog_listener_enabled` is
unread (shipped `false`). No syslog is ingested.

The 26 Nov security and CI changes (REST fail-closed, login throttle,
gitleaks, threat model) do not add detectors.

---

## 4. Known gaps (not live, even if a flag or header exists)

| Item | Evidence | Status |
|---|---|---|
| Sigma on by default | `sigma_enabled = false` in `server/config/server.conf`; subset engine only, see §3.1 | Off until an operator enables it; preview-only input |
| Live syslog ingest (UDP 514 / TCP 6514) | `syslog_ingestor.h` has parse/serialize only (§3.2); `server.cpp` does not include it; `syslog_listener_enabled` is unread | Not implemented |
| JSON log parser | No ingest class; JSON appears in REST (`json_escape`) and Hunt, not as a partner log format | Not a detection source |
| USB / peripheral monitor | Phase 19 **PLANNED -- NOT WIRED**; `usb_monitor.h` is not included from `server.cpp`; `usb_enabled = false` | Not live |
| Reporting / compliance packs | Same file, Phase 18 **PLANNED -- NOT WIRED**; `reports_enabled = false` | Not live |
| Agent auto-update | Phase 17 **PLANNED -- NOT WIRED**; `updates_enabled` | Not live |
| OIDC | `rbac_oidc_*` keys documented as planned, not read | Not live |
| Auth-log batch without HMAC/v2 | `MSG_LOG_BATCH` is sent only when `hmac_active` | With HMAC off only the 512-byte preview reaches the server |
| Historical logons | Windows bookmark and Linux offsets baseline on first run | No back-fill of events from before the agent started |
| Windows channels other than Security | `win_event_log.h` polls Security Event IDs 4624/4625/4634/4648/4672/4740 only | Not a full channel forwarder |
| Shipped IoC feed files / JSON feeds | `server/config/feeds/` is empty except a README; the loader is pipe-CSV only | Engine is live, but default install has zero indicators |
| Cert-to-device binding | Agent mTLS is enforced (`SSL_VERIFY_FAIL_IF_NO_PEER_CERT`) on port **65432**, but any client cert signed by the CA can present any `device_id`. | Identity gap, not a missing detector |
| Per-tenant ML, complete per-route RBAC | `docs/THREAT_MODEL.md` | Isolation gaps, not missing rules |
| Community Sigma coverage, `|cidr`, correlation-style Sigma, auto-reload | §3.1 | Not supported |

---

## 5. How to talk about this before outreach

Safe: “v5.1.1 has a built-in regex pack over a 512-byte agent log preview,
and, when the agent and server run protocol v2 with HMAC (the default),
the agent ships Windows Security logon events (4624 / 4625 / 4634 / 4648 /
4672 / 4740) and Linux `auth.log` / `secure` / syslog records that the server
parses into failed-logon, privilege-escalation and lockout alerts and an
`auth_brute_force` correlation. It also has threshold alerts, traffic and DNS
heuristics, IoC matching once an operator adds pipe-delimited CSV feeds (none
ship), FIM diffs, process/connection name-and-port heuristics, a small
correlation pack, and unsupervised ML anomaly scores. Agent-to-server mTLS is
required on port 65432.”

Not safe: “We ingest syslog as a SIEM collector” (there are no syslog
listeners), “we collect every Windows event channel,” “we import historical
logs” (collection starts when the agent starts), “Sigma is on” (off by
default, preview-only, small subset), “we ship community Sigma coverage,”
“USB device control is on,” “JSON IoC feeds come pre-loaded,” “PDF reporting
is on,” “client certificates are bound to a device id,” or any claim that
macOS agents are supported.
