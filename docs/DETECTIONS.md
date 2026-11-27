# Detections inventory (v5.1.1-prep)

**Audience:** Lead Researcher, before any design-partner outreach.

**Rule:** this list is taken from the code on `v5.1.1-prep` unless a section
says otherwise. File paths are the source of truth. Config flags that exist
but are not read, and headers that are not included by `server.cpp` /
`client.cpp`, are **not** live. Do not quote this as a complete Sigma, syslog,
or USB product.

Date of inventory: 27 Nov 2026 (Europe/London). Updated later the same
morning after a read of `origin/main` (`c201c5e`, v5.1.0) and a correction
to §2.3: the auth line parsers are **not** live on `main` or on
`v5.1.1-prep`. They become live only once `fix/auth-log-inputs` is merged.

---

## 1. How telemetry reaches the detectors

| Source | What is collected | Path |
|---|---|---|
| Agent log scrape (Windows) | **One** recent Security (fallback: System) Event Log record with `Level<=3`, rendered as XML into a **512-byte** `raw_log_chunk`. The Level filter drops typical Audit Success / Information logon events (4624 / 4625 are usually Level 4). Not an Event ID subscription, not a bookmark, not a channel forwarder. | `client/src/client.cpp` (`scrape_logs`) on `main` and `v5.1.1-prep` |
| Agent log scrape (Linux) | Tail of `/var/log/syslog` or `/var/log/messages` only, into the same 512-byte chunk. **Does not** read `/var/log/auth.log` or `/var/log/secure`. No offset tracking (the same tail can be re-sent every cycle). | `client/src/client.cpp` (`scrape_logs`) on `main` and `v5.1.1-prep` |
| Agent metrics | CPU, RAM, disk, net counters on the same telemetry report | `client/src/client.cpp` |
| Process / connection / session / software / FIM reports | Separate wire messages, deserialized on the server | `server/src/process_monitor.h`, `connection_inventory.h`, `session_tracker.h`, `software_inventory.h`, `fim_common.h`; dispatch in `server/src/server.cpp` |

The server runs the log-oriented detectors on `RawTelemetry.raw_log_chunk`
inside `process_report` (`server/src/server.cpp`). There is no separate JSON
log parser and no live syslog listener in this tree.

---

## 2. Live on `v5.1.1-prep`

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

Known gap in this tree: the `event id[: ] NNNN` alternatives do **not** use
a trailing word boundary, so `event id: 46250` matches the 4625 rule (and
similarly 4672 / 4740 / 4723). The `<EventID>4625</EventID>` form is exact.
A fix lives only on the unmerged `test/parser-coverage` branch (§3).

### 2.2 Threshold alerts

`server/src/alert_engine.h`, fed from regex `SecurityEvent`s in
`process_report`. These are counts-in-a-window, not extra detectors. Defaults
(`AlertConfig::load_defaults`): auth_failure 5/300s, brute_force 3/60s,
privilege_escalation 2/120s, account_lockout 1/60s, resource_exhaustion
1/60s, crash 2/300s. Written to `alert_log` (default `alerts.log`).

### 2.3 Session / auth line parsers — NOT live on prep or main

`server/src/session_tracker.h` and the identical `client/src/session_tracker.h`
contain `parse_log_for_auth`, `parse_windows_auth`, and `parse_linux_auth`.
**Those functions are never called** from `client/src/client.cpp` or
`server/src/server.cpp` on `v5.1.1-prep` or on `main`. Session reports only
enumerate active sessions (WTS / utmp) via `scan_sessions` /
`collect_auth_events`; the pending auth-event list stays empty because
nothing feeds the parsers. On these branches the parsers are also compiled
only for the **host OS** (`#ifdef _WIN32`), so a Linux server could not
parse Windows Event XML even if a call were added.

Do **not** tell customers that authentication log parsing is live on
`main` or on `v5.1.1-prep`. The only auth-like detection that actually
runs is the regex pack over the 512-byte `raw_log_chunk` (§2.1), which
inherits the collection gaps in §1 (Windows `Level<=3`, Linux syslog
only).

The parsers become live **only once `fix/auth-log-inputs` is merged**.
That branch (off prep, not on GitHub at the time of this update):

- Collects Windows Security Event IDs 4624 / 4625 / 4634 / 4648 / 4672 /
  4740 by EventID XPath (not Level), with an Evt bookmark and more than
  one event per cycle.
- Collects `/var/log/auth.log` or `/var/log/secure` in addition to
  syslog, with inode/offset tracking and rotation handling.
- Sends records on a backward-compatible `MSG_LOG_BATCH` (0x0C); the
  512-byte `raw_log_chunk` is unchanged.
- Routes records into the parsers on the **server** by source tag (a
  Linux server can parse Windows XML), and feeds `AuthEvent`s to
  `AlertEngine` and `CorrelationEngine` (including an `auth_brute_force`
  rule).

Parser quality notes for the **unwired** prep/main copies still stand:
Linux sudo can record the username as `sudo`; a line that merely
contains “Accepted” and “password” can be treated as a success; Windows
uses a bare `4625` / `failed` substring. Those bugs are also addressed
on `test/parser-coverage` (§3) and, for the XML / source-tag path, on
`fix/auth-log-inputs`.

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

## 3. Only on unmerged branches (not live on `v5.1.1-prep`)

Do not describe these as shipping detections until the branches are
reviewed and merged.

### 3.1 `test/parser-coverage` (local, not pushed)

- Implements `SyslogIngestor::parse` / `to_cef` / `to_leef` in
  `server/src/syslog_ingestor.h` (the header already declared them). **Live
  UDP/TCP listeners remain unimplemented.**
- Tightens Windows Event ID matching (real Event ID tokens, not bare
  `4625` / `failed`); adds 4624 / 4648 / 4740; caps auth lines at 4 KiB.
- Fixes the Linux sudo username capture and the over-broad “Accepted” +
  “password” match.
- Adds `\b` on RegexEngine Event ID patterns so `event id: 46250` no longer
  matches 4625; rejects oversized `rules.conf` patterns instead of
  truncating them into compiled rules.

### 3.2 `feature/sigma-rules` (local, not pushed)

- Real header-only Sigma YAML *subset* in `server/src/sigma_engine.h` (the
  prep branch only has a declaration stub).
- Wired in `server/src/sigma_ingest.h` + `process_report` behind
  `sigma_enabled` (**default false**). Hits go to `AlertEngine::raise_sigma`
  (rule id, title, level) and to `security_events` when Postgres is up.
- Keyword-style rules can match `raw_log_chunk`. Field-map rules
  (`Image|endswith`, …) need structured fields that `process_report` does
  not populate today.
- Unsupported: most community-rule features (`|cidr`, aggregations,
  auto-reload, logsource filtering, …). The old `server/config/sigma/README.md`
  “~90% of community rules” claim is not true of this subset.
- Sample rules under `rules/sigma/`; existing `server/config/sigma/*.yml`
  load as keyword lists.

The four 26 Nov *pushed* branches (`hardening/*`, `ci/secret-scan-gitleaks`,
`security/threat-model-v511`) are security, CI, and documentation. They do
not add detectors.

---

## 4. Known gaps (not live, even if a flag or header exists)

| Item | Evidence | Status |
|---|---|---|
| Sigma on `v5.1.1-prep` | `server/src/sigma_engine.h` is declarations only; `server.cpp` does not `#include` it; `sigma_enabled` in `server/config/server.conf` is not read | Not live. Subset + flag exist only on `feature/sigma-rules`. |
| Live syslog ingest (UDP 514 / TCP 6514) | `server/src/syslog_ingestor.h` has no function bodies on prep; `server.cpp` does not include it. `syslog_listener_enabled` defaults false | Not implemented. Parse/serialize only, on `test/parser-coverage`. |
| JSON log parser | No ingest class; JSON appears in REST (`json_escape`) and Hunt, not as a partner log format | Not a detection source |
| USB / peripheral monitor | Phase 19 **PLANNED -- NOT WIRED**; `usb_monitor.h` is not included from `server.cpp`. On prep/main the shipped conf still has `usb_enabled = true` (unread). Local `fix/config-honest-flags` sets it false. | Not live |
| Reporting / compliance packs | Same file, Phase 18 **PLANNED -- NOT WIRED** | Not live |
| Agent auto-update | Phase 17 **PLANNED -- NOT WIRED**; `updates_enabled` | Not live |
| OIDC | `rbac_oidc_*` keys documented as planned, not read | Not live |
| Full Windows Event Log shipping | On prep/main, `scrape_logs` queries **one** recent `Level<=3` event (Audit Success / Information logons such as 4624/4625 are typically missed). Bookmark + EventID query exists only on unmerged `fix/auth-log-inputs`. | Not a full channel forwarder on prep/main |
| Linux auth logs (`/var/log/auth.log`, `/var/log/secure`) | Prep/main read only syslog/messages. Auth files + offset tracking are on unmerged `fix/auth-log-inputs`. | Not collected on prep/main |
| Auth line parsers producing alerts / correlation | `parse_log_for_auth` is never called on prep/main (see §2.3). | **Not live** until `fix/auth-log-inputs` |
| Shipped IoC feed files / JSON feeds | `server/config/feeds/` is empty except a README; the loader is pipe-CSV only | Engine is live, but default install has zero indicators |
| Cert-to-device binding | Agent mTLS is enforced (`SSL_VERIFY_FAIL_IF_NO_PEER_CERT`) on port **65432**, but any client cert signed by the CA can present any `device_id`. | Identity gap, not a missing detector |
| Per-tenant ML, complete per-route RBAC | Threat model on `security/threat-model-v511` | Isolation gaps, not missing rules |
| Community Sigma coverage, `|cidr`, correlation-style Sigma, auto-reload | `feature/sigma-rules` subset notes | Not supported even on that branch |

---

## 5. How to talk about this before outreach

Safe: “v5.1.1-prep has a built-in regex pack on a 512-byte agent log
preview (Linux syslog/messages, or one recent Windows Event XML that
passed `Level<=3`), threshold alerts, traffic and DNS heuristics, IoC
matching once an operator adds pipe-delimited CSV feeds (none ship),
FIM diffs, process/connection name-and-port heuristics, a small
correlation pack, and unsupervised ML anomaly scores. Agent-to-server
mTLS is required on port 65432.”

Not safe: “We ingest syslog and Windows Event Logs as a SIEM collector,”
“authentication log parsing is live,” “we read auth.log / Security
logon events 4624/4625,” “Sigma is on,” “USB device control is on,”
“we ship community Sigma coverage,” “JSON IoC feeds come pre-loaded,”
“PDF reporting is on,” “client certificates are bound to a device id,”
or any claim that the unmerged parser, Sigma, or `fix/auth-log-inputs`
work is already on `main` or `v5.1.1-prep`.
