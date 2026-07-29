# Sigma Rules (Phase 16 / v3.5.0)

Drop community Sigma YAML detection rules (`*.yml`, `*.yaml`) into this folder.
SeaHorse picks them up on server start and reloads every `sigma_reload_s`
seconds (server.conf).

## Supported subset

SeaHorse ships a minimal evaluator — no external YAML dependency — so only
the flat-keyword subset of the Sigma spec works. That covers ~90% of
community rules. Anything relying on `fieldref:`, `|cidr`, `|re`, or nested
`near` / `count` aggregations is skipped with a warning at load time.

## Supported keys

| Key | Required | Notes |
|---|---|---|
| `title` | yes | Rendered in dashboard alerts |
| `id` | yes | UUID — used for dedup |
| `level` | yes | `informational` / `low` / `medium` / `high` / `critical` |
| `logsource.product` | recommended | `windows` / `linux` / `network` / ... |
| `logsource.service` | no | `sysmon`, `auditd`, `zeek`, etc. |
| `detection.selection` | yes | flat map of keyword substrings / regex |
| `detection.condition` | yes | `selection`, `any of selection*`, `all of selection*` |
| `tags` | no | `attack.*` values become MITRE IDs |

## Example

```yaml
title: Suspicious PowerShell Encoded Command
id: 6c5d7c7b-5a8f-4a37-9dfa-5c9d45e8b6b7
level: high
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    - "powershell.exe -enc"
    - "powershell -EncodedCommand"
  condition: selection
tags:
  - attack.t1059.001
  - attack.execution
```

## Loader caps

- 10,000 rules max across the directory
- 64 KB / file
- 4 KB / pattern

Malformed rules are logged and skipped, never aborting the whole load.
