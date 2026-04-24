# SecureSeaHorse v5.0 — README delta

Apply these two edits to `README.md` in the repo root. Everything else in
the current README stays as-is.

---

## Edit 1 — Replace the Roadmap section at the bottom of README.md

Swap the existing "Roadmap (Phases 16-25)" table for this block:

---

## Milestone Releases (Phases 16-25)

Every phase ships behind a config flag and is independently deployable on top
of the v3.1.4 hardening baseline. See `docs/PHASES_16_25_CHANGELOG.md` for the
full release notes and `docs/SERVER_INTEGRATION_SNIPPETS.md` for the exact
`server.cpp` edits.

### v3.5 — Detection Content & Operations

| Phase | Feature | File |
|-------|---------|------|
| 16 | **Sigma Rule Engine** — import community Sigma YAML, evaluate against every event | `src/server/sigma_engine.h` |
| 17 | **Agent Self-Protection & Auto-Update** — tamper baseline, watchdog, signed updates | `src/client/self_protection.h` |
| 18 | **Reporting & Compliance** — HTML/PDF reports for PCI DSS, HIPAA, SOC 2, ISO 27001 | `src/server/report_generator.h` |

### v4.0 — Enterprise Platform

| Phase | Feature | File |
|-------|---------|------|
| 19 | **USB & Peripheral Monitor** — hotplug detection, VID:PID whitelist, new `MSG_USB_REPORT (0x08)` | `src/client/usb_monitor.h` |
| 20 | **Multi-Tenancy & RBAC** — 4 roles, JWT HS256, tenant isolation, audit log | `src/server/rbac.h` |
| 21 | **SOAR Integration** — Splunk SOAR, Cortex XSOAR, TheHive, generic webhook (bidirectional) | `src/server/soar_connector.h` |

### v4.5 — Advanced Detection

| Phase | Feature | File |
|-------|---------|------|
| 22 | **Syslog Ingestion & Forwarding** — RFC 5424 + 3164 listener, CEF / LEEF / RFC 5424 output | `src/server/syslog_io.h` |
| 23 | **Threat Hunting DSL** — SPL-style pipeline compiled to parameterised SQL | `src/server/hunt_query.h` |
| 24 | **ML Anomaly Detection** — extended isolation forest + beaconing scorer, pure C++17 | `src/server/ml_anomaly.h` |

### v5.0 — Full Platform

| Phase | Feature | File |
|-------|---------|------|
| 25 | **React Web UI** — multi-page SPA with WebSocket live stream, incident workflow, hunt, reports | `src/webui/index.html` |

### Rollout order

Phases are additive and backward-compatible. Recommended order if you want
to stage the upgrade:

```
3.5.0  Sigma                    (detection content, low risk)
3.5.1  Self-protection           (client-side, tamper baseline)
3.5.2  Reporting                 (server-side, offline generation)
4.0.0  USB monitor               (client-side, new wire message)
4.0.1  RBAC                      (enable rbac_enabled after users provisioned)
4.0.2  SOAR                      (outbound first, inbound later)
4.5.0  Syslog I/O                (enable listener when ingestion needed)
4.5.1  Hunt DSL                  (analyst tool, no data-path change)
4.5.2  ML anomaly                (train for 24h before acting on findings)
5.0.0  React UI                  (run alongside embedded dashboard)
```

---

## Edit 2 — Bump the header version and status line

Change the first two lines of README.md from:

```
# 🐴 SecureSeaHorse v3.1.4: Complete SIEM Platform

**Release Date:** April 22, 2026
**Status:** Hardening & Security Audit Release (Phase 15)
```

...to:

```
# 🐴 SecureSeaHorse v5.0.0: Complete SIEM Platform

**Release Date:** April 2026
**Status:** Platform Release — Phases 1-25 complete
```

---

## Edit 3 — Update the Wire Protocol Message Types table

Add a row for Phase 19:

| Msg Type | Hex | Direction | Phase | Description |
| :---: | :---: | :---: | :---: | :--- |
| USB_REPORT | 0x08 | C → S | 19 | USB device snapshot + hotplug events |

---

That's it. The rest of the README is accurate for the extended build.
