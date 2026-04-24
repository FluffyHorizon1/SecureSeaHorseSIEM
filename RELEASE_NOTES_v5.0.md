# SecureSeaHorse v5.0 — Phases 16-25 Release Package

This directory contains every new file needed to extend SecureSeaHorse
v3.1.4 to v5.0, covering the full roadmap from the README.

## File layout

```
src/
├── server/
│   ├── sigma_engine.h        # Phase 16 — Sigma YAML rule engine
│   ├── report_generator.h    # Phase 18 — Compliance reports
│   ├── rbac.h                # Phase 20 — Multi-tenancy + JWT + audit
│   ├── soar_connector.h      # Phase 21 — SOAR integration
│   ├── syslog_io.h           # Phase 22 — Syslog listener + forwarder
│   ├── hunt_query.h          # Phase 23 — SPL-style hunt DSL
│   └── ml_anomaly.h          # Phase 24 — Isolation forest + beaconing
│
├── client/
│   ├── self_protection.h     # Phase 17 — Tamper, watchdog, auto-update
│   └── usb_monitor.h         # Phase 19 — USB hotplug + whitelist
│
└── webui/
    └── index.html            # Phase 25 — React SPA scaffold

config/
├── server.conf               # v5.0 keys for every new subsystem
└── client.conf               # Self-protection + USB monitor keys

docs/
├── PHASES_16_25_CHANGELOG.md # Per-phase release notes
├── SERVER_INTEGRATION_SNIPPETS.md  # Exact server.cpp edits
└── README_DELTA.md           # README patch for milestone table

CMakeLists.txt                # v5.0.0 build with all new headers
```

## Install steps

```bash
# From the SecureSeaHorse-v3.1.4 repo root, with this package extracted nearby:

# 1. Drop new headers into place
cp outputs/src/server/*.h  SecureSeaHorseSIEM/src/server/
cp outputs/src/client/*.h  SecureSeaHorseSIEM/src/client/

# 2. New Web UI directory
mkdir -p SecureSeaHorseSIEM/src/webui
cp outputs/src/webui/index.html SecureSeaHorseSIEM/src/webui/

# 3. Overwrite build and config (or diff-merge if you've customised them)
cp outputs/CMakeLists.txt        SecureSeaHorseSIEM/
cp outputs/config/server.conf    SecureSeaHorseSIEM/config/
cp outputs/config/client.conf    SecureSeaHorseSIEM/config/

# 4. Drop the new docs in
cp outputs/docs/*.md             SecureSeaHorseSIEM/docs/

# 5. Wire MSG_USB_REPORT into both crypto_utils.h copies
# (see README_DELTA.md -- Edit 3, or just check the enum in
# src/server/crypto_utils.h and src/client/crypto_utils.h -- the
# line MSG_USB_REPORT = 0x08 should already be present after
# pulling this package's version)

# 6. Edit server.cpp per docs/SERVER_INTEGRATION_SNIPPETS.md to wire
# each new subsystem into main() and process_report().

# 7. Apply the README patch per docs/README_DELTA.md.

# 8. Build normally.
cd SecureSeaHorseSIEM && mkdir -p build && cd build && cmake .. && make -j
```

## Rollout recommendation

Every phase is gated by its own `*_enabled` config flag and is
backward-compatible with v3.1.4 clients and servers. The recommended
order is:

1. **Sigma, Self-protection, Reporting** — low-risk detection / ops
2. **USB monitor** — adds a new wire message; update clients first
3. **RBAC** — flip on after provisioning the first admin user via the
   one-shot `./SeaHorseServer --admin-bootstrap ...` CLI
4. **SOAR** — start outbound-only, enable inbound when the partner
   platform is ready
5. **Syslog I/O** — turn on the listener once upstream feeders are
   pointed at it
6. **Hunt DSL** — no data-path change, safe at any time
7. **ML anomaly** — train for at least 24h before acting on findings
   (warmup + a few retrain cycles give a stable forest)
8. **React UI** — run alongside the embedded dashboard until cutover

## Known follow-ups

- `rest_server.h` needs a WebSocket upgrade path for `/ws/stream`
  (the Phase 25 SPA's `useLiveStream` hook). The UI degrades
  gracefully to 15-second REST polling if the endpoint is absent.
- `correlations_view` SQL view needs to be created in PostgreSQL once
  to back the Phase 23 hunt source (SQL in the changelog).
- Phase 18 PDF output depends on `wkhtmltopdf` or `weasyprint` being
  on PATH. HTML is always produced; PDF is opportunistic.

## Contact

This package is part of the Secured Cyber Solutions SecureSeaHorse
product line. Licensing terms are unchanged from v3.1.4 — see
`LICENSE` in the main repository.
