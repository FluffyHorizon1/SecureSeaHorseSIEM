# SeaHorseServer v5.1.1

Central SIEM analysis server. Standalone program — builds independently of
the client.

## What it does

**Live in v5.1.1:** Accepts mTLS connections (port `65432`, protocol v2 with
HMAC-SHA256) from SeaHorse agents, then runs events through: regex + threshold
alerting, 6-category traffic classification with MITRE ATT&CK tags,
threat-intel IoC matching, file integrity monitoring (FIM), deep network
inspection, cross-device correlation, incident-response playbooks, fleet
management, labeled `alert_history` persistence, PBKDF2 + JWT RBAC/multi-tenancy,
parameterized Hunt DSL (`POST /api/hunt`), and unsupervised ML anomaly detection
(`GET /api/anomalies`) behind the REST API and embedded dashboard (`127.0.0.1:8080`).

**Planned / not yet wired in v5.1.1:** Sigma YAML engine (Phase 32), agent
auto-update/self-protection (Phase 17), scheduled compliance reports (Phase 18),
USB whitelist monitor (Phase 19), SOAR connectors (Phase 21), syslog
listener/forwarder (Phase 22), and WebSocket/React SPA (Phase 25). See
`server/config/server.conf`, `CHANGELOG.md`, and `ROADMAP.md` for details.

## Dependencies

* C++17 compiler (MSVC 2019+, GCC 9+, Clang 7+)
* OpenSSL 3.0+
* PostgreSQL 14+ client libs (`libpq`) — server falls back to CSV if the DB is down
* CMake 3.15+

## Build

```bash
mkdir build && cd build
cmake ..
make -j$(nproc)
```

Windows (vcpkg):

```powershell
vcpkg install openssl:x64-windows libpq:x64-windows
mkdir build; cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake
cmake --build . --config Release
```

## Run

```bash
./SeaHorseServer --config server.conf
# Dashboard: http://127.0.0.1:8080  (loopback default; set rest_api_token or RBAC to expose)
```

`server.conf`, `rules.conf`, `sigma/`, `feeds/`, `usb_whitelist.csv`, and
`updates/` are staged into the build directory at configure time. Runtime
paths in `server.conf` are relative to the working directory.

## Layout

```
server/
├── CMakeLists.txt
├── src/                    # server.cpp + headers (self-contained)
├── config/
│   ├── server.conf         # WIRED vs PLANNED sections clearly marked
│   ├── rules.conf          # regex analysis rules
│   ├── sigma/              # Sigma YAML rules (pending Phase 32 wiring)
│   ├── feeds/              # feed drop-dir README
│   └── usb_whitelist.csv   # Phase 19 peripheral whitelist (planned)
├── feeds/                  # sample threat-intel CSVs (45 indicators)
├── updates/manifest.json   # Phase 17 signed-update manifest (planned)
├── certs/                  # put ca/server certs here (gitignored)
└── scripts/                # incident-response scripts
```
