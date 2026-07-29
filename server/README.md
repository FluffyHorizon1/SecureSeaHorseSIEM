# SeaHorseServer v5.0.0

Central SIEM analysis server. Standalone program — builds independently of
the client.

## What it does

Accepts mTLS connections from SeaHorse agents (and passive syslog sources),
then runs every event through: regex + threshold alerting, Sigma rules,
6-category traffic classification, threat-intel IoC matching, deep network
inspection, ML anomaly scoring, and the cross-device correlation engine.
Correlated incidents trigger incident-response playbooks (IP blocklist,
quarantine, webhooks, SOAR hand-off). Everything is queryable via the REST
API, the Hunt DSL, and the React dashboard with live WebSocket streams.

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
# Dashboard: http://localhost:8080  (token from server.conf rest_api_token)
```

`server.conf`, `rules.conf`, `sigma/`, `feeds/`, `usb_whitelist.csv`, and
`updates/` are staged into the build directory at configure time. Runtime
paths in `server.conf` are relative to the working directory.

## Layout

```
server/
├── CMakeLists.txt
├── src/                    # server.cpp + 25 headers (self-contained)
├── config/
│   ├── server.conf         # all 25 phases documented inline
│   ├── rules.conf          # regex analysis rules
│   ├── sigma/              # Sigma YAML rules (3 samples + README)
│   ├── feeds/              # feed drop-dir README
│   └── usb_whitelist.csv   # Phase 19 peripheral whitelist
├── feeds/                  # sample threat-intel CSVs (45 indicators)
├── updates/manifest.json   # Phase 17 signed-update manifest
├── certs/                  # put ca/server certs here (gitignored)
└── scripts/                # incident-response scripts
```
