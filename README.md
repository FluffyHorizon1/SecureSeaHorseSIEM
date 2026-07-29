# 🐴 SecureSeaHorse SIEM v5.0.0 — split layout

Two fully independent programs in one repo. Each folder builds on its own —
no shared build, no shared CMake, no cross-folder includes.

```
SecureSeaHorse/
├── server/          # Central analysis server  → binary: SeaHorseServer
├── client/          # Endpoint telemetry agent → binary: SeaHorseClient
├── installer/       # Linux + Windows installers (build both programs)
├── docs/            # User manual + phase changelogs
├── CHANGELOG.md     # v1.0.1 → v5.0.0 history with rationale
├── ROADMAP.md       # v5.x → v10 plan
├── LICENSE
└── .gitignore
```

## Build the server

```bash
cd server
mkdir build && cd build
cmake .. && make -j$(nproc)          # Linux
# or: cmake .. -DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake  (Windows)
./SeaHorseServer --config server.conf
```

Requires OpenSSL 3.0+ and PostgreSQL client libs (libpq). Configs, sigma
rules, threat-intel feeds, and the USB whitelist are staged into the build
directory automatically.

## Build the client

```bash
cd client
mkdir build && cd build
cmake .. && make -j$(nproc)
./SeaHorseClient --config client.conf
```

Requires OpenSSL only — the agent has no database dependency.

## Certificates

Both programs need mTLS certs (see `server/certs/README.md` and
`client/certs/README.md`). Generate a test set with:

```bash
sudo ./installer/install_linux.sh certs
```

## Docs

Full feature documentation lives in `docs/USER_MANUAL.md`. Version history
with per-release rationale is in `CHANGELOG.md`; the forward plan through
v10 is in `ROADMAP.md`.
