# SeaHorseClient v5.0.0

Endpoint telemetry agent. Standalone program — builds independently of the
server, no database dependency.

## What it does

Collects and ships to the server over mTLS (protocol v2, HMAC-signed):
system telemetry + log chunks, file-integrity snapshots (SHA-256), process
inventory with suspicious-tool detection, TCP/UDP connection inventory,
user session + auth events, installed-software inventory, and USB
attach/detach events. Phase 17 self-protection adds a watchdog, self-hash
verification, and signed auto-update.

## Dependencies

* C++17 compiler (MSVC 2019+, GCC 9+, Clang 7+)
* OpenSSL 3.0+
* CMake 3.15+

## Build

```bash
mkdir build && cd build
cmake ..
make -j$(nproc)
```

Windows (vcpkg):

```powershell
vcpkg install openssl:x64-windows
mkdir build; cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake
cmake --build . --config Release
```

## Run

```bash
./SeaHorseClient --config client.conf
```

Set `server_ip`, `device_id`, and cert paths in `client.conf` first. The
config is staged into the build directory at configure time.

## Layout

```
client/
├── CMakeLists.txt
├── src/                    # client.cpp + 10 headers (self-contained)
├── config/client.conf      # all agent modules documented inline
└── certs/                  # put ca/client certs here (gitignored)
```
