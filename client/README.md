# SeaHorseClient v5.1.1

Endpoint telemetry agent. Standalone program — builds independently of the
server, no database dependency.

## What it does

**Live in v5.1.1:** Collects and ships to the server over mTLS (`port 65432`,
protocol v2, HMAC-SHA256): system telemetry + log chunks, file-integrity
snapshots (SHA-256), process inventory with suspicious-tool detection, TCP/UDP
connection inventory, user session + auth events, and installed-software
inventory.

**Planned / not yet wired in v5.1.1:** Phase 17 self-protection watchdog /
signed auto-update and Phase 19 USB attach/detach reporting (`usb_monitor.h`)
exist as headers and are not yet wired into `client.cpp`.

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
├── src/                    # client.cpp + headers (self-contained)
├── config/client.conf      # WIRED vs PLANNED sections marked
└── certs/                  # put ca/client certs here (gitignored)
```
