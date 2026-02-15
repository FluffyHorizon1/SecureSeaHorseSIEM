# 🐴 SecureSeaHorse SIEM

**v1.3.0** · Lightweight, High-Security SIEM System

---

SecureSeaHorse is a Security Information and Event Management (SIEM) system built in C++. It features mutual TLS (mTLS) encryption, regex-based log analysis, threshold alerting, and dual storage capability (PostgreSQL + CSV).

## Features

- **Secure Communication** — Full mutual TLS (mTLS) encryption between Client and Server.
- **Real-time Analysis** — Regex-based engine to detect specific threats (SSH failures, SQL injection, etc.).
- **Alerting Engine** — Threshold-based logic (e.g., "5 failed logins in 1 minute") triggers alerts.
- **Dual Persistence** — PostgreSQL for production; automatic CSV fallback if the DB is unreachable.
- **Cross-Platform** — Runs on Windows (MSVC) and Linux (GCC/Clang).

---

## Prerequisites

### Windows

- [Visual Studio 2022](https://visualstudio.microsoft.com/) (with C++ Desktop Development workload)
- [CMake](https://cmake.org/) (included with VS or installed separately)
- [Git](https://git-scm.com/)
- [Vcpkg](https://github.com/microsoft/vcpkg) (Package Manager)

### Linux (Ubuntu / Debian)

```bash
sudo apt-get update
sudo apt-get install build-essential cmake libssl-dev libpq-dev git
```

---

## Build Instructions

### Windows (Visual Studio + Vcpkg)

**1. Install dependencies:**

```powershell
cd C:\
git clone https://github.com/microsoft/vcpkg.git
cd vcpkg
.\bootstrap-vcpkg.bat
.\vcpkg integrate install
.\vcpkg install openssl:x64-windows libpq:x64-windows
```

**2. Build the project:**

```powershell
mkdir build
cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake
cmake --build . --config Release
```

**3. Locate executables:** compiled files will be in `build\Release\`.

### Linux

```bash
mkdir build && cd build
cmake ..
make
```

---

## Certificate Generation (mTLS)

This system requires valid certificates to run. Run these commands using **Git Bash** (Windows) or **Terminal** (Linux) inside your `build` folder.

### 1. Generate CA & Server Keys

```bash
# Generate CA/Server key pair
openssl req -x509 -newkey rsa:4096 \
  -keyout server.key -out server.crt \
  -days 365 -nodes -subj "/CN=localhost"

# Create CA file (self-signed server cert acts as CA)
cp server.crt ca.crt
```

### 2. Generate Client Keys

```bash
# Generate client key
openssl genrsa -out client.key 2048

# Create signing request
openssl req -new -key client.key -out client.csr -subj "/CN=client"

# Sign client cert with server cert
openssl x509 -req -in client.csr \
  -CA server.crt -CAkey server.key \
  -CAcreateserial -out client.crt -days 365
```

> **Important:** Ensure `server.conf` and `client.conf` point to these files, or place the certificate files in the same directory as your executables.

---

## Configuration

### `server.conf`

Place next to `SeaHorseServer.exe`.

```ini
port       = 65432
db_enabled = true          # Set to false for CSV-only mode
rules_file = rules.conf    # Regex detection rules
ca_path    = ca.crt
server_crt = server.crt
server_key = server.key
```

### `client.conf`

Place next to `SeaHorseClient.exe`.

```ini
server_ip  = 127.0.0.1
port       = 65432
ca_path    = ca.crt
client_crt = client.crt
client_key = client.key
```

---

## How to Run

### 1. Start the Server

Navigate to your build folder (e.g., `build/Release`) and run:

```
SeaHorseServer.exe
```

Expected output:

```
[INFO] Secure mTLS Server started on Port 65432
```

### 2. Start the Client

Open a **new terminal** (Run as Administrator recommended for full log access) and run:

```
SeaHorseClient.exe
```

Expected output:

```
[INFO] Connected to server!
```

---

## Troubleshooting

| Problem | Cause | Solution |
|---|---|---|
| `PostgreSQL connection failed` | No local PostgreSQL server running. | Install PostgreSQL, or set `db_enabled = false` in `server.conf`. The server automatically falls back to CSV mode (`s_log.csv`). |
| `Failed to load CA certificate` | The executable cannot find `ca.crt`. | Ensure `ca.crt` is in the same directory as the `.exe` and that `server.conf` uses `ca_path = ca.crt` (not `certs/ca.crt`). |
| Client closes immediately | Program finishes execution or crashes silently. | Run from the command prompt (`cmd.exe`) instead of double-clicking, or add `system("pause");` at the end of your code. |
