# SecureSeaHorse SIEM v3.0.0 -- User Manual

---

## Table of Contents

1. Introduction
2. System Requirements
3. Installation
   - 3.1 Building from Source (All Platforms)
   - 3.2 Linux Installation
   - 3.3 Windows Installation
   - 3.4 TLS Certificate Setup
4. Configuration Reference
   - 4.1 Server Configuration (server.conf)
   - 4.2 Client Configuration (client.conf)
   - 4.3 Detection Rules (rules.conf)
5. Getting Started -- First Run
6. Architecture Overview
7. Feature Reference
   - 7.1 Core Telemetry (Phases 1-3)
   - 7.2 Threat Detection (Phase 4)
   - 7.3 Threat Intelligence Feeds (Phase 5)
   - 7.4 File Integrity Monitoring (Phase 6)
   - 7.5 REST API & Web Dashboard (Phase 7)
   - 7.6 Incident Response Automation (Phase 8)
   - 7.7 Agent Fleet Management (Phase 9)
   - 7.8 Network Deep Inspection (Phase 10)
   - 7.9 Process Monitor (Phase 11)
   - 7.10 Network Connection Inventory (Phase 12)
   - 7.11 User Session & Auth Tracker (Phase 13)
   - 7.12 Software & Patch Inventory (Phase 14)
   - 7.13 Correlation Engine (Phase 15)
8. REST API Reference
9. Web Dashboard Guide
10. Database Setup (PostgreSQL)
11. Operational Guide
    - 11.1 Running as a Service
    - 11.2 Log Management
    - 11.3 Backup and Recovery
    - 11.4 Performance Tuning
12. Security Hardening
13. Troubleshooting
14. File Reference

---

## 1. Introduction

SecureSeaHorse is a lightweight, open-source Security Information and Event Management (SIEM) system written in C++17 with zero external runtime dependencies beyond OpenSSL. It consists of two components:

**Server** -- Receives telemetry from agents, analyzes data for threats, manages a web dashboard, and orchestrates automated incident response.

**Client Agent** -- Runs on monitored endpoints (Windows or Linux), collecting system metrics, log data, process information, network connections, user sessions, and file integrity snapshots, then securely transmitting everything to the server over mutual TLS.

Key capabilities include real-time traffic classification, threat intelligence feed matching, file integrity monitoring, process and connection inventory, user session tracking, software inventory, cross-device correlation, automated incident response with IP blocking and device quarantine, and a live web dashboard with full REST API.

---

## 2. System Requirements

### Server

| Requirement | Minimum | Recommended |
|---|---|---|
| OS | Ubuntu 20.04, RHEL 8, Windows 10 | Ubuntu 24.04, Windows Server 2022 |
| CPU | 2 cores | 4+ cores |
| RAM | 2 GB | 8 GB |
| Disk | 10 GB | 50 GB (with DB) |
| Compiler | GCC 9+ or MSVC 2019+ | GCC 13+ or MSVC 2022 |
| CMake | 3.15+ | 3.25+ |
| OpenSSL | 1.1.1+ | 3.0+ |
| PostgreSQL | 14+ (optional) | 16+ |

### Client Agent

| Requirement | Minimum |
|---|---|
| OS | Windows 10+, Ubuntu 18.04+, RHEL 7+ |
| CPU | 1 core |
| RAM | 256 MB |
| Disk | 50 MB |
| Network | TCP connectivity to server on port 9443 |

---

## 3. Installation

### 3.1 Building from Source (All Platforms)

The project uses CMake. The folder structure is:

```
SecureSeaHorse-v3.0.0/
  CMakeLists.txt
  src/
    server.cpp           # Server main
    client.cpp           # Client main
    server_protocol.h    # Wire protocol (server)
    client_protocol.h    # Wire protocol (client)
    crypto_utils.h       # HMAC-SHA256, heartbeat, CRL/OCSP
    regex_engine.h       # Log analysis regex patterns
    alert_engine.h       # Threshold alerting
    db_layer.h           # PostgreSQL persistence
    traffic_classifier.h # ML-style traffic classification
    mitre_map.h          # MITRE ATT&CK technique mapping
    threat_intel.h       # IoC feed loading and matching
    fim_common.h         # FIM data structures
    fim_scanner.h        # Client-side file hashing
    fim_monitor.h        # Server-side FIM processor
    baseline_tracker.h   # Per-device file baselines
    rest_server.h        # Embedded HTTP server
    dashboard_html.h     # Web dashboard HTML/JS
    incident_response.h  # Playbook engine
    fleet_manager.h      # Device inventory
    network_inspector.h  # DNS/protocol/entropy analysis
    process_monitor.h    # Process enumeration
    connection_inventory.h # TCP/UDP connection scanner
    session_tracker.h    # User session and auth events
    software_inventory.h # Installed software enumeration
    correlation_engine.h # Cross-device event correlation
  config/
    server.conf
    client.conf
    rules.conf
    feeds/               # Threat intel CSV files
  certs/                 # TLS certificates
  scripts/               # Incident response scripts
```

**Build steps:**

```bash
cd SecureSeaHorse-v3.0.0
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)    # Linux/macOS
# or: cmake --build . --config Release   # Windows
```

This produces two executables:
- `SeaHorseServer` (or `SeaHorseServer.exe`)
- `SeaHorseClient` (or `SeaHorseClient.exe`)

**Build options:**

```bash
cmake .. -DWITH_POSTGRESQL=OFF   # Disable PostgreSQL (CSV-only mode)
cmake .. -DCMAKE_INSTALL_PREFIX=/opt/seahorse
```

### 3.2 Linux Installation

Use the provided installer script:

```bash
# Build from source and install both server + client
sudo ./installer/install_linux.sh build

# Or install components individually
sudo ./installer/install_linux.sh server
sudo ./installer/install_linux.sh client

# Generate self-signed TLS certificates for testing
sudo ./installer/install_linux.sh certs
```

The installer creates:
- `/opt/seahorse/server/` -- Server binary, config, logs
- `/opt/seahorse/client/` -- Client binary, config, logs
- Systemd service files for both components
- A dedicated `seahorse` service user

**Start the services:**

```bash
sudo systemctl enable --now seahorse-server
sudo systemctl enable --now seahorse-client
sudo systemctl status seahorse-server
```

### 3.3 Windows Installation

**Option A: NSIS Installer (recommended)**

1. Build the project first with Visual Studio or CMake.
2. Place `SeaHorseServer.exe` and `SeaHorseClient.exe` into a `build/` directory.
3. Run NSIS compiler: `makensis installer/installer_windows.nsi`
4. Execute the generated `SecureSeaHorse-v3.0.0-Setup.exe`.
5. Choose which components to install (Server, Client, or both).

The installer:
- Installs to `C:\Program Files\SecureSeaHorse\`
- Creates Windows services (SeaHorseServer, SeaHorseClient)
- Adds firewall rules for ports 9443 and 8080
- Creates Start Menu shortcuts

**Option B: Manual Installation**

1. Create `C:\SeaHorse\server\` and `C:\SeaHorse\client\`
2. Copy executables and config files to the appropriate directories.
3. Register as Windows services:

```cmd
sc create SeaHorseServer binPath= "C:\SeaHorse\server\seahorse-server.exe --config C:\SeaHorse\server\server.conf" start= auto
sc create SeaHorseClient binPath= "C:\SeaHorse\client\seahorse-client.exe --config C:\SeaHorse\client\client.conf" start= auto
```

### 3.4 TLS Certificate Setup

SecureSeaHorse uses mutual TLS (mTLS). Both server and client must present certificates signed by the same CA.

**Generate certificates with OpenSSL:**

```bash
# 1. Create CA
openssl req -x509 -newkey rsa:4096 -days 365 -nodes \
  -keyout ca-key.pem -out ca.pem \
  -subj "/CN=SeaHorse-CA/O=YourOrg"

# 2. Create server certificate
openssl req -newkey rsa:2048 -nodes \
  -keyout server-key.pem -out server.csr \
  -subj "/CN=seahorse-server"
openssl x509 -req -in server.csr \
  -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
  -days 365 -out server.pem

# 3. Create client certificate
openssl req -newkey rsa:2048 -nodes \
  -keyout client-key.pem -out client.csr \
  -subj "/CN=seahorse-client"
openssl x509 -req -in client.csr \
  -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
  -days 365 -out client.pem

# 4. Clean up CSRs
rm -f *.csr *.srl
```

**Place certificates:**

| File | Server Location | Client Location |
|---|---|---|
| `ca.pem` | `certs/ca.pem` | `certs/ca.pem` |
| `server.pem` | `certs/server.pem` | -- |
| `server-key.pem` | `certs/server-key.pem` | -- |
| `client.pem` | -- | `certs/client.pem` |
| `client-key.pem` | -- | `certs/client-key.pem` |

Or use the automated installer: `sudo ./installer/install_linux.sh certs`

---

## 4. Configuration Reference

### 4.1 Server Configuration (server.conf)

All settings use `key = value` format. Lines starting with `#` are comments.

#### Network & TLS

| Key | Default | Description |
|---|---|---|
| `tls_port` | `9443` | Port for mTLS agent connections |
| `tls_bind` | `0.0.0.0` | Bind address |
| `cert_file` | `certs/server.pem` | Server TLS certificate |
| `key_file` | `certs/server-key.pem` | Server TLS private key |
| `ca_file` | `certs/ca.pem` | CA certificate for client verification |

#### Thread Pool

| Key | Default | Description |
|---|---|---|
| `thread_pool_min` | `4` | Minimum worker threads |
| `thread_pool_max` | `32` | Maximum worker threads |

#### PostgreSQL (Optional)

| Key | Default | Description |
|---|---|---|
| `pg_enabled` | `false` | Enable PostgreSQL persistence |
| `pg_host` | `localhost` | Database host |
| `pg_port` | `5432` | Database port |
| `pg_dbname` | `seahorse` | Database name |
| `pg_user` | `seahorse` | Database user |
| `pg_password` | _(empty)_ | Database password |

#### Phase 4: Traffic Classification

| Key | Default | Description |
|---|---|---|
| `classifier_enabled` | `true` | Enable traffic classification engine |

#### Phase 5: Threat Intelligence

| Key | Default | Description |
|---|---|---|
| `threat_intel_enabled` | `true` | Enable IoC feed matching |
| `threat_intel_dir` | `config/feeds` | Directory containing CSV/JSON feed files |
| `threat_intel_reload_s` | `3600` | Reload interval in seconds |

#### Phase 6: FIM (Server-side)

| Key | Default | Description |
|---|---|---|
| `fim_enabled` | `true` | Enable server-side FIM processing |
| `fim_default_severity` | `medium` | Default severity for FIM alerts |

#### Phase 7: REST API & Dashboard

| Key | Default | Description |
|---|---|---|
| `rest_enabled` | `true` | Enable REST API server |
| `rest_port` | `8080` | REST API port |
| `rest_bind` | `0.0.0.0` | REST API bind address |
| `rest_api_token` | `changeme-seahorse-token-2026` | Bearer token for API auth |

#### Phase 8: Incident Response

| Key | Default | Description |
|---|---|---|
| `ir_enabled` | `true` | Enable automated incident response |
| `ir_webhook_url` | _(empty)_ | Webhook URL for notifications |
| `ir_script_dir` | `scripts` | Directory for response scripts |

#### Phase 9: Fleet Management

| Key | Default | Description |
|---|---|---|
| `fleet_enabled` | `true` | Enable fleet management |
| `fleet_stale_s` | `300` | Seconds before device is "stale" |
| `fleet_offline_s` | `900` | Seconds before device is "offline" |

#### Phase 10: Network Deep Inspection

| Key | Default | Description |
|---|---|---|
| `inspector_enabled` | `true` | Enable network deep inspection |
| `inspect_dns` | `true` | DNS tunneling/DGA detection |
| `inspect_protocol` | `true` | Protocol anomaly detection |
| `inspect_connections` | `true` | Connection state analysis |
| `inspect_entropy` | `true` | Payload entropy analysis |

#### Phase 15: Correlation Engine

| Key | Default | Description |
|---|---|---|
| `correlation_enabled` | `true` | Enable cross-device correlation |

### 4.2 Client Configuration (client.conf)

#### Connection

| Key | Default | Description |
|---|---|---|
| `server_host` | `127.0.0.1` | Server hostname or IP |
| `server_port` | `9443` | Server TLS port |
| `device_id` | `7001` | Unique device ID (must be unique per agent) |
| `cert_file` | `certs/client.pem` | Client TLS certificate |
| `key_file` | `certs/client-key.pem` | Client TLS private key |
| `ca_file` | `certs/ca.pem` | CA certificate for server verification |

#### Telemetry

| Key | Default | Description |
|---|---|---|
| `report_interval_s` | `30` | Telemetry report interval in seconds |
| `heartbeat_interval_s` | `15` | Heartbeat interval |
| `heartbeat_timeout_s` | `60` | Heartbeat timeout before reconnect |

#### Log Collection

| Key | Default | Description |
|---|---|---|
| `log_source` | `/var/log/syslog` | Log file to monitor (Linux) |
| `log_read_lines` | `100` | Lines to read per cycle |

#### Phase 6: FIM (Client-side)

| Key | Default | Description |
|---|---|---|
| `fim_enabled` | `true` | Enable file integrity scanning |
| `fim_scan_interval_s` | `300` | FIM scan interval |
| `fim_watch_paths` | `/etc,/usr/bin` | Comma-separated paths to monitor |
| `fim_max_file_size` | `10485760` | Max file size to hash (10MB) |
| `fim_max_files` | `50000` | Max files per scan |

#### Phase 11: Process Monitor

| Key | Default | Description |
|---|---|---|
| `process_monitor_enabled` | `true` | Enable process scanning |
| `process_scan_interval_s` | `60` | Process scan interval |
| `process_track_cmdline` | `true` | Capture command line arguments |

#### Phase 12: Connection Inventory

| Key | Default | Description |
|---|---|---|
| `connection_monitor_enabled` | `true` | Enable connection scanning |
| `connection_scan_interval_s` | `60` | Connection scan interval |

#### Phase 13: Session & Auth Tracker

| Key | Default | Description |
|---|---|---|
| `session_tracker_enabled` | `true` | Enable session tracking |
| `session_scan_interval_s` | `60` | Session scan interval |

#### Phase 14: Software Inventory

| Key | Default | Description |
|---|---|---|
| `software_inventory_enabled` | `true` | Enable software scanning |
| `software_scan_interval_s` | `3600` | Software scan interval (1 hour) |

### 4.3 Detection Rules (rules.conf)

The rules.conf file defines regex-based log analysis patterns for the alert engine. Each rule has the format:

```
[rule_name]
pattern = <regex pattern>
severity = low|medium|high|critical
description = Human-readable description
threshold = <count>         # Optional: trigger only after N matches
window_seconds = <seconds>  # Optional: time window for threshold
```

Example rules:

```
[ssh_brute_force]
pattern = Failed password for .* from .* port
severity = high
description = SSH brute force attempt
threshold = 5
window_seconds = 300

[root_login]
pattern = session opened for user root
severity = medium
description = Root login detected
```

---

## 5. Getting Started -- First Run

**Step 1: Generate certificates**

```bash
cd SecureSeaHorse-v3.0.0
sudo ./installer/install_linux.sh certs
# Or generate manually (see Section 3.4)
```

**Step 2: Configure the server**

Edit `config/server.conf`. At minimum, verify the TLS certificate paths are correct. Change the REST API token:

```ini
rest_api_token = your-secret-token-here
```

**Step 3: Start the server**

```bash
./build/SeaHorseServer --config config/server.conf
```

You should see startup output:

```
=== SecureSeaHorse Server v3.0.0 (Phase 15) starting ===
[INFO] Traffic Classifier: ENABLED | 6 categories loaded
[INFO] Threat Intel: ENABLED | 0 IoCs loaded
[INFO] FIM Monitor: ENABLED
[INFO] REST API: ENABLED on port 8080
[INFO] Incident Response: ENABLED | 7 playbooks loaded
[INFO] Fleet Manager: ENABLED | stale=300s offline=900s
[INFO] Network Inspector: ENABLED
[INFO] Correlation Engine: ENABLED | 7 rules loaded
[INFO] Listening on 0.0.0.0:9443 (TLS)
```

**Step 4: Configure the client**

Edit `config/client.conf`. Set the server address:

```ini
server_host = 192.168.1.100    # Your server IP
device_id = 7001                # Unique per agent
```

**Step 5: Start the client**

```bash
./build/SeaHorseClient --config config/client.conf
```

**Step 6: Open the dashboard**

Navigate to `http://your-server-ip:8080/` in a web browser. Enter your API token to log in. The dashboard will show live data once agents connect.

---

## 6. Architecture Overview

```
Monitored Endpoints                     SIEM Server
+-------------------+                  +---------------------------+
| SeaHorse Client   |  mTLS (9443)     | SeaHorse Server           |
|                   | ===============> |                           |
| System Metrics    |  Binary Protocol | Thread Pool               |
| Log Collection    |                  | Protocol Handler          |
| Process Monitor   |                  |   |                       |
| Connection Scan   |                  |   +-> Traffic Classifier  |
| Session Tracker   |                  |   +-> Threat Intel Match  |
| Software Inventory|                  |   +-> FIM Monitor         |
| FIM Scanner       |                  |   +-> Network Inspector   |
| Heartbeat         |                  |   +-> Correlation Engine  |
+-------------------+                  |   +-> Incident Response   |
                                       |   +-> Fleet Manager       |
                                       |                           |
                                       | REST API (8080)           |
                                       |   +-> Web Dashboard       |
                                       |   +-> JSON Endpoints      |
                                       |                           |
                                       | PostgreSQL (optional)     |
                                       +---------------------------+
```

**Wire Protocol:** Binary V2 protocol with HMAC-SHA256 integrity verification on every packet. Message types: telemetry report (0x01), heartbeat (0x02), FIM report (0x03), process report (0x04), connection report (0x05), session report (0x06), software report (0x07).

**Data Flow:** Client sends telemetry at configurable intervals. Server processes each report through a pipeline of analyzers (traffic classifier, threat intel, network inspector). Detections feed into the correlation engine and incident response automation. All data is persisted to PostgreSQL (if configured) and available via the REST API.

---

## 7. Feature Reference

### 7.1 Core Telemetry (Phases 1-3)

The client collects and sends: CPU usage, RAM usage, disk usage, network I/O, OS username, hostname, IP address, and raw log lines from configured log sources. The server processes each report, stores metrics in PostgreSQL, and runs the detection pipeline.

Additional security features include HMAC-SHA256 packet integrity, heartbeat keep-alive with configurable timeout, CRL/OCSP certificate revocation checking, and exponential backoff on connection failures.

### 7.2 Threat Detection (Phase 4)

The traffic classifier analyzes telemetry for six attack categories, each with MITRE ATT&CK technique mapping:

| Category | Description | MITRE |
|---|---|---|
| Brute Force | Failed auth patterns, high connection rates | T1110 |
| C2 Beacon | Periodic outbound, unusual timing patterns | T1071 |
| Data Exfiltration | Abnormal outbound volume, burst transfers | T1048 |
| Port Scan | High connection count, sequential port patterns | T1046 |
| Cryptomining | Sustained high CPU, known pool connections | T1496 |
| Exploit Attempt | Shellcode patterns, buffer overflow signatures | T1203 |

Each detection includes a severity rating (low/medium/high/critical) and confidence score (0.0-1.0).

### 7.3 Threat Intelligence Feeds (Phase 5)

Place CSV files in the `config/feeds/` directory. Supported formats:

```csv
type,value,severity,description,mitre_id,tags
ip,203.0.113.50,high,Known C2 server,T1071.001,apt
domain,evil-domain.xyz,critical,Malware distribution,T1566,phishing
hash_sha256,abc123...,medium,Trojan dropper,T1059,malware
url,http://bad.com/payload,high,Exploit kit,T1190,exploit
email,attacker@evil.com,low,Phishing sender,T1566.001,phishing
```

Feeds are automatically reloaded at the configured interval (default: hourly).

### 7.4 File Integrity Monitoring (Phase 6)

The client hashes files in configured watch paths using SHA-256. On each scan, it compares against the previous baseline and reports additions, modifications, and deletions. The server processes FIM reports, assigns severity based on file location, and maps changes to MITRE ATT&CK techniques (T1547 Boot/Autostart, T1543 System Service, etc.).

### 7.5 REST API & Web Dashboard (Phase 7)

The server includes an embedded HTTP/1.1 server providing a single-page web dashboard and JSON API. See Section 8 for the full endpoint reference.

### 7.6 Incident Response Automation (Phase 8)

Seven built-in playbooks map detection events to automated response actions:

| Playbook | Trigger | Actions |
|---|---|---|
| `critical_response` | Any critical severity | Log + Block IP 1hr + Quarantine |
| `brute_force_block` | Brute force (high+) | Log + Block IP 30min |
| `c2_containment` | C2 beacon (high+) | Log + Block IP 2hr + Quarantine |
| `exfil_throttle` | Data exfiltration (high+) | Log + Rate limit |
| `ioc_critical_block` | IoC match (critical) | Log + Block IP 24hr |
| `fim_critical_quarantine` | FIM (critical) | Log + Quarantine |
| `general_log` | Any medium+ | Log |

All actions include a cooldown period to prevent action storms. The complete audit trail is available via `/api/ir/actions`.

### 7.7 Agent Fleet Management (Phase 9)

Every connecting agent is automatically registered in the device inventory. The fleet manager tracks hostname, IP, OS, agent version, first/last seen timestamps, and per-device threat/alert/FIM counters. Devices are classified as online (< 5min), stale (< 15min), or offline (>= 15min) based on last contact time. A health score (0.0-1.0) is computed based on connectivity freshness and threat history.

### 7.8 Network Deep Inspection (Phase 10)

Four specialized analyzers examine log content for advanced network threats:

- **DNS Analysis:** DGA domain detection (entropy + consonant ratio), DNS tunneling (subdomain depth), suspicious TLDs.
- **Protocol Anomaly:** Unusual HTTP methods, suspicious user agents, base64 payloads in URLs.
- **Connection Tracking:** SYN flood detection, RST storm identification.
- **Entropy Analysis:** Shannon entropy calculation to detect encrypted C2 channels.

### 7.9 Process Monitor (Phase 11)

The client enumerates all running processes including PID, parent PID, name, full path, command line, memory usage, and elevation status. Between scans, it detects newly started and terminated processes. A built-in suspicious process detector flags known attack tools (mimikatz, psexec, nmap, certutil, xmrig, etc.).

### 7.10 Network Connection Inventory (Phase 12)

The client scans all active TCP/UDP connections (equivalent to `netstat -an`), tracking local/remote address, port, state, and owning PID. It detects new and closed connections between scans, and flags connections to known suspicious ports (4444, 1337, 31337, 6667, etc.).

### 7.11 User Session & Auth Tracker (Phase 13)

The client enumerates active user sessions (console, RDP, SSH, TTY) and monitors authentication events including successful logins, failed logins with source IP, privilege escalation (sudo/runas), and account lockouts. On Linux, it parses `/var/log/auth.log` for SSH events and sudo commands. On Windows, it monitors WTS sessions and security event log entries.

### 7.12 Software & Patch Inventory (Phase 14)

The client enumerates all installed software with name, version, publisher, install date, and size. On Windows, it reads both 32-bit and 64-bit Uninstall registry keys. On Linux, it queries dpkg, rpm, or pacman. Between scans (default: hourly), it detects newly installed, removed, and updated packages.

### 7.13 Correlation Engine (Phase 15)

The server-side correlation engine links events across multiple devices and time windows to detect multi-stage attacks. Seven built-in correlation rules:

| Rule | Description | Scope | Window |
|---|---|---|---|
| `brute_force_then_login` | Brute force followed by successful auth | Cross-device | 10min |
| `ioc_then_exfil` | IoC match followed by data exfiltration | Single device | 15min |
| `fim_and_c2` | File modification + C2 communication | Single device | 10min |
| `multi_device_campaign` | Multiple high-severity events across devices | Cross-device | 5min |
| `privesc_suspicious_proc` | Privilege escalation + suspicious process | Single device | 5min |
| `scan_then_exploit` | Port scan followed by exploitation | Cross-device | 10min |
| `dns_tunnel_exfil` | DNS tunneling + exfiltration | Single device | 15min |

Correlated incidents are assigned IDs, tracked as active/resolved, and available via `/api/correlations`.

---

## 8. REST API Reference

All `/api/*` endpoints require bearer token authentication:

```
Authorization: Bearer your-secret-token-here
```

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Web dashboard (no auth required) |
| `GET` | `/api/stats` | System-wide statistics |
| `GET` | `/api/threats?limit=50&device_id=N` | Threat detections |
| `GET` | `/api/ioc?limit=50&device_id=N` | IoC feed matches |
| `GET` | `/api/fim?limit=50&device_id=N` | FIM change events |
| `GET` | `/api/events?limit=50&device_id=N` | Security events |
| `GET` | `/api/devices?device_id=N` | Fleet inventory |
| `GET` | `/api/ir/actions` | IR audit trail |
| `GET` | `/api/ir/blocklist` | Blocked IPs |
| `GET` | `/api/ir/quarantined` | Quarantined device IDs |
| `GET` | `/api/correlations?limit=50` | Correlated incidents |

**Example usage with curl:**

```bash
TOKEN="your-secret-token-here"

# Get system stats
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/stats | jq .

# Get recent threats for device 7001
curl -H "Authorization: Bearer $TOKEN" "http://localhost:8080/api/threats?device_id=7001&limit=10"

# Get fleet inventory
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/devices

# Get correlated incidents
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/correlations
```

**Stats response fields:**

```json
{
  "uptime_hours": 12,
  "total_reports": 5420,
  "total_threats": 47,
  "total_ioc_hits": 3,
  "total_fim_changes": 12,
  "ir_incidents": 15,
  "ir_actions_executed": 23,
  "ir_blocked_ips": 5,
  "ir_quarantined": 1,
  "fleet_total": 10,
  "fleet_online": 8,
  "fleet_stale": 1,
  "fleet_offline": 1,
  "net_findings": 7,
  "corr_incidents": 2,
  "corr_active": 1,
  "api_requests": 342
}
```

---

## 9. Web Dashboard Guide

Access the dashboard at `http://your-server:8080/`. On first visit, you will see a login screen asking for the API token (configured in `server.conf` as `rest_api_token`).

The dashboard displays:

- **Top row:** 8 stat cards showing fleet status, threats, IoC hits, FIM changes, blocked IPs, network findings, IR actions, and uptime.
- **Panel 1: Recent Threats** -- Table of threat detections with severity color coding (red=critical, yellow=high, blue=medium), MITRE technique IDs, and timestamps.
- **Panel 2: IoC Matches** -- Feed matches with indicator type, value, source feed, and severity.
- **Panel 3: FIM Events** -- File integrity changes with change type highlighting (green=added, yellow=modified, red=deleted).
- **Panel 4: Security Events** -- Regex-matched log events with rule name and matched text.

The dashboard auto-refreshes every 15 seconds. A status indicator in the top-right shows connection health.

---

## 10. Database Setup (PostgreSQL)

PostgreSQL is optional but recommended for production. Without it, the server operates in CSV-only mode.

**Setup:**

```bash
sudo -u postgres createuser seahorse
sudo -u postgres createdb seahorse -O seahorse
sudo -u postgres psql -c "ALTER USER seahorse PASSWORD 'your-password';"
```

**Enable in server.conf:**

```ini
pg_enabled = true
pg_host = localhost
pg_port = 5432
pg_dbname = seahorse
pg_user = seahorse
pg_password = your-password
```

Tables are created automatically on first connection. The database stores telemetry, threat detections, IoC matches, FIM events, and security events with full query support via the REST API.

---

## 11. Operational Guide

### 11.1 Running as a Service

**Linux (systemd):**

```bash
sudo systemctl enable seahorse-server
sudo systemctl start seahorse-server
sudo journalctl -u seahorse-server -f     # View live logs
```

**Windows:**

```cmd
sc start SeaHorseServer
sc start SeaHorseClient
```

### 11.2 Log Management

Server logs are written to `logs/server.log` (or the configured `log_file` path). Logs rotate automatically. Use the `--verbose` flag for debug-level output.

### 11.3 Backup and Recovery

Back up the following:
- `config/server.conf` -- Server configuration
- `config/client.conf` -- Client configuration (on each endpoint)
- `certs/` -- TLS certificates and keys
- PostgreSQL database: `pg_dump seahorse > backup.sql`

### 11.4 Performance Tuning

For large deployments (100+ agents):

- Increase `thread_pool_max` to match expected concurrent connections.
- Set `report_interval_s` to 60 or higher to reduce server load.
- Increase `software_scan_interval_s` to 7200 (2 hours) since software changes infrequently.
- Use PostgreSQL for persistent storage rather than CSV.
- Open file descriptor limits: `LimitNOFILE=65535` in the systemd service.

---

## 12. Security Hardening

1. **Change the default API token** in `server.conf`. Use a long, random string.
2. **Use CA-signed certificates** in production. The self-signed certs are for testing only.
3. **Restrict REST API binding.** Set `rest_bind = 127.0.0.1` if the dashboard should only be accessed locally, or use a reverse proxy (nginx/Caddy) with HTTPS.
4. **Firewall rules.** Only allow port 9443 from known agent subnets. Restrict port 8080 to admin networks.
5. **PostgreSQL.** Use a dedicated database user with minimal privileges. Enable SSL for database connections.
6. **File permissions.** Configuration files containing passwords should be mode 600. Certificate private keys should be mode 600.
7. **Service user.** Run the server as a dedicated non-root user (the Linux installer creates `seahorse`).
8. **Audit the API token.** The token is transmitted in HTTP headers. Use HTTPS (via reverse proxy) for production dashboard access.

---

## 13. Troubleshooting

**Client cannot connect to server:**
- Verify the server is running and listening: `ss -tlnp | grep 9443`
- Check firewall rules allow port 9443
- Verify TLS certificates: `openssl s_client -connect server:9443 -cert client.pem -key client-key.pem -CAfile ca.pem`
- Confirm `server_host` in client.conf matches the server's address

**Dashboard shows no data:**
- Verify at least one client is connected and sending telemetry
- Check the server log for errors
- Confirm the API token in the dashboard matches `rest_api_token` in server.conf

**High CPU usage on server:**
- Reduce `inspect_entropy` if log content is large (entropy analysis is regex-heavy)
- Increase client report intervals
- Check for regex patterns in rules.conf that may cause backtracking

**Database connection failures:**
- Verify PostgreSQL is running: `systemctl status postgresql`
- Test connection: `psql -h localhost -U seahorse -d seahorse`
- Check `pg_hba.conf` allows the connection method

**FIM generating too many alerts:**
- Add frequently-changing files to `fim_exclude_extensions` (e.g., `.log`, `.tmp`)
- Reduce `fim_watch_paths` to only critical directories
- Increase `fim_max_file_size` threshold

**Process monitor causing performance issues:**
- Increase `process_scan_interval_s` to 120 or 300
- Disable `process_track_cmdline` to skip command line capture

---

## 14. File Reference

### Source Files (25)

| File | Lines | Phase | Description |
|---|---|---|---|
| `server.cpp` | ~1550 | All | Server main, pipeline, REST integration |
| `client.cpp` | ~1140 | All | Client main, scanners, send functions |
| `server_protocol.h` | 331 | 1 | Server-side wire protocol + thread pool |
| `client_protocol.h` | 277 | 1 | Client-side wire protocol + backoff |
| `crypto_utils.h` | 321 | 3 | HMAC-SHA256, CRL, OCSP, heartbeat |
| `regex_engine.h` | 321 | 2 | Regex-based log analysis |
| `alert_engine.h` | 210 | 2 | Threshold alerting |
| `db_layer.h` | 703 | 2+ | PostgreSQL persistence layer |
| `traffic_classifier.h` | 641 | 4 | ML-style traffic classification |
| `mitre_map.h` | 204 | 4 | MITRE ATT&CK mappings |
| `threat_intel.h` | 699 | 5 | IoC feed engine |
| `fim_common.h` | 194 | 6 | FIM data structures |
| `fim_scanner.h` | 288 | 6 | Client-side file hashing |
| `fim_monitor.h` | 270 | 6 | Server-side FIM processor |
| `baseline_tracker.h` | 252 | 6 | Per-device baselines |
| `rest_server.h` | 557 | 7 | Embedded HTTP server |
| `dashboard_html.h` | 212 | 7 | Web dashboard |
| `incident_response.h` | 396 | 8 | Playbook engine |
| `fleet_manager.h` | 383 | 9 | Device inventory |
| `network_inspector.h` | 552 | 10 | DNS/protocol/entropy |
| `process_monitor.h` | ~350 | 11 | Process enumeration |
| `connection_inventory.h` | ~350 | 12 | Connection scanning |
| `session_tracker.h` | ~350 | 13 | Session/auth tracking |
| `software_inventory.h` | ~300 | 14 | Software inventory |
| `correlation_engine.h` | ~400 | 15 | Cross-device correlation |

### Configuration Files (3)

| File | Description |
|---|---|
| `config/server.conf` | Server settings (~177 lines) |
| `config/client.conf` | Client settings (~95 lines) |
| `config/rules.conf` | Regex detection rules |

### Installer Files (2)

| File | Description |
|---|---|
| `installer/install_linux.sh` | Linux installer (build/install/certs/uninstall) |
| `installer/installer_windows.nsi` | NSIS installer script for Windows |

---

*SecureSeaHorse SIEM v3.0.0 -- Built with C++17, OpenSSL, and zero external runtime dependencies.*
