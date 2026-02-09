# SecureSeaHorse

**SecureSeaHorse** is a lightweight, secure, cross-platform telemetry system written in C++. It features a custom TCP protocol wrapped in Mutual TLS (mTLS) to ensure that only authorized clients can report data to the central server.

## Features

* **Mutual TLS (mTLS) Authentication**: Both server and client verify each other's certificates using OpenSSL.
* **Cross-Platform**: Runs on **Windows** (Winsock/EventLog) and **Linux** (Syscall/Syslog).
* **System Telemetry**: Real-time reporting of:
    * CPU Usage (User/Kernel/Idle split)
    * RAM Usage (Total/Available)
    * Disk Usage
    * Network Traffic (In/Out bytes)
* **Log Scraping**:
    * **Windows**: Scrapes the "System" Event Log securely.
    * **Linux**: Tails `/var/log/syslog` or `/var/log/messages`.
* **Robust Networking**: Auto-reconnection logic, CRC32 packet integrity checks, and thread-pooled server handling.

## Directory Structure

```text
src/client/   - Client source code
src/server/   - Server source code
config/       - Configuration templates
scripts/      - Certificate generation helpers
