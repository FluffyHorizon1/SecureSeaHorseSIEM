# 🐴 SecureSeaHorse v1.3.0: The Security & Lifecycle Update

**Release Date:** February 15, 2026  
**Status:** Major Update (Phase 3)

We are proud to announce **SecureSeaHorse v1.3.0**. While v1.0.1 established the foundation of secure transport, v1.3.0 hardens the protocol against sophisticated tampering and introduces robust lifecycle management for enterprise deployments. This release moves us from "Secure Transport" to **Active Defense**.

---

## 🚀 Key Features

### 🛡️ Protocol v2: From Integrity to Authenticity
The application-layer integrity check has been completely overhauled to meet modern cryptographic standards.

* **HMAC-SHA256 Payload Signing:**
    * **The Problem:** v1.0.1 used CRC32, which detects accidental corruption but provides zero protection against deliberate tampering.
    * **The Solution:** We replaced CRC32 with HMAC-SHA256. Every packet is now cryptographically signed.
* **Zero-Knowledge Key Exchange:** Using **RFC 5705 (TLS Keying Material Exporters)**, the client and server derive a unique 256-bit HMAC key directly from the TLS master secret. No shared secret is ever stored on disk or sent over the wire.
* **Constant-Time Verification:** The server utilizes `CRYPTO_memcmp` for signature verification to eliminate timing side-channel attacks.

### 🔍 Certificate Lifecycle & Revocation
Trust is no longer permanent. v1.3.0 introduces three layers of certificate validation beyond the initial handshake.

* **CRL (Certificate Revocation List) Support:** The server and client can now ingest PEM-formatted CRLs. If a device is stolen, you can revoke its certificate immediately without re-issuing the entire CA.
* **OCSP Stapling (Must-Staple):** To ensure real-time revocation status without the overhead of large CRL files, the client can now require the server to provide a "stapled" OCSP response during the handshake.
* **Certificate Pinning:** For high-security environments, clients can be configured with a **SHA-256 Fingerprint Pin**. Even if your CA is compromised, the client will only talk to a server matching that specific hardware-linked certificate.

### 💓 Connection Lifecycle (Heartbeat Engine)
To prevent "Zombie Connections" and ensure telemetry reliability in unstable networks:

* **Bidirectional Heartbeats:** The client sends a cryptographically signed "Ping" during idle periods. If the server doesn't respond with a "Pong" within the timeout window, the client force-reconnects.
* **Server-Side Reaping:** The server now automatically identifies and reaps dead sockets that haven't sent data or heartbeats, freeing up thread-pool slots for active agents.

### 🧠 Data Intelligence (Phase 2 Integration)
Since v1.0.1, we have integrated a full analysis suite into the server:

* **Regex Analysis Engine:** Real-time log parsing using a customizable `rules.conf`.
* **Threshold Alerting:** Sophisticated logic to detect brute force (e.g., "5 failures in 30 seconds") and fire alerts to a dedicated log.
* **PostgreSQL Persistence:** High-performance database storage with automatic schema creation and CSV fallback.

---

## 🛠️ Fixes & Improvements in v1.3.0

* **NOMINMAX Implementation:** Resolved long-standing conflicts between Windows headers and the C++ Standard Library.
* **Thread-Safe Logging:** The `AsyncLogger` now handles log rotation and high-frequency writes without blocking the main telemetry loop.
* **Strict Bounds Checking:** All incoming telemetry buffers are now validated against the expected struct size before processing to prevent memory corruption.
* **Backward Compatibility:** The v1.3.0 server remains "Protocol Aware"—it can transparently handle both v1.1 (CRC32) and v1.3 (HMAC) packets simultaneously.

---

## 🔐 Deep Dive: Security Architecture

### 1. Cryptographic Authenticity
The upgrade from CRC32 to HMAC-SHA256 ensures that logs cannot be modified in transit.
* **Tamper Proofing:** If a single bit of log data is changed, the signature verification fails, and the server drops the packet.
* **Key Derivation:** By using **RFC 5705**, the HMAC key is never transmitted. It is "baked" into RAM during the TLS handshake, making it impossible to sniff or steal from a configuration file.

### 2. Advanced Identity Management
Standard mTLS is vulnerable if a client certificate is stolen.
* **Kill Switch:** CRL and OCSP support allow administrators to block specific compromised devices instantly.
* **Fingerprint Pinning:** By telling the client to only trust a specific SHA-256 fingerprint, you protect against "Rogue CA" attacks where an attacker might compromise your Root CA to issue fake certificates.

### 3. Defense Against DoS & Zombie Sockets
* **Socket Reaping:** The Heartbeat engine prevents "Zombie Sockets" from consuming the server's thread pool.
* **Memory Protection:** The server validates `payload_len` against the expected struct size before allocating memory, preventing "Buffer Overflow" and memory exhaustion attacks.

---

## 📊 Security Summary Table

| Threat | v1.0.1 Defense | v1.3.0 Defense (Current) |
| :--- | :--- | :--- |
| **Data Tampering** | CRC32 (Weak) | **HMAC-SHA256 (Cryptographic)** |
| **Timing Attacks** | Vulnerable | **Protected (`CRYPTO_memcmp`)** |
| **Stolen Devices** | Manual CA Reissue | **CRL/OCSP Revocation** |
| **Fake Servers** | Basic CA Check | **SHA-256 Cert Pinning** |
| **Zombie Sockets** | None | **Signed Heartbeat Reaping** |
| **Memory Crashing** | Weak Bounds Checking | **Strict Struct Size Validation** |

---

## 📋 Prerequisites

* **OpenSSL 3.0** or newer (Recommended for OCSP features).
* **PostgreSQL 14+** (Optional, for database persistence).
* **CMake 3.15+** for building.

---

## 📦 Installation & Upgrade

### Build with vcpkg (Windows):

```powershell
# Install dependencies
.\vcpkg install openssl:x64-windows libpq:x64-windows

# Build
mkdir build
cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=[path_to_vcpkg]/scripts/buildsystems/vcpkg.cmake
cmake --build . --config Release
```
# Generate v2 Certificates:
Existing certificates will work, but to enable OCSP and CRL support, see the updated scripts/generate_certs.sh.
