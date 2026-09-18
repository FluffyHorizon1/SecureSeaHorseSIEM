# SecureSeaHorse SIEM — Phase 3 Changelog

## Version 1.3.0 — Security & Lifecycle

### Summary

Phase 3 hardens the on-wire protocol and adds connection lifecycle management. The CRC32 integrity check is replaced with HMAC-SHA256 (derived from the TLS session), a heartbeat keep-alive detects dead connections, CRL/OCSP certificate revocation prevents compromised-cert access, and optional certificate pinning locks the client to a specific server certificate. All changes are backward-compatible — v1.3.0 servers accept v1.1.0 clients transparently.

---

### 1. HMAC-SHA256 Payload Integrity (`crypto_utils.h`)

**Problem:** CRC32 detects accidental corruption but provides zero protection against deliberate tampering. An attacker who can modify ciphertext in transit (even through TLS) or who compromises a relay can alter payloads and recompute the CRC undetected.

**Solution:** HMAC-SHA256 signing using a key derived from the TLS session via `SSL_export_keying_material()` (RFC 5705).

**How it works:**
- After TLS handshake, both client and server call `SSL_export_keying_material()` with the label `SEAHORSE_SIEM_HMAC_V1` to derive an identical 256-bit HMAC key.
- No key is ever transmitted — it's derived from the TLS master secret.
- The client signs every payload with `HMAC(key, payload)` and places the 32-byte digest in the v2 header.
- The server verifies using `CRYPTO_memcmp()` (constant-time) to prevent timing side-channels.
- Failed verification logs a warning and drops the packet but keeps the connection alive.
- On session teardown, `OPENSSL_cleanse()` wipes the key from memory.

**Protocol v2 header (44 bytes, replaces v1's 14-byte header):**

```
Offset  Size  Field
0       4     magic (0xDEADBEEF)
4       2     version (2)
6       1     msg_type (0=telemetry, 1=ping, 2=pong)
7       4     payload_len
11      32    hmac[32] (HMAC-SHA256 of payload)
43      1     reserved (0)
```

**Backward compatibility:** The server reads the first 6 bytes (magic + version) to detect v1 vs v2. v1 clients continue to work with CRC32 validation. There is no negotiation — the client decides which version to use based on `hmac_enabled` in its config.

**Config keys (both client.conf and server.conf):**
```
hmac_enabled = true
```

**Files added:** `crypto_utils.h`
**Files changed:** `client.cpp`, `server.cpp`, `client_protocol.h`

---

### 2. Heartbeat Keep-Alive (`crypto_utils.h`, `client.cpp`, `server.cpp`)

**Problem:** If a client crashes, the network drops silently, or a firewall times out a NAT mapping, the server holds an open thread forever. Conversely, a client doesn't know if the server is gone until the next telemetry write fails.

**Solution:** Bidirectional heartbeat: client sends periodic pings, server responds with pongs. Both sides enforce timeouts.

**Protocol:**
- `MSG_HEARTBEAT_PING` (0x01): Client → Server, contains `HeartbeatPayload` (timestamp + device_id + sequence number).
- `MSG_HEARTBEAT_PONG` (0x02): Server → Client, echoes the payload back.
- Both use HMAC-signed v2 headers.

**Client behavior:**
- Every `heartbeat_interval_s` (default 15s), if no telemetry was sent recently, the client sends a PING.
- A dedicated receiver thread listens for PONGs.
- If no PONG arrives within `heartbeat_timeout_s` (default 45s), the client forces a reconnect with exponential backoff.

**Server behavior:**
- On receiving a PING, immediately responds with a PONG.
- `connection_timeout_s` (default 120s): if no message of any type is received from a client within this window, the server closes the connection and frees the thread pool slot.

**Config keys:**
```
# client.conf
heartbeat_interval_s = 15
heartbeat_timeout_s  = 45

# server.conf
connection_timeout_s = 120
```

---

### 3. CRL Certificate Revocation (`crypto_utils.h`, `client.cpp`, `server.cpp`)

**Problem:** If a client or server private key is compromised, there was no mechanism to revoke the certificate. The compromised endpoint could continue to authenticate until the certificate expired.

**Solution:** CRL (Certificate Revocation List) loading via OpenSSL's `X509_STORE`.

**How it works:**
- Configure `crl_path` in client.conf or server.conf to point to a PEM-formatted CRL file.
- On startup, the CRL is loaded into the X509 verification store.
- `X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL` enables checking for the leaf certificate and the entire chain.
- If a peer presents a revoked certificate, the TLS handshake is rejected.

**Generating a CRL:**
```bash
# Revoke a compromised certificate
openssl ca -revoke compromised_client.crt -config ca.cnf

# Generate the CRL file
openssl ca -gencrl -out crl.pem -config ca.cnf
```

**Config keys:**
```
crl_path = certs/crl.pem
```

---

### 4. OCSP Stapling (`crypto_utils.h`, `client.cpp`, `server.cpp`)

**Problem:** CRL files are static and must be distributed manually. For environments with many certificates, OCSP provides real-time revocation status.

**Solution:** OCSP stapling support on both sides.

**Client side:**
- Requests the server to provide a stapled OCSP response during TLS handshake.
- `ocsp_stapling = true` enables the request.
- `ocsp_must_staple = false` (default): soft-fail — accept connections even if the server doesn't staple.
- `ocsp_must_staple = true`: hard-fail — reject connections without a valid stapled OCSP response.

**Server side:**
- `ocsp_stapling = false` (default): the server does not staple OCSP responses.
- When enabled, the server needs an OCSP response file. This is typically provided by certbot or a cron job that queries the CA's OCSP responder.

**Config keys:**
```
# client.conf
ocsp_stapling    = true
ocsp_must_staple = false

# server.conf
ocsp_stapling = false
```

---

### 5. Certificate Pinning (`crypto_utils.h`, `client.cpp`)

**Problem:** Even with proper CA validation, a compromised or rogue CA could issue a certificate for the server hostname, enabling a man-in-the-middle attack.

**Solution:** Optional SHA-256 certificate pinning. The client compares the server certificate's fingerprint against a configured pin.

**How to get the pin:**
```bash
openssl x509 -in server.crt -noout -fingerprint -sha256
# Output: SHA256 Fingerprint=AA:BB:CC:DD:...
```

**Config key (client.conf):**
```
cert_pin_sha256 = AA:BB:CC:DD:EE:FF:...
```

If the pin doesn't match, the connection is aborted immediately (not retried with backoff, since this indicates a security issue, not a transient failure).

---

### Migration Guide from v1.2.0

1. **New files to add:**
   - `crypto_utils.h` → alongside other server/client headers

2. **Updated files (replace in-place):**
   - `client_protocol.h` — added `get_bool()`, updated help text
   - `client.cpp` — HMAC signing, heartbeat, CRL/OCSP, cert pinning
   - `server.cpp` — dual-protocol v1/v2, HMAC verification, heartbeat pong, CRL/OCSP
   - `client.conf` — added Phase 3 config keys
   - `server.conf` — added Phase 3 config keys

3. **No new dependencies.** Phase 3 uses only OpenSSL APIs already linked.

4. **No protocol migration needed.** The server auto-detects v1 vs v2 per-packet. You can upgrade the server first, then roll out client upgrades at your own pace.

5. **Unchanged from Phase 2:** `db_layer.h`, `regex_engine.h`, `alert_engine.h`, `rules.conf`, `server_protocol.h`

6. **Recommended post-upgrade steps:**
   - Generate a CRL even if empty: `openssl ca -gencrl -out crl.pem -config ca.cnf`
   - Get your server cert pin: `openssl x509 -in server.crt -noout -fingerprint -sha256`
   - Set `cert_pin_sha256` in client.conf for production deployments.

---

### Version History

| Version | Phase | Highlights |
|---------|-------|------------|
| 1.0.1 | — | Initial release: mTLS, binary protocol, CSV output |
| 1.1.0 | 1 | Thread pool, backoff, CLI, async logger |
| 1.2.0 | 2 | PostgreSQL, regex engine, threshold alerting |
| 1.3.0 | 3 | HMAC-SHA256, heartbeat, CRL/OCSP, cert pinning |
