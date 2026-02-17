#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#ifndef NOMINMAX
#define NOMINMAX
#endif

// =============================================================================
// SecureSeaHorse SIEM — Phase 3: Cryptographic Utilities
// =============================================================================
// Provides:
//   - HMAC-SHA256 payload signing/verification (replaces CRC32)
//   - TLS session key derivation via SSL_export_keying_material()
//   - CRL (Certificate Revocation List) loading
//   - OCSP stapling setup
// =============================================================================

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <iostream>

#include <openssl/ssl.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/ocsp.h>

// =============================================================================
// CONSTANTS
// =============================================================================
constexpr size_t HMAC_KEY_LEN    = 32;  // 256-bit key
constexpr size_t HMAC_DIGEST_LEN = 32;  // SHA-256 output = 32 bytes

// TLS Exported Keying Material label (RFC 5705)
// Both sides derive the same key from the TLS master secret
static const char* const EKM_LABEL = "SEAHORSE_SIEM_HMAC_V1";
constexpr size_t EKM_LABEL_LEN = 22;  // strlen("SEAHORSE_SIEM_HMAC_V1")

// =============================================================================
// PROTOCOL V2 — Message Types
// =============================================================================
enum MsgType : uint8_t {
    MSG_TELEMETRY      = 0x00,  // Standard telemetry report
    MSG_HEARTBEAT_PING = 0x01,  // Client → Server keep-alive ping
    MSG_HEARTBEAT_PONG = 0x02,  // Server → Client keep-alive pong
    MSG_FIM_REPORT     = 0x03,  // Phase 6: File Integrity Monitoring snapshot
};

// =============================================================================
// PROTOCOL V2 — Packet Header (replaces v1 PacketHeader)
// =============================================================================
// v1 header: magic(4) + version(2) + payload_len(4) + crc32(4)     = 14 bytes
// v2 header: magic(4) + version(2) + msg_type(1) + payload_len(4)
//            + hmac(32) + reserved(1)                                = 44 bytes
//
// Backward compatibility: server checks header.version to decide
// which validation path to use (CRC32 for v1, HMAC for v2).
// =============================================================================
#pragma pack(push, 1)
struct PacketHeaderV2 {
    uint32_t magic;            // PROTOCOL_MAGIC (0xDEADBEEF)
    uint16_t version;          // 2 for Phase 3+
    uint8_t  msg_type;         // MsgType enum
    uint32_t payload_len;      // Payload size in bytes (0 for heartbeats)
    uint8_t  hmac[HMAC_DIGEST_LEN]; // HMAC-SHA256 of payload
    uint8_t  reserved;         // Pad to even alignment, set to 0
};
#pragma pack(pop)

static_assert(sizeof(PacketHeaderV2) == 44, "PacketHeaderV2 must be 44 bytes");

// =============================================================================
// HEARTBEAT PAYLOAD (lightweight, fixed size)
// =============================================================================
#pragma pack(push, 1)
struct HeartbeatPayload {
    int64_t  timestamp_ms;     // Sender's wall-clock timestamp
    int32_t  device_id;        // Sender's device_id (0 for server)
    uint32_t seq;              // Sequence number (monotonic per session)
};
#pragma pack(pop)

// =============================================================================
// HMAC KEY DERIVATION — From TLS Session
// =============================================================================
// Uses RFC 5705 Exported Keying Material so both sides derive the
// same HMAC key from the TLS master secret without transmitting it.
// Returns true on success, fills key_out with HMAC_KEY_LEN bytes.
// =============================================================================
inline bool derive_hmac_key(SSL* ssl, uint8_t* key_out) {
    if (!ssl || !key_out) return false;

    int rc = SSL_export_keying_material(
        ssl,
        key_out, HMAC_KEY_LEN,
        EKM_LABEL, EKM_LABEL_LEN,
        nullptr, 0,  // No context (both sides use same label)
        0             // use_context = false
    );

    return (rc == 1);
}

// =============================================================================
// HMAC-SHA256 — Compute
// =============================================================================
// Signs the payload data and writes HMAC_DIGEST_LEN bytes into hmac_out.
// Returns true on success.
// =============================================================================
inline bool compute_hmac(const uint8_t* key, size_t key_len,
                         const uint8_t* data, size_t data_len,
                         uint8_t* hmac_out)
{
    unsigned int out_len = 0;
    unsigned char* result = HMAC(
        EVP_sha256(),
        key, static_cast<int>(key_len),
        data, data_len,
        hmac_out, &out_len
    );

    return (result != nullptr && out_len == HMAC_DIGEST_LEN);
}

// =============================================================================
// HMAC-SHA256 — Verify
// =============================================================================
// Computes HMAC of data and compares with expected_hmac using constant-time
// comparison to prevent timing attacks.
// =============================================================================
inline bool verify_hmac(const uint8_t* key, size_t key_len,
                        const uint8_t* data, size_t data_len,
                        const uint8_t* expected_hmac)
{
    uint8_t computed[HMAC_DIGEST_LEN];
    if (!compute_hmac(key, key_len, data, data_len, computed)) {
        return false;
    }

    // Constant-time comparison (CRYPTO_memcmp returns 0 if equal)
    return CRYPTO_memcmp(computed, expected_hmac, HMAC_DIGEST_LEN) == 0;
}

// =============================================================================
// BUILD V2 HEADER — Helper to construct a signed packet header
// =============================================================================
inline PacketHeaderV2 build_v2_header(MsgType type, uint32_t payload_len,
                                       const uint8_t* payload_data,
                                       const uint8_t* hmac_key)
{
    PacketHeaderV2 hdr;
    std::memset(&hdr, 0, sizeof(hdr));

    hdr.magic       = htonl(0xDEADBEEF);
    hdr.version     = htons(2);
    hdr.msg_type    = type;
    hdr.payload_len = htonl(payload_len);
    hdr.reserved    = 0;

    // Compute HMAC over the payload
    if (payload_data && payload_len > 0) {
        compute_hmac(hmac_key, HMAC_KEY_LEN,
                     payload_data, payload_len,
                     hdr.hmac);
    } else {
        // For zero-length payloads (heartbeats with inline data),
        // HMAC the header fields themselves (magic + version + type + len)
        // as a simple liveness proof
        uint8_t hdr_data[11]; // magic(4)+version(2)+type(1)+len(4)
        std::memcpy(hdr_data, &hdr.magic, 4);
        std::memcpy(hdr_data + 4, &hdr.version, 2);
        hdr_data[6] = hdr.msg_type;
        std::memcpy(hdr_data + 7, &hdr.payload_len, 4);
        compute_hmac(hmac_key, HMAC_KEY_LEN, hdr_data, 11, hdr.hmac);
    }

    return hdr;
}

// =============================================================================
// CRL LOADING — Add Certificate Revocation List to SSL_CTX
// =============================================================================
// Loads a PEM-formatted CRL file and enables CRL checking on the
// X509 verification store. Returns true on success.
// =============================================================================
inline bool load_crl(SSL_CTX* ctx, const std::string& crl_path) {
    if (crl_path.empty()) return false;

    FILE* fp = fopen(crl_path.c_str(), "r");
    if (!fp) {
        std::cerr << "[CRL] Cannot open CRL file: " << crl_path << "\n";
        return false;
    }

    X509_CRL* crl = PEM_read_X509_CRL(fp, nullptr, nullptr, nullptr);
    fclose(fp);

    if (!crl) {
        std::cerr << "[CRL] Failed to parse CRL from: " << crl_path << "\n";
        return false;
    }

    X509_STORE* store = SSL_CTX_get_cert_store(ctx);
    if (!store) {
        X509_CRL_free(crl);
        return false;
    }

    if (X509_STORE_add_crl(store, crl) != 1) {
        std::cerr << "[CRL] Failed to add CRL to store\n";
        X509_CRL_free(crl);
        return false;
    }

    // Enable CRL checking flags
    X509_STORE_set_flags(store,
        X509_V_FLAG_CRL_CHECK |          // Check CRL for leaf cert
        X509_V_FLAG_CRL_CHECK_ALL);      // Check CRL for entire chain

    X509_CRL_free(crl);
    return true;
}

// =============================================================================
// OCSP STAPLING — Client-side callback to verify stapled OCSP response
// =============================================================================
// This callback is invoked during TLS handshake when the server provides
// a stapled OCSP response. Returns 1 to continue, 0 to abort.
// =============================================================================
inline int ocsp_client_callback(SSL* ssl, void* arg) {
    const unsigned char* resp_data = nullptr;
    long resp_len = SSL_get_tlsext_status_ocsp_resp(ssl, &resp_data);

    if (!resp_data || resp_len <= 0) {
        // No OCSP response stapled — this is acceptable (soft fail).
        // Set ocsp_must_staple=true in config to make this a hard failure.
        bool* must_staple = static_cast<bool*>(arg);
        if (must_staple && *must_staple) {
            std::cerr << "[OCSP] No stapled response and must_staple=true. Rejecting.\n";
            return 0;  // Hard fail
        }
        return 1;  // Soft fail — continue without OCSP
    }

    // Parse the OCSP response
    OCSP_RESPONSE* ocsp_resp = d2i_OCSP_RESPONSE(nullptr, &resp_data, resp_len);
    if (!ocsp_resp) {
        std::cerr << "[OCSP] Failed to parse stapled OCSP response.\n";
        return 0;
    }

    int status = OCSP_response_status(ocsp_resp);
    OCSP_RESPONSE_free(ocsp_resp);

    if (status != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        std::cerr << "[OCSP] Stapled response status: " << status << " (not successful)\n";
        return 0;
    }

    return 1;  // OCSP response is valid
}

// =============================================================================
// OCSP STAPLING — Server-side: enable status request in context
// =============================================================================
// Call this on the server SSL_CTX to indicate it supports OCSP stapling.
// The actual OCSP response must be loaded separately via a callback or file.
// =============================================================================
inline void enable_ocsp_stapling_server(SSL_CTX* ctx) {
    SSL_CTX_set_tlsext_status_type(ctx, TLSEXT_STATUSTYPE_ocsp);
}

// =============================================================================
// OCSP STAPLING — Client-side: request stapled OCSP during handshake
// =============================================================================
inline void enable_ocsp_stapling_client(SSL_CTX* ctx, bool* must_staple_flag) {
    SSL_CTX_set_tlsext_status_type(ctx, TLSEXT_STATUSTYPE_ocsp);
    SSL_CTX_set_tlsext_status_cb(ctx, ocsp_client_callback);
    SSL_CTX_set_tlsext_status_arg(ctx, must_staple_flag);
}

// =============================================================================
// CERTIFICATE PINNING — Optional additional validation
// =============================================================================
// Extracts the SHA-256 fingerprint of the peer certificate and compares
// it against a configured pin. Returns true if the pin matches.
// =============================================================================
inline bool verify_cert_pin(SSL* ssl, const std::string& expected_pin_hex) {
    if (expected_pin_hex.empty()) return true;  // Pinning not configured

    X509* cert = SSL_get_peer_certificate(ssl);
    if (!cert) return false;

    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    if (X509_digest(cert, EVP_sha256(), md, &md_len) != 1) {
        X509_free(cert);
        return false;
    }
    X509_free(cert);

    // Convert to hex string for comparison
    std::string actual_hex;
    actual_hex.reserve(md_len * 3);
    for (unsigned int i = 0; i < md_len; i++) {
        char buf[4];
        snprintf(buf, sizeof(buf), "%02X", md[i]);
        if (i > 0) actual_hex += ':';
        actual_hex += buf;
    }

    return (actual_hex == expected_pin_hex);
}

#endif
