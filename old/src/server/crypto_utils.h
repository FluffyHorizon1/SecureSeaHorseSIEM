#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#ifndef NOMINMAX
#define NOMINMAX
#endif

// =============================================================================
// SecureSeaHorse SIEM -- Phase 3: Cryptographic Utilities
// =============================================================================
// Provides:
//   - HMAC-SHA256 payload signing/verification (replaces CRC32)
//   - TLS session key derivation via SSL_export_keying_material()
//   - CRL (Certificate Revocation List) loading
//   - OCSP stapling setup
//
// v5.0 update: added MSG_USB_REPORT (0x08) for Phase 19 USB telemetry.
// Existing MsgType values are preserved to maintain wire compatibility with
// older agents.
// =============================================================================

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <iostream>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

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
// PROTOCOL V2 -- Message Types
// =============================================================================
enum MsgType : uint8_t {
    MSG_TELEMETRY       = 0x00,  // Standard telemetry report
    MSG_HEARTBEAT_PING  = 0x01,  // Client -> Server keep-alive ping
    MSG_HEARTBEAT_PONG  = 0x02,  // Server -> Client keep-alive pong
    MSG_FIM_REPORT      = 0x03,  // Phase 6: File Integrity Monitoring snapshot
    MSG_PROCESS_REPORT  = 0x04,  // Phase 11: Process snapshot
    MSG_CONN_REPORT     = 0x05,  // Phase 12: Network connection inventory
    MSG_SESSION_REPORT  = 0x06,  // Phase 13: User session & auth events
    MSG_SOFTWARE_REPORT = 0x07,  // Phase 14: Software & patch inventory
    MSG_USB_REPORT      = 0x08,  // Phase 19 (v5.0): USB device inventory + changes
};

// =============================================================================
// PROTOCOL V2 -- Packet Header (replaces v1 PacketHeader)
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
    uint32_t magic = 0;            // PROTOCOL_MAGIC (0xDEADBEEF)
    uint16_t version = 0;          // 2 for Phase 3+
    uint8_t  msg_type = 0;         // MsgType enum
    uint32_t payload_len = 0;      // Payload size in bytes (0 for heartbeats)
    uint8_t  hmac[HMAC_DIGEST_LEN] = {}; // HMAC-SHA256 of payload
    uint8_t  reserved = 0;         // Pad to even alignment, set to 0
};
#pragma pack(pop)

static_assert(sizeof(PacketHeaderV2) == 44, "PacketHeaderV2 must be 44 bytes");

// =============================================================================
// HEARTBEAT PAYLOAD (lightweight, fixed size)
// =============================================================================
#pragma pack(push, 1)
struct HeartbeatPayload {
    int64_t  timestamp_ms = 0;     // Sender's wall-clock timestamp
    int32_t  device_id = 0;        // Sender's device_id (0 for server)
    uint32_t seq = 0;              // Sequence number (monotonic per session)
};
#pragma pack(pop)

// =============================================================================
// HMAC KEY DERIVATION -- From TLS Session
// =============================================================================
inline bool derive_hmac_key(SSL* ssl, uint8_t* key_out) {
    if (!ssl || !key_out) return false;

    int rc = SSL_export_keying_material(
        ssl,
        key_out, HMAC_KEY_LEN,
        EKM_LABEL, EKM_LABEL_LEN,
        nullptr, 0,
        0
    );

    return (rc == 1);
}

// =============================================================================
// HMAC-SHA256 -- Compute
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
// HMAC-SHA256 -- Verify
// =============================================================================
inline bool verify_hmac(const uint8_t* key, size_t key_len,
                        const uint8_t* data, size_t data_len,
                        const uint8_t* expected_hmac)
{
    uint8_t computed[HMAC_DIGEST_LEN];
    if (!compute_hmac(key, key_len, data, data_len, computed)) {
        return false;
    }
    return CRYPTO_memcmp(computed, expected_hmac, HMAC_DIGEST_LEN) == 0;
}

// =============================================================================
// BUILD V2 HEADER -- Helper to construct a signed packet header
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

    if (payload_data && payload_len > 0) {
        compute_hmac(hmac_key, HMAC_KEY_LEN,
                     payload_data, payload_len,
                     hdr.hmac);
    } else {
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
// CRL LOADING -- Add Certificate Revocation List to SSL_CTX
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

    X509_STORE_set_flags(store,
        X509_V_FLAG_CRL_CHECK |
        X509_V_FLAG_CRL_CHECK_ALL);

    X509_CRL_free(crl);
    return true;
}

// =============================================================================
// OCSP STAPLING -- Client-side callback
// =============================================================================
inline int ocsp_client_callback(SSL* ssl, void* arg) {
    const unsigned char* resp_data = nullptr;
    long resp_len = SSL_get_tlsext_status_ocsp_resp(ssl, &resp_data);

    if (!resp_data || resp_len <= 0) {
        bool* must_staple = static_cast<bool*>(arg);
        if (must_staple && *must_staple) {
            std::cerr << "[OCSP] No stapled response and must_staple=true. Rejecting.\n";
            return 0;
        }
        return 1;
    }

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

    return 1;
}

// =============================================================================
// OCSP STAPLING helpers
// =============================================================================
inline void enable_ocsp_stapling_server(SSL_CTX* ctx) {
    SSL_CTX_set_tlsext_status_type(ctx, TLSEXT_STATUSTYPE_ocsp);
}

inline void enable_ocsp_stapling_client(SSL_CTX* ctx, bool* must_staple_flag) {
    SSL_CTX_set_tlsext_status_type(ctx, TLSEXT_STATUSTYPE_ocsp);
    SSL_CTX_set_tlsext_status_cb(ctx, ocsp_client_callback);
    SSL_CTX_set_tlsext_status_arg(ctx, must_staple_flag);
}

// =============================================================================
// CERTIFICATE PINNING
// =============================================================================
inline bool verify_cert_pin(SSL* ssl, const std::string& expected_pin_hex) {
    if (expected_pin_hex.empty()) return true;

    X509* cert = SSL_get_peer_certificate(ssl);
    if (!cert) return false;

    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    if (X509_digest(cert, EVP_sha256(), md, &md_len) != 1) {
        X509_free(cert);
        return false;
    }
    X509_free(cert);

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
