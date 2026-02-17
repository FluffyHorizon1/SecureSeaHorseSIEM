#ifndef FIM_COMMON_H
#define FIM_COMMON_H

#ifndef NOMINMAX
#define NOMINMAX
#endif

// =============================================================================
// SecureSeaHorse SIEM — Phase 6: File Integrity Monitoring — Common Types
// =============================================================================
// Shared by client (scanner) and server (monitor).
// Provides:
//   - FimEntry: hash record for a single file
//   - FimReport: collection of entries + device metadata
//   - Serialization/deserialization (text-based, pipe-delimited)
//   - SHA-256 file hashing via OpenSSL
// =============================================================================

#include <string>
#include <vector>
#include <sstream>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <algorithm>
#include <iomanip>

#include <openssl/evp.h>

// =============================================================================
// FIM ENTRY — Hash record for a single file
// =============================================================================
struct FimEntry {
    std::string path;          // Absolute file path
    std::string sha256;        // Hex-encoded SHA-256 hash (64 chars)
    uint64_t    size_bytes;    // File size in bytes
    int64_t     mtime_epoch;   // Last modification time (Unix epoch seconds)

    bool operator==(const FimEntry& o) const {
        return path == o.path && sha256 == o.sha256 &&
               size_bytes == o.size_bytes && mtime_epoch == o.mtime_epoch;
    }
    bool operator!=(const FimEntry& o) const { return !(*this == o); }
};

// =============================================================================
// FIM CHANGE — Detected change between baseline and current scan
// =============================================================================
enum class FimChangeType {
    FIM_ADDED,       // New file not in baseline
    FIM_MODIFIED,    // File exists but hash changed
    FIM_DELETED,     // File in baseline but missing from current scan
};

inline std::string fim_change_str(FimChangeType t) {
    switch (t) {
        case FimChangeType::FIM_ADDED:    return "added";
        case FimChangeType::FIM_MODIFIED: return "modified";
        case FimChangeType::FIM_DELETED:  return "deleted";
        default:                          return "unknown";
    }
}

struct FimChange {
    FimChangeType type;
    std::string   path;
    std::string   old_hash;     // Empty for FIM_ADDED
    std::string   new_hash;     // Empty for FIM_DELETED
    uint64_t      old_size;
    uint64_t      new_size;
    int64_t       old_mtime;
    int64_t       new_mtime;
};

// =============================================================================
// FIM REPORT — Serializable snapshot from client to server
// =============================================================================
// Wire format (text, one line per entry):
//   Header line:  FIM|<device_id>|<timestamp_ms>|<entry_count>
//   Entry lines:  <path>|<sha256>|<size_bytes>|<mtime_epoch>
//   Terminator:   FIM_END
// =============================================================================
struct FimReport {
    int32_t device_id;
    int64_t timestamp_ms;
    std::vector<FimEntry> entries;

    // Serialize to text for v2 message payload
    std::string serialize() const {
        std::ostringstream oss;
        oss << "FIM|" << device_id << "|" << timestamp_ms << "|" << entries.size() << "\n";
        for (const auto& e : entries) {
            oss << e.path << "|" << e.sha256 << "|" << e.size_bytes << "|" << e.mtime_epoch << "\n";
        }
        oss << "FIM_END\n";
        return oss.str();
    }

    // Deserialize from text
    static bool deserialize(const std::string& data, FimReport& out) {
        std::istringstream iss(data);
        std::string line;

        // Parse header
        if (!std::getline(iss, line)) return false;
        std::vector<std::string> header = split(line, '|');
        if (header.size() < 4 || header[0] != "FIM") return false;

        try {
            out.device_id    = std::stoi(header[1]);
            out.timestamp_ms = std::stoll(header[2]);
            size_t count     = std::stoull(header[3]);
            out.entries.clear();
            out.entries.reserve(count);
        } catch (...) {
            return false;
        }

        // Parse entries
        while (std::getline(iss, line)) {
            if (line == "FIM_END") break;
            if (line.empty()) continue;

            std::vector<std::string> fields = split(line, '|');
            if (fields.size() < 4) continue;

            FimEntry entry;
            entry.path       = fields[0];
            entry.sha256     = fields[1];
            try {
                entry.size_bytes  = std::stoull(fields[2]);
                entry.mtime_epoch = std::stoll(fields[3]);
            } catch (...) {
                continue;
            }
            out.entries.push_back(std::move(entry));
        }

        return true;
    }

private:
    static std::vector<std::string> split(const std::string& s, char delim) {
        std::vector<std::string> parts;
        std::istringstream iss(s);
        std::string part;
        while (std::getline(iss, part, delim)) {
            parts.push_back(part);
        }
        return parts;
    }
};

// =============================================================================
// SHA-256 FILE HASHING — Using OpenSSL EVP API
// =============================================================================
inline std::string sha256_file(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) return "";

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return "";

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        return "";
    }

    char buf[8192];
    while (file.read(buf, sizeof(buf)) || file.gcount() > 0) {
        if (EVP_DigestUpdate(ctx, buf, static_cast<size_t>(file.gcount())) != 1) {
            EVP_MD_CTX_free(ctx);
            return "";
        }
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return "";
    }
    EVP_MD_CTX_free(ctx);

    // Convert to hex string
    std::ostringstream hex;
    hex << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < hash_len; i++) {
        hex << std::setw(2) << static_cast<int>(hash[i]);
    }
    return hex.str();
}

#endif
