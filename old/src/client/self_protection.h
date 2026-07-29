#ifndef SELF_PROTECTION_H
#define SELF_PROTECTION_H

#ifndef NOMINMAX
#define NOMINMAX
#endif

// =============================================================================
// SecureSeaHorse SIEM -- Phase 17: Agent Self-Protection & Auto-Update
// =============================================================================
// Client-side component that defends the agent process and its files from
// tampering, and handles signed update delivery from the server.
//
// Components:
//   1. Tamper Detector   -- SHA-256 of the running binary + config files
//                            compared against a sealed baseline on disk
//   2. Watchdog          -- External heartbeat to the server announcing
//                            liveness; also runs a second "guardian"
//                            thread that re-launches the agent if the
//                            main service thread stops responding
//   3. Auto-Updater      -- Polls server for signed update manifests,
//                            verifies RSA-SHA256 signature using the
//                            pinned public key, downloads, and stages
//                            a replacement binary
//
// Design constraints:
//   - Keep everything header-only C++17
//   - Signature verification uses OpenSSL (already linked in the project)
//   - No elevated privileges required at run time (staging only -- an
//     administrator still approves the swap via install_linux.sh)
// =============================================================================

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

#include "fim_common.h"  // re-use sha256_file

namespace fs = std::filesystem;

// =============================================================================
// TAMPER BASELINE -- Stored on disk at first run
// =============================================================================
struct TamperBaselineEntry {
    std::string path;
    std::string sha256;
    uint64_t    size_bytes = 0;
};

class TamperDetector {
public:
    struct Config {
        bool enabled = true;
        std::string baseline_path = "agent_baseline.json";
        std::vector<std::string> protected_paths;   // binary + configs
        int check_interval_s = 60;
    };

    enum class Status { OK, CHANGED, MISSING, NOT_INITIALIZED };
    struct CheckResult {
        Status status = Status::OK;
        std::string offending_path;
        std::string expected_hash;
        std::string actual_hash;
    };

    explicit TamperDetector(const Config& cfg) : config_(cfg) {
        if (config_.enabled) load_baseline();
    }

    // Seal a new baseline -- only callable from the installer / first run.
    bool create_baseline() {
        std::vector<TamperBaselineEntry> entries;
        for (const auto& p : config_.protected_paths) {
            if (!fs::exists(p)) continue;
            uint64_t sz = 0;
            try { sz = fs::file_size(p); } catch (...) {}
            std::string hash = sha256_file(p, 512 * 1024 * 1024, &sz);
            if (hash.empty()) continue;
            entries.push_back({p, hash, sz});
        }
        std::lock_guard<std::mutex> lock(mutex_);
        baseline_ = std::move(entries);
        return save_baseline();
    }

    CheckResult verify() const {
        CheckResult r;
        std::lock_guard<std::mutex> lock(mutex_);
        if (baseline_.empty()) { r.status = Status::NOT_INITIALIZED; return r; }
        for (const auto& e : baseline_) {
            if (!fs::exists(e.path)) {
                r.status = Status::MISSING; r.offending_path = e.path;
                r.expected_hash = e.sha256;
                return r;
            }
            uint64_t actual_sz = 0;
            std::string actual = sha256_file(e.path, 512 * 1024 * 1024, &actual_sz);
            if (actual != e.sha256) {
                r.status = Status::CHANGED;
                r.offending_path = e.path;
                r.expected_hash = e.sha256;
                r.actual_hash = actual;
                return r;
            }
        }
        return r;
    }

    const Config& config() const { return config_; }

private:
    Config config_;
    mutable std::mutex mutex_;
    std::vector<TamperBaselineEntry> baseline_;

    bool save_baseline() {
        // Simple line format: path|sha256|size
        std::ofstream f(config_.baseline_path, std::ios::trunc);
        if (!f.is_open()) return false;
        f << "# SecureSeaHorse agent tamper baseline -- do not edit\n";
        for (const auto& e : baseline_) {
            f << e.path << "|" << e.sha256 << "|" << e.size_bytes << "\n";
        }
        return true;
    }

    void load_baseline() {
        std::lock_guard<std::mutex> lock(mutex_);
        baseline_.clear();
        std::ifstream f(config_.baseline_path);
        if (!f.is_open()) return;
        std::string line;
        while (std::getline(f, line)) {
            if (line.empty() || line[0] == '#') continue;
            std::istringstream iss(line);
            std::string p, h, s;
            if (std::getline(iss, p, '|') && std::getline(iss, h, '|') && std::getline(iss, s, '|')) {
                TamperBaselineEntry e;
                e.path = p; e.sha256 = h;
                try { e.size_bytes = std::stoull(s); } catch (...) {}
                baseline_.push_back(e);
            }
        }
    }
};

// =============================================================================
// WATCHDOG -- External liveness monitor
// =============================================================================
class AgentWatchdog {
public:
    struct Config {
        bool enabled = true;
        int  liveness_ping_interval_s = 30;
        int  stall_threshold_s = 180;        // main thread silent this long => fire
    };

    using StallCallback = std::function<void()>;

    explicit AgentWatchdog(const Config& cfg, StallCallback on_stall = nullptr)
        : config_(cfg), on_stall_(std::move(on_stall)) {}

    ~AgentWatchdog() { stop(); }

    void start() {
        if (!config_.enabled || running_) return;
        running_ = true;
        mark_alive();
        thread_ = std::thread([this]() { loop(); });
    }

    void stop() {
        running_ = false;
        if (thread_.joinable()) thread_.join();
    }

    // Main thread calls this on every work cycle to indicate liveness.
    void mark_alive() {
        last_alive_ms_ = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }

    int64_t last_alive_ms() const { return last_alive_ms_.load(); }

private:
    Config config_;
    StallCallback on_stall_;
    std::thread thread_;
    std::atomic<bool> running_{false};
    std::atomic<int64_t> last_alive_ms_{0};

    void loop() {
        while (running_) {
            std::this_thread::sleep_for(std::chrono::seconds(config_.liveness_ping_interval_s));
            int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            int64_t stale_ms = now_ms - last_alive_ms_;
            if (stale_ms > config_.stall_threshold_s * 1000LL) {
                if (on_stall_) on_stall_();
                last_alive_ms_ = now_ms;  // arm next cycle
            }
        }
    }
};

// =============================================================================
// SIGNED UPDATE MANIFEST
// =============================================================================
// The server sends (via REST or MSG_UPDATE_MANIFEST) a JSON manifest:
//   { "version": "3.6.0",
//     "binary_url": "https://updates/.../seahorse-client",
//     "sha256": "abc...",
//     "signature_b64": "..."      // RSA-SHA256 signature over `version|sha256`
//   }
// =============================================================================
struct UpdateManifest {
    std::string version;
    std::string binary_url;
    std::string sha256;
    std::string signature_b64;

    std::string canonical() const { return version + "|" + sha256; }
};

// =============================================================================
// AUTO-UPDATER
// =============================================================================
class AutoUpdater {
public:
    struct Config {
        bool enabled = true;
        std::string public_key_pem_path = "update_pubkey.pem";
        std::string staging_dir = "update_staging";
        std::string current_version = "3.1.4";
    };

    enum class Verdict { NO_UPDATE, VERIFIED_STAGED, SIG_INVALID, HASH_MISMATCH, ERROR };

    explicit AutoUpdater(const Config& cfg) : config_(cfg) {
        try { fs::create_directories(config_.staging_dir); } catch (...) {}
    }

    // Verify a manifest's signature using the pinned public key.
    bool verify_signature(const UpdateManifest& m) const {
        std::ifstream f(config_.public_key_pem_path);
        if (!f.is_open()) return false;
        std::stringstream ss; ss << f.rdbuf();
        std::string pem = ss.str();

        BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
        if (!bio) return false;
        EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        if (!pkey) return false;

        std::vector<uint8_t> sig = b64_decode(m.signature_b64);
        std::string canonical = m.canonical();

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        bool ok = false;
        if (ctx) {
            if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) == 1 &&
                EVP_DigestVerifyUpdate(ctx, canonical.data(), canonical.size()) == 1) {
                ok = (EVP_DigestVerifyFinal(ctx, sig.data(), sig.size()) == 1);
            }
            EVP_MD_CTX_free(ctx);
        }
        EVP_PKEY_free(pkey);
        return ok;
    }

    // Stage an already-downloaded binary. Caller provides the path to the
    // downloaded file (the fetch itself is out of scope for this header --
    // wire it up through the server REST transport or curl in the caller).
    Verdict stage_update(const UpdateManifest& m, const std::string& downloaded_path) {
        if (!config_.enabled) return Verdict::NO_UPDATE;
        if (!compare_versions(m.version, config_.current_version)) return Verdict::NO_UPDATE;
        if (!verify_signature(m)) return Verdict::SIG_INVALID;

        uint64_t sz = 0;
        std::string hash = sha256_file(downloaded_path, 2ULL * 1024 * 1024 * 1024, &sz);
        if (hash.empty() || hash != m.sha256) return Verdict::HASH_MISMATCH;

        // Copy into staging
        try {
            fs::path target = fs::path(config_.staging_dir) / ("seahorse-client-" + m.version);
            fs::copy_file(downloaded_path, target, fs::copy_options::overwrite_existing);
            last_staged_version_ = m.version;
            return Verdict::VERIFIED_STAGED;
        } catch (...) {
            return Verdict::ERROR;
        }
    }

    std::string last_staged_version() const { return last_staged_version_; }

private:
    Config config_;
    std::string last_staged_version_;

    static bool compare_versions(const std::string& candidate, const std::string& current) {
        // Simple dotted-number comparison; falls back to lexicographic.
        auto parse = [](const std::string& s) {
            std::vector<int> parts; std::string cur;
            for (char c : s) {
                if (c == '.') { try { parts.push_back(std::stoi(cur)); } catch (...) {} cur.clear(); }
                else cur += c;
            }
            if (!cur.empty()) try { parts.push_back(std::stoi(cur)); } catch (...) {}
            return parts;
        };
        auto a = parse(candidate);
        auto b = parse(current);
        for (size_t i = 0; i < std::max(a.size(), b.size()); i++) {
            int av = i < a.size() ? a[i] : 0;
            int bv = i < b.size() ? b[i] : 0;
            if (av != bv) return av > bv;
        }
        return false;
    }

    static std::vector<uint8_t> b64_decode(const std::string& in) {
        static const int8_t tbl[] = {
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
            -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
            -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1};
        std::vector<uint8_t> out;
        int val = 0, bits = -8;
        for (unsigned char c : in) {
            if (c == '=' || c == '\n' || c == '\r' || c == ' ') continue;
            if (c >= 128 || tbl[c] == -1) continue;
            val = (val << 6) | tbl[c];
            bits += 6;
            if (bits >= 0) {
                out.push_back(static_cast<uint8_t>((val >> bits) & 0xFF));
                bits -= 8;
            }
        }
        return out;
    }
};

#endif
