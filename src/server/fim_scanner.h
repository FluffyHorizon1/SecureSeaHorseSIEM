#ifndef FIM_SCANNER_H
#define FIM_SCANNER_H

#ifndef NOMINMAX
#define NOMINMAX
#endif

// =============================================================================
// SecureSeaHorse SIEM — Phase 6: Client-Side FIM Scanner
// =============================================================================
// Provides:
//   - Recursive directory scanning with configurable watch paths
//   - SHA-256 file hashing via OpenSSL (from fim_common.h)
//   - Snapshot comparison: detects adds, modifies, deletes
//   - Configurable exclusion patterns (by extension, path prefix)
//   - Max file size limit to avoid hashing huge files
//   - Thread-safe: snapshot stored with mutex for periodic scan thread
// =============================================================================

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <chrono>
#include <filesystem>
#include <algorithm>
#include <atomic>

#include "fim_common.h"

namespace fs = std::filesystem;

// =============================================================================
// FIM SCANNER CONFIG
// =============================================================================
struct FimScannerConfig {
    bool enabled = true;

    // Watch paths — directories and individual files to monitor
    std::vector<std::string> watch_paths;

    // Exclusion patterns
    std::vector<std::string> exclude_extensions;  // e.g. ".tmp", ".log", ".swp"
    std::vector<std::string> exclude_prefixes;    // e.g. "/tmp/", "/proc/"

    // Limits
    uint64_t max_file_size    = 100 * 1024 * 1024;  // 100MB — skip larger files
    int      max_files        = 50000;                // Safety limit per scan
    int      max_depth        = 20;                   // Max directory recursion depth
    int      scan_interval_s  = 300;                  // Seconds between full scans
};

// =============================================================================
// FIM SCANNER
// =============================================================================
class FimScanner {
public:
    explicit FimScanner(const FimScannerConfig& cfg = {})
        : config_(cfg) {}

    // =========================================================================
    // SCAN: Perform a full scan of all watch paths
    // =========================================================================
    // Returns a snapshot of all monitored files with their current hashes.
    // =========================================================================
    std::vector<FimEntry> scan() {
        std::vector<FimEntry> snapshot;
        files_scanned_ = 0;
        files_hashed_  = 0;
        scan_errors_   = 0;

        for (const auto& watch_path : config_.watch_paths) {
            try {
                fs::path p(watch_path);
                if (!fs::exists(p)) continue;

                if (fs::is_regular_file(p)) {
                    // Single file watch
                    scan_file(p, snapshot);
                } else if (fs::is_directory(p)) {
                    // Recursive directory scan
                    scan_directory(p, snapshot, 0);
                }
            } catch (const std::exception&) {
                scan_errors_++;
            }

            if (static_cast<int>(snapshot.size()) >= config_.max_files) break;
        }

        files_scanned_ = static_cast<int>(snapshot.size());
        return snapshot;
    }

    // =========================================================================
    // DIFF: Compare current scan against previous baseline
    // =========================================================================
    // Returns list of changes (additions, modifications, deletions).
    // =========================================================================
    static std::vector<FimChange> diff(const std::vector<FimEntry>& baseline,
                                        const std::vector<FimEntry>& current)
    {
        std::vector<FimChange> changes;

        // Build maps for O(1) lookup
        std::map<std::string, const FimEntry*> base_map;
        std::map<std::string, const FimEntry*> curr_map;

        for (const auto& e : baseline) base_map[e.path] = &e;
        for (const auto& e : current)  curr_map[e.path] = &e;

        // Check for additions and modifications
        for (const auto& [path, curr_entry] : curr_map) {
            auto it = base_map.find(path);
            if (it == base_map.end()) {
                // New file — ADDED
                FimChange c;
                c.type      = FimChangeType::FIM_ADDED;
                c.path      = path;
                c.new_hash  = curr_entry->sha256;
                c.new_size  = curr_entry->size_bytes;
                c.new_mtime = curr_entry->mtime_epoch;
                c.old_size  = 0;
                c.old_mtime = 0;
                changes.push_back(std::move(c));
            } else {
                // Exists in both — check if modified
                const FimEntry* base_entry = it->second;
                if (base_entry->sha256 != curr_entry->sha256) {
                    FimChange c;
                    c.type      = FimChangeType::FIM_MODIFIED;
                    c.path      = path;
                    c.old_hash  = base_entry->sha256;
                    c.new_hash  = curr_entry->sha256;
                    c.old_size  = base_entry->size_bytes;
                    c.new_size  = curr_entry->size_bytes;
                    c.old_mtime = base_entry->mtime_epoch;
                    c.new_mtime = curr_entry->mtime_epoch;
                    changes.push_back(std::move(c));
                }
            }
        }

        // Check for deletions
        for (const auto& [path, base_entry] : base_map) {
            if (curr_map.find(path) == curr_map.end()) {
                FimChange c;
                c.type      = FimChangeType::FIM_DELETED;
                c.path      = path;
                c.old_hash  = base_entry->sha256;
                c.old_size  = base_entry->size_bytes;
                c.old_mtime = base_entry->mtime_epoch;
                c.new_size  = 0;
                c.new_mtime = 0;
                changes.push_back(std::move(c));
            }
        }

        return changes;
    }

    // =========================================================================
    // SNAPSHOT MANAGEMENT — Thread-safe baseline storage
    // =========================================================================
    void update_baseline(const std::vector<FimEntry>& snapshot) {
        std::lock_guard<std::mutex> lock(mutex_);
        baseline_ = snapshot;
        has_baseline_ = true;
    }

    bool get_baseline(std::vector<FimEntry>& out) const {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!has_baseline_) return false;
        out = baseline_;
        return true;
    }

    bool has_baseline() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return has_baseline_;
    }

    // --- Diagnostics ---
    int files_scanned() const { return files_scanned_; }
    int files_hashed() const  { return files_hashed_; }
    int scan_errors() const   { return scan_errors_; }
    const FimScannerConfig& config() const { return config_; }

private:
    FimScannerConfig config_;
    mutable std::mutex mutex_;
    std::vector<FimEntry> baseline_;
    bool has_baseline_ = false;

    std::atomic<int> files_scanned_{0};
    std::atomic<int> files_hashed_{0};
    std::atomic<int> scan_errors_{0};

    // -------------------------------------------------------------------------
    // SCAN A SINGLE FILE
    // -------------------------------------------------------------------------
    void scan_file(const fs::path& filepath, std::vector<FimEntry>& snapshot) {
        try {
            if (!fs::is_regular_file(filepath)) return;
            if (static_cast<int>(snapshot.size()) >= config_.max_files) return;

            // Check exclusions
            std::string ext = filepath.extension().string();
            std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
            for (const auto& excl : config_.exclude_extensions) {
                if (ext == excl) return;
            }

            std::string abs_path = fs::absolute(filepath).string();
            // Normalize path separators
            std::replace(abs_path.begin(), abs_path.end(), '\\', '/');

            for (const auto& prefix : config_.exclude_prefixes) {
                if (abs_path.find(prefix) == 0) return;
            }

            // Check file size
            auto fsize = fs::file_size(filepath);
            if (fsize > config_.max_file_size) return;

            // Get modification time
            auto ftime = fs::last_write_time(filepath);
            auto sctp = std::chrono::time_point_cast<std::chrono::seconds>(
                std::chrono::clock_cast<std::chrono::system_clock>(ftime));
            int64_t mtime = sctp.time_since_epoch().count();

            // Hash the file
            std::string hash = sha256_file(abs_path);
            if (hash.empty()) {
                scan_errors_++;
                return;
            }

            files_hashed_++;

            FimEntry entry;
            entry.path        = abs_path;
            entry.sha256      = hash;
            entry.size_bytes  = static_cast<uint64_t>(fsize);
            entry.mtime_epoch = mtime;
            snapshot.push_back(std::move(entry));

        } catch (...) {
            scan_errors_++;
        }
    }

    // -------------------------------------------------------------------------
    // SCAN A DIRECTORY RECURSIVELY
    // -------------------------------------------------------------------------
    void scan_directory(const fs::path& dir, std::vector<FimEntry>& snapshot, int depth) {
        if (depth >= config_.max_depth) return;
        if (static_cast<int>(snapshot.size()) >= config_.max_files) return;

        try {
            for (const auto& entry : fs::directory_iterator(dir,
                    fs::directory_options::skip_permission_denied)) {
                if (static_cast<int>(snapshot.size()) >= config_.max_files) return;

                try {
                    if (entry.is_regular_file()) {
                        scan_file(entry.path(), snapshot);
                    } else if (entry.is_directory()) {
                        // Skip symlinks to prevent infinite loops
                        if (entry.is_symlink()) continue;

                        std::string dir_name = entry.path().filename().string();
                        // Skip hidden directories
                        if (!dir_name.empty() && dir_name[0] == '.') continue;

                        scan_directory(entry.path(), snapshot, depth + 1);
                    }
                } catch (...) {
                    scan_errors_++;
                }
            }
        } catch (...) {
            scan_errors_++;
        }
    }
};

#endif
