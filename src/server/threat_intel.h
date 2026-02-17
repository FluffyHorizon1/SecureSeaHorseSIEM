#ifndef THREAT_INTEL_H
#define THREAT_INTEL_H

#ifndef NOMINMAX
#define NOMINMAX
#endif

// =============================================================================
// SecureSeaHorse SIEM — Phase 5: Threat Intelligence Feed Engine
// =============================================================================
// Provides:
//   - Indicator of Compromise (IoC) matching: IPs, domains, hashes, user agents
//   - CSV feed loading with configurable format
//   - O(1) hash-map lookups per IoC type
//   - Auto-reload: detects file modification and reloads without restart
//   - MITRE ATT&CK tagging on every IoC match
//   - Thread-safe: read-write lock allows concurrent matching during reload
// =============================================================================

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <map>
#include <mutex>
#include <shared_mutex>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <regex>
#include <filesystem>
#include <functional>
#include <atomic>

namespace fs = std::filesystem;

// =============================================================================
// IoC TYPES
// =============================================================================
enum class IoCType {
    IoC_IP,     // IPv4 or IPv6
    IoC_DOMAIN,         // FQDN or subdomain
    IoC_HASH,      // MD5, SHA1, SHA256
    IoC_UA,     // HTTP user-agent string
    IoC_URL,            // Full URL pattern
    IoC_EMAIL,          // Email address
    IoC_CIDR,           // IP range (e.g. 10.0.0.0/8) — matched via prefix
};

inline std::string ioc_type_str(IoCType t) {
    switch (t) {
        case IoCType::IoC_IP: return "ip";
        case IoCType::IoC_DOMAIN:     return "domain";
        case IoCType::IoC_HASH:  return "hash";
        case IoCType::IoC_UA: return "useragent";
        case IoCType::IoC_URL:        return "url";
        case IoCType::IoC_EMAIL:      return "email";
        case IoCType::IoC_CIDR:       return "cidr";
        default:                  return "unknown";
    }
}

inline IoCType parse_ioc_type(const std::string& s) {
    std::string lower = s;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    if (lower == "ip" || lower == "ip_address" || lower == "ipv4" || lower == "ipv6") return IoCType::IoC_IP;
    if (lower == "domain" || lower == "fqdn" || lower == "hostname") return IoCType::IoC_DOMAIN;
    if (lower == "hash" || lower == "md5" || lower == "sha1" || lower == "sha256" || lower == "file_hash") return IoCType::IoC_HASH;
    if (lower == "useragent" || lower == "user_agent" || lower == "ua") return IoCType::IoC_UA;
    if (lower == "url") return IoCType::IoC_URL;
    if (lower == "email") return IoCType::IoC_EMAIL;
    if (lower == "cidr") return IoCType::IoC_CIDR;
    return IoCType::IoC_IP;  // Default fallback
}

// =============================================================================
// IoC ENTRY — Single indicator record
// =============================================================================
struct IoCEntry {
    IoCType     type;
    std::string value;          // The indicator itself (normalized to lowercase)
    std::string severity;       // "low", "medium", "high", "critical"
    std::string feed_source;    // Name of the feed file it came from
    std::string description;    // Human-readable description
    std::string mitre_id;       // MITRE ATT&CK technique ID (optional)
    std::string tags;           // Comma-separated tags (e.g. "apt,ransomware")
    int64_t     first_seen;     // Unix timestamp when added to feed (0 = unknown)
    int64_t     last_seen;      // Unix timestamp of last activity (0 = unknown)
};

// =============================================================================
// IoC MATCH — Result from the matcher
// =============================================================================
struct IoCMatch {
    IoCEntry    ioc;            // The matched indicator
    std::string matched_in;     // Where it was found: "client_ip", "log_chunk", "machine_name"
    std::string context;        // Surrounding text or field value
};

// =============================================================================
// CIDR HELPER — Check if an IP falls within a CIDR range
// =============================================================================
inline uint32_t ip_to_uint32(const std::string& ip) {
    uint32_t result = 0;
    int octets[4] = {0};
    if (sscanf(ip.c_str(), "%d.%d.%d.%d", &octets[0], &octets[1], &octets[2], &octets[3]) == 4) {
        result = (static_cast<uint32_t>(octets[0]) << 24) |
                 (static_cast<uint32_t>(octets[1]) << 16) |
                 (static_cast<uint32_t>(octets[2]) << 8)  |
                 static_cast<uint32_t>(octets[3]);
    }
    return result;
}

struct CidrRange {
    uint32_t    network;
    uint32_t    mask;
    IoCEntry    entry;
};

inline bool ip_in_cidr(uint32_t ip, const CidrRange& cidr) {
    return (ip & cidr.mask) == (cidr.network & cidr.mask);
}

inline CidrRange parse_cidr(const std::string& cidr_str, const IoCEntry& entry) {
    CidrRange range;
    range.entry = entry;
    range.network = 0;
    range.mask = 0;

    size_t slash = cidr_str.find('/');
    if (slash == std::string::npos) {
        range.network = ip_to_uint32(cidr_str);
        range.mask = 0xFFFFFFFF;  // /32
    } else {
        range.network = ip_to_uint32(cidr_str.substr(0, slash));
        int prefix_len = std::stoi(cidr_str.substr(slash + 1));
        if (prefix_len >= 0 && prefix_len <= 32) {
            range.mask = (prefix_len == 0) ? 0 : (~0u << (32 - prefix_len));
        }
    }
    return range;
}

// =============================================================================
// FEED FILE TRACKER — Monitors file modification time for auto-reload
// =============================================================================
struct FeedFile {
    std::string path;
    std::string name;          // Human-readable feed name
    fs::file_time_type last_modified;
    size_t entry_count = 0;
};

// =============================================================================
// IoC STORE — Thread-safe indicator database with O(1) lookups
// =============================================================================
class IoCStore {
public:
    IoCStore() = default;

    // -------------------------------------------------------------------------
    // LOAD: Parse a CSV feed file into the store
    // -------------------------------------------------------------------------
    // CSV format: type|value|severity|description|mitre_id|tags
    // Lines starting with # are comments. Empty lines are skipped.
    // Pipe-delimited (same as rules.conf) for consistency.
    // -------------------------------------------------------------------------
    size_t load_feed(const std::string& path, const std::string& feed_name) {
        std::ifstream file(path);
        if (!file.is_open()) return 0;

        size_t loaded = 0;
        std::string line;

        while (std::getline(file, line)) {
            // Strip comments and whitespace
            size_t comment = line.find('#');
            if (comment != std::string::npos) line = line.substr(0, comment);
            line.erase(0, line.find_first_not_of(" \t\r\n"));
            line.erase(line.find_last_not_of(" \t\r\n") + 1);
            if (line.empty()) continue;

            // Parse pipe-delimited fields
            std::vector<std::string> fields;
            std::istringstream iss(line);
            std::string field;
            while (std::getline(iss, field, '|')) {
                field.erase(0, field.find_first_not_of(" \t"));
                field.erase(field.find_last_not_of(" \t") + 1);
                fields.push_back(field);
            }

            if (fields.size() < 2) continue;  // Need at least type + value

            IoCEntry entry;
            entry.type        = parse_ioc_type(fields[0]);
            entry.value       = fields[1];
            entry.severity    = (fields.size() > 2 && !fields[2].empty()) ? fields[2] : "high";
            entry.description = (fields.size() > 3) ? fields[3] : "";
            entry.mitre_id    = (fields.size() > 4) ? fields[4] : "";
            entry.tags        = (fields.size() > 5) ? fields[5] : "";
            entry.feed_source = feed_name;
            entry.first_seen  = 0;
            entry.last_seen   = 0;

            // Normalize value to lowercase for matching
            std::transform(entry.value.begin(), entry.value.end(),
                           entry.value.begin(), ::tolower);

            add(entry);
            loaded++;
        }

        return loaded;
    }

    // -------------------------------------------------------------------------
    // ADD: Insert a single IoC entry
    // -------------------------------------------------------------------------
    void add(const IoCEntry& entry) {
        switch (entry.type) {
            case IoCType::IoC_IP:
                ip_map_[entry.value] = entry;
                break;
            case IoCType::IoC_DOMAIN:
                domain_map_[entry.value] = entry;
                break;
            case IoCType::IoC_HASH:
                hash_map_[entry.value] = entry;
                break;
            case IoCType::IoC_UA:
                ua_map_[entry.value] = entry;
                break;
            case IoCType::IoC_URL:
                url_map_[entry.value] = entry;
                break;
            case IoCType::IoC_EMAIL:
                email_map_[entry.value] = entry;
                break;
            case IoCType::IoC_CIDR:
                cidr_ranges_.push_back(parse_cidr(entry.value, entry));
                break;
        }
    }

    // -------------------------------------------------------------------------
    // LOOKUP: Check if a specific value exists (O(1) for hash maps)
    // -------------------------------------------------------------------------
    bool lookup_ip(const std::string& ip, IoCEntry& out) const {
        std::string lower = ip;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        auto it = ip_map_.find(lower);
        if (it != ip_map_.end()) { out = it->second; return true; }

        // Check CIDR ranges (linear scan — typically small)
        uint32_t ip_num = ip_to_uint32(lower);
        if (ip_num != 0) {
            for (const auto& cidr : cidr_ranges_) {
                if (ip_in_cidr(ip_num, cidr)) {
                    out = cidr.entry;
                    return true;
                }
            }
        }
        return false;
    }

    bool lookup_domain(const std::string& domain, IoCEntry& out) const {
        std::string lower = domain;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        // Exact match
        auto it = domain_map_.find(lower);
        if (it != domain_map_.end()) { out = it->second; return true; }
        // Subdomain match: check if any feed domain is a suffix
        for (const auto& [key, val] : domain_map_) {
            if (lower.size() > key.size() &&
                lower.substr(lower.size() - key.size()) == key &&
                lower[lower.size() - key.size() - 1] == '.') {
                out = val;
                return true;
            }
        }
        return false;
    }

    bool lookup_hash(const std::string& hash, IoCEntry& out) const {
        std::string lower = hash;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        auto it = hash_map_.find(lower);
        if (it != hash_map_.end()) { out = it->second; return true; }
        return false;
    }

    bool lookup_ua(const std::string& ua, IoCEntry& out) const {
        std::string lower = ua;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        for (const auto& [key, val] : ua_map_) {
            if (lower.find(key) != std::string::npos) { out = val; return true; }
        }
        return false;
    }

    bool lookup_url(const std::string& url, IoCEntry& out) const {
        std::string lower = url;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        auto it = url_map_.find(lower);
        if (it != url_map_.end()) { out = it->second; return true; }
        return false;
    }

    bool lookup_email(const std::string& email, IoCEntry& out) const {
        std::string lower = email;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        auto it = email_map_.find(lower);
        if (it != email_map_.end()) { out = it->second; return true; }
        return false;
    }

    // -------------------------------------------------------------------------
    // CLEAR: Wipe the store (for reload)
    // -------------------------------------------------------------------------
    void clear() {
        ip_map_.clear();
        domain_map_.clear();
        hash_map_.clear();
        ua_map_.clear();
        url_map_.clear();
        email_map_.clear();
        cidr_ranges_.clear();
    }

    // -------------------------------------------------------------------------
    // STATS
    // -------------------------------------------------------------------------
    size_t total_count() const {
        return ip_map_.size() + domain_map_.size() + hash_map_.size() +
               ua_map_.size() + url_map_.size() + email_map_.size() +
               cidr_ranges_.size();
    }

    size_t ip_count() const      { return ip_map_.size() + cidr_ranges_.size(); }
    size_t domain_count() const  { return domain_map_.size(); }
    size_t hash_count() const    { return hash_map_.size(); }

private:
    std::unordered_map<std::string, IoCEntry> ip_map_;
    std::unordered_map<std::string, IoCEntry> domain_map_;
    std::unordered_map<std::string, IoCEntry> hash_map_;
    std::unordered_map<std::string, IoCEntry> ua_map_;
    std::unordered_map<std::string, IoCEntry> url_map_;
    std::unordered_map<std::string, IoCEntry> email_map_;
    std::vector<CidrRange> cidr_ranges_;
};

// =============================================================================
// THREAT INTEL ENGINE — Feed management + real-time matching
// =============================================================================
class ThreatIntelEngine {
public:
    struct Config {
        bool        enabled          = true;
        std::string feeds_dir        = "feeds";    // Directory containing feed CSVs
        int         reload_interval_s = 300;        // Check for feed updates every N seconds
    };

    explicit ThreatIntelEngine(const Config& cfg = {})
        : config_(cfg), last_reload_(std::chrono::steady_clock::now())
    {
        if (config_.enabled) {
            load_all_feeds();
        }
    }

    // =========================================================================
    // MATCH: Scan telemetry + log data against all loaded IoCs
    // =========================================================================
    // Returns all matches found in this report.
    // =========================================================================
    std::vector<IoCMatch> match(
        const std::string& client_ip,
        const std::string& machine_name,
        const std::string& os_user,
        const std::string& raw_log) const
    {
        if (!config_.enabled) return {};

        std::shared_lock<std::shared_mutex> lock(rw_mutex_);
        std::vector<IoCMatch> matches;

        // --- Match client IP against blocklists ---
        IoCEntry entry;
        if (store_.lookup_ip(client_ip, entry)) {
            matches.push_back({entry, "client_ip", client_ip});
        }

        // --- Extract and match IPs from log chunk ---
        auto log_ips = extract_ips(raw_log);
        for (const auto& ip : log_ips) {
            if (store_.lookup_ip(ip, entry)) {
                matches.push_back({entry, "log_chunk_ip", ip});
            }
        }

        // --- Extract and match domains from log chunk ---
        auto log_domains = extract_domains(raw_log);
        for (const auto& domain : log_domains) {
            if (store_.lookup_domain(domain, entry)) {
                matches.push_back({entry, "log_chunk_domain", domain});
            }
        }

        // --- Extract and match hashes from log chunk ---
        auto log_hashes = extract_hashes(raw_log);
        for (const auto& hash : log_hashes) {
            if (store_.lookup_hash(hash, entry)) {
                matches.push_back({entry, "log_chunk_hash", hash});
            }
        }

        // --- Extract and match URLs from log chunk ---
        auto log_urls = extract_urls(raw_log);
        for (const auto& url : log_urls) {
            if (store_.lookup_url(url, entry)) {
                matches.push_back({entry, "log_chunk_url", url});
            }
        }

        // --- Extract and match emails from log chunk ---
        auto log_emails = extract_emails(raw_log);
        for (const auto& email : log_emails) {
            if (store_.lookup_email(email, entry)) {
                matches.push_back({entry, "log_chunk_email", email});
            }
        }

        return matches;
    }

    // =========================================================================
    // AUTO-RELOAD: Check if feed files have been modified and reload
    // =========================================================================
    // Call this periodically (e.g. every 30s from the diagnostics thread).
    // Uses file modification timestamps to detect changes.
    // =========================================================================
    bool check_and_reload() {
        if (!config_.enabled) return false;

        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_reload_).count();
        if (elapsed < config_.reload_interval_s) return false;

        last_reload_ = now;

        // Check if any feed file has been modified
        bool needs_reload = false;
        for (auto& ff : feed_files_) {
            try {
                auto current_mtime = fs::last_write_time(ff.path);
                if (current_mtime != ff.last_modified) {
                    needs_reload = true;
                    break;
                }
            } catch (...) {
                // File may have been deleted — trigger reload to clean up
                needs_reload = true;
                break;
            }
        }

        // Also check for new files in the feeds directory
        if (!needs_reload) {
            try {
                size_t current_file_count = 0;
                for (const auto& entry : fs::directory_iterator(config_.feeds_dir)) {
                    if (entry.path().extension() == ".csv") current_file_count++;
                }
                if (current_file_count != feed_files_.size()) needs_reload = true;
            } catch (...) {}
        }

        if (needs_reload) {
            load_all_feeds();
            return true;
        }
        return false;
    }

    // =========================================================================
    // MANUAL RELOAD: Force reload all feeds
    // =========================================================================
    void reload() {
        load_all_feeds();
    }

    // --- Diagnostics ---
    size_t total_iocs() const {
        std::shared_lock<std::shared_mutex> lock(rw_mutex_);
        return store_.total_count();
    }
    size_t feed_count() const { return feed_files_.size(); }
    size_t ip_count() const {
        std::shared_lock<std::shared_mutex> lock(rw_mutex_);
        return store_.ip_count();
    }
    size_t domain_count() const {
        std::shared_lock<std::shared_mutex> lock(rw_mutex_);
        return store_.domain_count();
    }
    size_t hash_count() const {
        std::shared_lock<std::shared_mutex> lock(rw_mutex_);
        return store_.hash_count();
    }

    std::atomic<size_t> total_matches{0};

    const Config& config() const { return config_; }

private:
    Config config_;
    mutable std::shared_mutex rw_mutex_;  // Allows concurrent reads, exclusive writes
    IoCStore store_;
    std::vector<FeedFile> feed_files_;
    std::chrono::steady_clock::time_point last_reload_;

    // Compiled regex patterns for extracting indicators from log text
    struct Extractors {
        std::regex ip_pattern;
        std::regex domain_pattern;
        std::regex hash_pattern;
        std::regex url_pattern;
        std::regex email_pattern;
    };

    static const Extractors& extractors() {
        static Extractors ext = []() {
            Extractors e;
            try {
                // IPv4 addresses
                e.ip_pattern = std::regex(
                    R"(\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b)",
                    std::regex_constants::optimize);

                // Domain names (simplified — captures FQDNs)
                e.domain_pattern = std::regex(
                    R"(\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,})\b)",
                    std::regex_constants::optimize);

                // File hashes: MD5 (32 hex), SHA1 (40 hex), SHA256 (64 hex)
                e.hash_pattern = std::regex(
                    R"(\b([a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b)",
                    std::regex_constants::optimize);

                // URLs
                e.url_pattern = std::regex(
                    R"(https?://[^\s\"'<>]+)",
                    std::regex_constants::icase | std::regex_constants::optimize);

                // Email addresses
                e.email_pattern = std::regex(
                    R"(\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b)",
                    std::regex_constants::optimize);
            } catch (...) {}
            return e;
        }();
        return ext;
    }

    // --- Extraction helpers ---
    static std::vector<std::string> extract_ips(const std::string& text) {
        std::vector<std::string> results;
        if (text.empty()) return results;
        const auto& ext = extractors();
        auto begin = std::sregex_iterator(text.begin(), text.end(), ext.ip_pattern);
        auto end   = std::sregex_iterator();
        std::unordered_set<std::string> seen;
        for (auto it = begin; it != end; ++it) {
            std::string ip = (*it)[1].str();
            // Skip common non-routable/local IPs to reduce noise
            if (ip.substr(0, 4) == "127." || ip == "0.0.0.0" || ip == "255.255.255.255") continue;
            if (seen.insert(ip).second) results.push_back(ip);
        }
        return results;
    }

    static std::vector<std::string> extract_domains(const std::string& text) {
        std::vector<std::string> results;
        if (text.empty()) return results;
        const auto& ext = extractors();
        auto begin = std::sregex_iterator(text.begin(), text.end(), ext.domain_pattern);
        auto end   = std::sregex_iterator();
        std::unordered_set<std::string> seen;
        for (auto it = begin; it != end; ++it) {
            std::string domain = (*it)[1].str();
            std::transform(domain.begin(), domain.end(), domain.begin(), ::tolower);
            // Skip IPs that look like domains (all numeric octets)
            bool all_digits = true;
            for (char c : domain) { if (!isdigit(c) && c != '.') { all_digits = false; break; } }
            if (all_digits) continue;
            if (seen.insert(domain).second) results.push_back(domain);
        }
        return results;
    }

    static std::vector<std::string> extract_hashes(const std::string& text) {
        std::vector<std::string> results;
        if (text.empty()) return results;
        const auto& ext = extractors();
        auto begin = std::sregex_iterator(text.begin(), text.end(), ext.hash_pattern);
        auto end   = std::sregex_iterator();
        std::unordered_set<std::string> seen;
        for (auto it = begin; it != end; ++it) {
            std::string hash = (*it)[1].str();
            std::transform(hash.begin(), hash.end(), hash.begin(), ::tolower);
            if (seen.insert(hash).second) results.push_back(hash);
        }
        return results;
    }

    static std::vector<std::string> extract_urls(const std::string& text) {
        std::vector<std::string> results;
        if (text.empty()) return results;
        const auto& ext = extractors();
        auto begin = std::sregex_iterator(text.begin(), text.end(), ext.url_pattern);
        auto end   = std::sregex_iterator();
        std::unordered_set<std::string> seen;
        for (auto it = begin; it != end; ++it) {
            std::string url = (*it)[0].str();
            std::transform(url.begin(), url.end(), url.begin(), ::tolower);
            if (seen.insert(url).second) results.push_back(url);
        }
        return results;
    }

    static std::vector<std::string> extract_emails(const std::string& text) {
        std::vector<std::string> results;
        if (text.empty()) return results;
        const auto& ext = extractors();
        auto begin = std::sregex_iterator(text.begin(), text.end(), ext.email_pattern);
        auto end   = std::sregex_iterator();
        std::unordered_set<std::string> seen;
        for (auto it = begin; it != end; ++it) {
            std::string email = (*it)[0].str();
            std::transform(email.begin(), email.end(), email.begin(), ::tolower);
            if (seen.insert(email).second) results.push_back(email);
        }
        return results;
    }

    // =========================================================================
    // LOAD ALL FEEDS: Scan feeds directory and load every .csv file
    // =========================================================================
    void load_all_feeds() {
        // Build a new store, then swap under write lock
        IoCStore new_store;
        std::vector<FeedFile> new_files;

        try {
            if (!fs::exists(config_.feeds_dir) || !fs::is_directory(config_.feeds_dir)) {
                // Create feeds directory if it doesn't exist
                fs::create_directories(config_.feeds_dir);
            }

            for (const auto& entry : fs::directory_iterator(config_.feeds_dir)) {
                if (!entry.is_regular_file()) continue;
                std::string ext = entry.path().extension().string();
                std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
                if (ext != ".csv") continue;

                std::string path = entry.path().string();
                std::string name = entry.path().stem().string();

                size_t loaded = new_store.load_feed(path, name);

                FeedFile ff;
                ff.path = path;
                ff.name = name;
                ff.entry_count = loaded;
                try { ff.last_modified = fs::last_write_time(path); } catch (...) {}

                new_files.push_back(ff);
            }
        } catch (...) {
            // Directory scan failed — keep existing store
            return;
        }

        // Swap under exclusive write lock
        {
            std::unique_lock<std::shared_mutex> lock(rw_mutex_);
            store_ = std::move(new_store);
            feed_files_ = std::move(new_files);
        }
    }
};

#endif
