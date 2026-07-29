#ifndef NETWORK_INSPECTOR_H
#define NETWORK_INSPECTOR_H

#ifndef NOMINMAX
#define NOMINMAX
#endif

// =============================================================================
// SecureSeaHorse SIEM -- Phase 10: Network Deep Inspection
// =============================================================================
// Provides:
//   - DNS query analysis: tunneling detection, DGA domain scoring
//   - Protocol anomaly detection: unusual ports, methods, header sizes
//   - Connection state tracking: SYN flood, half-open, session abuse
//   - Payload entropy analysis: encrypted C2, data encoding detection
//   - Extracts indicators from log chunks and telemetry metadata
//   - Thread-safe: concurrent analysis from telemetry processing
// =============================================================================

#include <string>
#include <vector>
#include <map>
#include <set>
#include <mutex>
#include <regex>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <sstream>
#include <algorithm>
#include <numeric>

// =============================================================================
// NETWORK FINDING -- Output from deep inspection
// =============================================================================
struct NetworkFinding {
    int32_t     device_id     = 0;
    int64_t     timestamp_ms  = 0;
    std::string machine_ip;
    std::string category;       // "dns_tunnel","dga","proto_anomaly","syn_flood","entropy"
    std::string severity;       // "low","medium","high","critical"
    std::string mitre_id;
    std::string description;
    double      confidence    = 0.0;  // 0.0-1.0
    std::string indicator;      // Domain, IP, port, etc.
    std::string raw_evidence;   // Snippet that triggered the finding
};

// =============================================================================
// DNS ANALYSIS -- Detect tunneling and DGA domains
// =============================================================================
class DnsAnalyzer {
public:
    // Analyze a DNS query extracted from logs
    std::vector<NetworkFinding> analyze_query(const std::string& domain,
                                               int32_t device_id,
                                               const std::string& machine_ip) const
    {
        std::vector<NetworkFinding> findings;
        if (domain.empty() || domain.size() < 4) return findings;

        std::string lower = domain;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

        // --- DGA Detection: Entropy + consonant ratio ---
        double entropy = char_entropy(lower);
        double consonant_r = consonant_ratio(lower);
        size_t label_count = count_labels(lower);
        size_t max_label_len = max_label_length(lower);

        // High entropy + high consonant ratio = likely DGA
        if (entropy > 3.5 && consonant_r > 0.7 && max_label_len > 12) {
            double conf = std::min(1.0, (entropy - 3.0) * 0.3 + (consonant_r - 0.5) * 0.5);
            NetworkFinding f;
            f.device_id = device_id; f.machine_ip = machine_ip;
            f.timestamp_ms = current_ms();
            f.category = "dga"; f.severity = conf > 0.7 ? "high" : "medium";
            f.mitre_id = "T1568.002"; f.confidence = conf;
            f.indicator = domain;
            f.description = "Possible DGA domain detected (entropy=" + fmt(entropy, 2)
                + " consonant_ratio=" + fmt(consonant_r, 2) + ")";
            findings.push_back(std::move(f));
        }

        // --- DNS Tunneling: Excessive subdomain depth or long labels ---
        if (label_count > 5 || max_label_len > 40 || lower.size() > 80) {
            double conf = 0.5;
            if (max_label_len > 50) conf = 0.8;
            if (label_count > 7) conf = 0.9;
            NetworkFinding f;
            f.device_id = device_id; f.machine_ip = machine_ip;
            f.timestamp_ms = current_ms();
            f.category = "dns_tunnel"; f.severity = conf > 0.7 ? "high" : "medium";
            f.mitre_id = "T1071.004"; f.confidence = conf;
            f.indicator = domain;
            f.description = "Possible DNS tunneling (labels=" + std::to_string(label_count)
                + " max_label_len=" + std::to_string(max_label_len)
                + " total_len=" + std::to_string(lower.size()) + ")";
            findings.push_back(std::move(f));
        }

        // --- Known suspicious TLDs ---
        static const std::set<std::string> suspicious_tlds = {
            ".xyz",".top",".tk",".ml",".ga",".cf",".gq",
            ".work",".click",".loan",".racing",".download"
        };
        for (const auto& tld : suspicious_tlds) {
            if (lower.size() > tld.size() && lower.substr(lower.size() - tld.size()) == tld) {
                if (entropy > 3.0) {
                    NetworkFinding f;
                    f.device_id = device_id; f.machine_ip = machine_ip;
                    f.timestamp_ms = current_ms();
                    f.category = "dga"; f.severity = "medium";
                    f.mitre_id = "T1568.002"; f.confidence = 0.5;
                    f.indicator = domain;
                    f.description = "Suspicious TLD with high entropy: " + tld;
                    findings.push_back(std::move(f));
                }
                break;
            }
        }

        return findings;
    }

    // Extract and analyze DNS queries from raw log text
    std::vector<NetworkFinding> analyze_log_chunk(const std::string& log,
                                                    int32_t device_id,
                                                    const std::string& ip) const
    {
        std::vector<NetworkFinding> all;
        // Pattern: DNS query for <domain>, query[A]: <domain>, lookup <domain>
        static const std::regex dns_rx(
            R"((?:query|lookup|resolve[ds]?|DNS)[^a-z]*([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+))",
            std::regex_constants::optimize | std::regex_constants::icase);

        std::sregex_iterator it(log.begin(), log.end(), dns_rx);
        std::sregex_iterator end;
        std::set<std::string> seen;

        for (; it != end; ++it) {
            std::string domain = (*it)[1].str();
            if (seen.count(domain)) continue;
            seen.insert(domain);
            auto findings = analyze_query(domain, device_id, ip);
            all.insert(all.end(), findings.begin(), findings.end());
        }
        return all;
    }

private:
    static double char_entropy(const std::string& s) {
        if (s.empty()) return 0.0;
        int freq[256] = {};
        int total = 0;
        for (char c : s) {
            if (c == '.') continue; // Skip dots
            freq[static_cast<unsigned char>(c)]++;
            total++;
        }
        if (total == 0) return 0.0;
        double ent = 0.0;
        for (int i = 0; i < 256; i++) {
            if (freq[i] == 0) continue;
            double p = static_cast<double>(freq[i]) / total;
            ent -= p * std::log2(p);
        }
        return ent;
    }

    static double consonant_ratio(const std::string& s) {
        static const std::string vowels = "aeiou";
        int consonants = 0, alpha = 0;
        for (char c : s) {
            if (c == '.' || c == '-') continue;
            if (std::isalpha(c)) {
                alpha++;
                if (vowels.find(std::tolower(c)) == std::string::npos)
                    consonants++;
            }
        }
        return alpha > 0 ? static_cast<double>(consonants) / alpha : 0.0;
    }

    static size_t count_labels(const std::string& domain) {
        return std::count(domain.begin(), domain.end(), '.') + 1;
    }

    static size_t max_label_length(const std::string& domain) {
        size_t max_len = 0, cur = 0;
        for (char c : domain) {
            if (c == '.') { max_len = std::max(max_len, cur); cur = 0; }
            else cur++;
        }
        return std::max(max_len, cur);
    }

    static int64_t current_ms() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }

    static std::string fmt(double v, int prec) {
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(prec) << v;
        return oss.str();
    }
};

// =============================================================================
// PROTOCOL ANOMALY DETECTOR
// =============================================================================
class ProtocolAnalyzer {
public:
    std::vector<NetworkFinding> analyze_log_chunk(const std::string& log,
                                                    int32_t device_id,
                                                    const std::string& ip) const
    {
        std::vector<NetworkFinding> findings;

        // --- Unusual HTTP methods ---
        static const std::regex http_method_rx(
            R"(\b(CONNECT|TRACE|PROPFIND|MKCOL|COPY|MOVE|LOCK|UNLOCK|PATCH)\s+\S+\s+HTTP)",
            std::regex_constants::optimize | std::regex_constants::icase);
        {
            std::sregex_iterator it(log.begin(), log.end(), http_method_rx);
            std::sregex_iterator end;
            for (; it != end; ++it) {
                NetworkFinding f;
                f.device_id = device_id; f.machine_ip = ip;
                f.timestamp_ms = current_ms();
                f.category = "proto_anomaly"; f.severity = "medium";
                f.mitre_id = "T1190"; f.confidence = 0.6;
                f.indicator = (*it)[1].str();
                f.description = "Unusual HTTP method: " + f.indicator;
                f.raw_evidence = (*it)[0].str().substr(0, 100);
                findings.push_back(std::move(f));
            }
        }

        // --- Suspicious user agents ---
        static const std::regex ua_rx(
            R"(User-Agent:\s*(python-requests|curl|wget|powershell|certutil|bitsadmin|Go-http-client))",
            std::regex_constants::optimize | std::regex_constants::icase);
        {
            std::sregex_iterator it(log.begin(), log.end(), ua_rx);
            std::sregex_iterator end;
            for (; it != end; ++it) {
                NetworkFinding f;
                f.device_id = device_id; f.machine_ip = ip;
                f.timestamp_ms = current_ms();
                f.category = "proto_anomaly"; f.severity = "medium";
                f.mitre_id = "T1071.001"; f.confidence = 0.5;
                f.indicator = (*it)[1].str();
                f.description = "Suspicious user agent in logs: " + f.indicator;
                findings.push_back(std::move(f));
            }
        }

        // --- Base64-encoded payloads in URLs ---
        static const std::regex b64_rx(
            R"([?&=][A-Za-z0-9+/]{40,}={0,2})",
            std::regex_constants::optimize);
        {
            std::sregex_iterator it(log.begin(), log.end(), b64_rx);
            std::sregex_iterator end;
            for (; it != end; ++it) {
                NetworkFinding f;
                f.device_id = device_id; f.machine_ip = ip;
                f.timestamp_ms = current_ms();
                f.category = "proto_anomaly"; f.severity = "high";
                f.mitre_id = "T1132.001"; f.confidence = 0.65;
                f.indicator = (*it)[0].str().substr(0, 60);
                f.description = "Base64-encoded data in URL parameter (possible data encoding)";
                findings.push_back(std::move(f));
            }
        }

        // --- Unusually long URLs (command injection, SQLi) ---
        static const std::regex long_url_rx(
            R"((GET|POST)\s+(\S{300,})\s+HTTP)",
            std::regex_constants::optimize | std::regex_constants::icase);
        {
            std::sregex_iterator it(log.begin(), log.end(), long_url_rx);
            std::sregex_iterator end;
            for (; it != end; ++it) {
                NetworkFinding f;
                f.device_id = device_id; f.machine_ip = ip;
                f.timestamp_ms = current_ms();
                f.category = "proto_anomaly"; f.severity = "high";
                f.mitre_id = "T1190"; f.confidence = 0.7;
                f.indicator = (*it)[2].str().substr(0, 80) + "...";
                f.description = "Unusually long URL (" + std::to_string((*it)[2].str().size())
                    + " chars) -- possible injection attempt";
                findings.push_back(std::move(f));
            }
        }

        return findings;
    }

private:
    static int64_t current_ms() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }
};

// =============================================================================
// CONNECTION STATE TRACKER -- Per-device connection pattern analysis
// =============================================================================
class ConnectionTracker {
public:
    struct ConnStats {
        uint64_t total_connections  = 0;
        uint64_t syn_count          = 0;
        uint64_t rst_count          = 0;
        uint64_t fin_count          = 0;
        uint64_t half_open          = 0;
        double   avg_duration_ms    = 0.0;
        int64_t  last_update_ms     = 0;
        std::map<int, int> port_freq;  // port -> count
    };

    void update(int32_t device_id, uint64_t connections, uint64_t resets,
                uint64_t refused, int64_t timestamp_ms)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto& s = stats_[device_id];
        s.total_connections = connections;
        s.rst_count = resets;
        s.half_open = refused;
        s.last_update_ms = timestamp_ms;
    }

    std::vector<NetworkFinding> check_anomalies(int32_t device_id,
                                                  const std::string& ip) const
    {
        std::vector<NetworkFinding> findings;
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = stats_.find(device_id);
        if (it == stats_.end()) return findings;
        const auto& s = it->second;

        // SYN flood indicator: very high half-open to total ratio
        if (s.total_connections > 100 && s.half_open > 0) {
            double ratio = static_cast<double>(s.half_open) / s.total_connections;
            if (ratio > 0.5) {
                NetworkFinding f;
                f.device_id = device_id; f.machine_ip = ip;
                f.timestamp_ms = current_ms();
                f.category = "syn_flood"; f.severity = "high";
                f.mitre_id = "T1498.001"; f.confidence = std::min(1.0, ratio);
                f.description = "High half-open connection ratio (" + fmt(ratio * 100, 1) + "%)";
                findings.push_back(std::move(f));
            }
        }

        // RST storm
        if (s.total_connections > 50 && s.rst_count > 0) {
            double rst_ratio = static_cast<double>(s.rst_count) / s.total_connections;
            if (rst_ratio > 0.4) {
                NetworkFinding f;
                f.device_id = device_id; f.machine_ip = ip;
                f.timestamp_ms = current_ms();
                f.category = "proto_anomaly"; f.severity = "medium";
                f.mitre_id = "T1046"; f.confidence = std::min(1.0, rst_ratio);
                f.description = "High RST ratio (" + fmt(rst_ratio * 100, 1) + "%) -- possible scan activity";
                findings.push_back(std::move(f));
            }
        }

        return findings;
    }

private:
    mutable std::mutex mutex_;
    std::map<int32_t, ConnStats> stats_;

    static int64_t current_ms() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }

    static std::string fmt(double v, int prec) {
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(prec) << v;
        return oss.str();
    }
};

// =============================================================================
// PAYLOAD ENTROPY ANALYZER -- Detect encrypted/encoded C2 traffic
// =============================================================================
class EntropyAnalyzer {
public:
    // Analyze a data chunk (e.g., POST body, suspicious payload from logs)
    NetworkFinding analyze_payload(const std::string& data, int32_t device_id,
                                    const std::string& ip) const
    {
        NetworkFinding f;
        if (data.size() < 32) return f; // Too small

        double entropy = byte_entropy(data);
        f.device_id = device_id; f.machine_ip = ip;
        f.timestamp_ms = current_ms();

        // High entropy (>7.0 for 8-bit) suggests encryption/compression
        if (entropy > 7.2 && data.size() > 128) {
            f.category = "entropy"; f.severity = "high";
            f.mitre_id = "T1573.001"; f.confidence = std::min(1.0, (entropy - 6.5) * 0.5);
            f.description = "High payload entropy (" + fmt(entropy, 2)
                + " bits/byte, " + std::to_string(data.size())
                + " bytes) -- possible encrypted C2 channel";
        } else if (entropy > 6.5 && data.size() > 256) {
            f.category = "entropy"; f.severity = "medium";
            f.mitre_id = "T1132"; f.confidence = std::min(1.0, (entropy - 6.0) * 0.3);
            f.description = "Elevated payload entropy (" + fmt(entropy, 2)
                + " bits/byte) -- possible data encoding";
        }

        return f;
    }

    // Scan log text for base64 blobs and check entropy
    std::vector<NetworkFinding> scan_log_chunk(const std::string& log,
                                                int32_t device_id,
                                                const std::string& ip) const
    {
        std::vector<NetworkFinding> findings;

        // Find long base64-like strings
        static const std::regex b64_rx(
            R"([A-Za-z0-9+/]{64,}={0,2})",
            std::regex_constants::optimize);
        std::sregex_iterator it(log.begin(), log.end(), b64_rx);
        std::sregex_iterator end;

        for (; it != end; ++it) {
            std::string blob = (*it)[0].str();
            auto f = analyze_payload(blob, device_id, ip);
            if (!f.category.empty()) {
                f.indicator = blob.substr(0, 40) + "...";
                f.raw_evidence = blob.substr(0, 80);
                findings.push_back(std::move(f));
            }
        }
        return findings;
    }

private:
    static double byte_entropy(const std::string& data) {
        if (data.empty()) return 0.0;
        int freq[256] = {};
        for (unsigned char c : data) freq[c]++;
        double ent = 0.0;
        double n = static_cast<double>(data.size());
        for (int i = 0; i < 256; i++) {
            if (freq[i] == 0) continue;
            double p = freq[i] / n;
            ent -= p * std::log2(p);
        }
        return ent;
    }

    static int64_t current_ms() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }

    static std::string fmt(double v, int prec) {
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(prec) << v;
        return oss.str();
    }
};

// =============================================================================
// NETWORK INSPECTOR -- Unified facade for all deep inspection analyzers
// =============================================================================
class NetworkInspector {
public:
    struct InspectorConfig {
        bool dns_enabled      = true;
        bool protocol_enabled = true;
        bool connection_enabled = true;
        bool entropy_enabled  = true;
    };

    explicit NetworkInspector(const InspectorConfig& cfg) : config_(cfg) {}

    // Full inspection of a log chunk -- runs all enabled analyzers
    std::vector<NetworkFinding> inspect(const std::string& log_chunk,
                                         int32_t device_id,
                                         const std::string& machine_ip)
    {
        std::vector<NetworkFinding> all;

        if (config_.dns_enabled) {
            auto f = dns_.analyze_log_chunk(log_chunk, device_id, machine_ip);
            all.insert(all.end(), f.begin(), f.end());
        }

        if (config_.protocol_enabled) {
            auto f = proto_.analyze_log_chunk(log_chunk, device_id, machine_ip);
            all.insert(all.end(), f.begin(), f.end());
        }

        if (config_.entropy_enabled) {
            auto f = entropy_.scan_log_chunk(log_chunk, device_id, machine_ip);
            all.insert(all.end(), f.begin(), f.end());
        }

        total_findings_ += all.size();
        total_inspections_++;
        return all;
    }

    // Update connection tracker (called from telemetry)
    void update_connections(int32_t device_id, uint64_t connections,
                             uint64_t resets, uint64_t refused, int64_t ts_ms)
    {
        if (config_.connection_enabled)
            conn_.update(device_id, connections, resets, refused, ts_ms);
    }

    // Check connection anomalies for a device
    std::vector<NetworkFinding> check_connections(int32_t device_id,
                                                    const std::string& ip) const
    {
        if (!config_.connection_enabled) return {};
        return conn_.check_anomalies(device_id, ip);
    }

    // --- Diagnostics ---
    size_t total_findings() const     { return total_findings_.load(); }
    size_t total_inspections() const  { return total_inspections_.load(); }
    const InspectorConfig& config() const { return config_; }

private:
    InspectorConfig config_;
    DnsAnalyzer dns_;
    ProtocolAnalyzer proto_;
    ConnectionTracker conn_;
    EntropyAnalyzer entropy_;

    std::atomic<size_t> total_findings_{0};
    std::atomic<size_t> total_inspections_{0};
};

#endif
