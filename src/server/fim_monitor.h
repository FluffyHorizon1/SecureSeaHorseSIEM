#ifndef FIM_MONITOR_H
#define FIM_MONITOR_H

#ifndef NOMINMAX
#define NOMINMAX
#endif

// =============================================================================
// SecureSeaHorse SIEM — Phase 6: Server-Side FIM Monitor
// =============================================================================
// Provides:
//   - Per-device baseline storage for file hashes
//   - Change detection: additions, modifications, deletions
//   - Severity classification based on file path criticality
//   - MITRE ATT&CK tagging for FIM changes
//   - Thread-safe: per-device mutexes
// =============================================================================

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <algorithm>
#include <atomic>
#include <cstdint>
#include <regex>

#include "fim_common.h"
#include "fim_scanner.h"   // For FimScanner::diff()

// =============================================================================
// FIM ALERT — Detection output
// =============================================================================
struct FimAlert {
    int32_t     device_id;
    int64_t     timestamp_ms;
    std::string machine_ip;
    FimChangeType change_type;
    std::string path;
    std::string old_hash;
    std::string new_hash;
    uint64_t    old_size;
    uint64_t    new_size;
    std::string severity;       // "low", "medium", "high", "critical"
    std::string mitre_id;
    std::string mitre_tactic;
    std::string description;
};

// =============================================================================
// FIM MONITOR CONFIG
// =============================================================================
struct FimMonitorConfig {
    bool enabled = true;

    // Critical paths — changes to these are always "critical" severity
    std::vector<std::string> critical_paths;

    // High-priority paths — "high" severity
    std::vector<std::string> high_paths;

    // Default severity for changes not matching critical/high paths
    std::string default_severity = "medium";
};

// =============================================================================
// FIM MONITOR
// =============================================================================
class FimMonitor {
public:
    explicit FimMonitor(const FimMonitorConfig& cfg = {})
        : config_(cfg)
    {
        init_default_paths();
    }

    // =========================================================================
    // PROCESS: Receive a FIM report and detect changes
    // =========================================================================
    std::vector<FimAlert> process(const FimReport& report,
                                   const std::string& machine_ip)
    {
        std::vector<FimAlert> alerts;
        int32_t dev = report.device_id;

        // Get or create device baseline
        std::unique_lock<std::mutex> global_lock(registry_mutex_);
        auto& device = baselines_[dev];
        global_lock.unlock();

        std::lock_guard<std::mutex> dev_lock(device.mutex);

        if (!device.has_baseline) {
            // First report — establish baseline, no alerts
            device.entries = report.entries;
            device.has_baseline = true;
            device.last_scan_ms = report.timestamp_ms;
            total_baselined_++;
            return alerts;
        }

        // Compute diff against stored baseline
        std::vector<FimChange> changes = FimScanner::diff(device.entries, report.entries);

        // Generate alerts for each change
        for (const auto& change : changes) {
            FimAlert alert;
            alert.device_id    = dev;
            alert.timestamp_ms = report.timestamp_ms;
            alert.machine_ip   = machine_ip;
            alert.change_type  = change.type;
            alert.path         = change.path;
            alert.old_hash     = change.old_hash;
            alert.new_hash     = change.new_hash;
            alert.old_size     = change.old_size;
            alert.new_size     = change.new_size;

            // Classify severity based on path
            alert.severity = classify_severity(change.path);

            // MITRE ATT&CK mapping
            assign_mitre(alert);

            // Human-readable description
            alert.description = build_description(alert);

            alerts.push_back(std::move(alert));
            total_alerts_++;
        }

        // Update baseline to current scan
        device.entries = report.entries;
        device.last_scan_ms = report.timestamp_ms;
        total_changes_ += static_cast<int>(changes.size());

        return alerts;
    }

    // --- Diagnostics ---
    size_t baselined_devices() const { return total_baselined_.load(); }
    size_t total_changes() const     { return total_changes_.load(); }
    size_t total_alerts() const      { return total_alerts_.load(); }

    const FimMonitorConfig& config() const { return config_; }

private:
    FimMonitorConfig config_;
    std::mutex registry_mutex_;

    struct DeviceBaseline {
        std::mutex mutex;
        std::vector<FimEntry> entries;
        bool has_baseline = false;
        int64_t last_scan_ms = 0;
    };

    std::map<int32_t, DeviceBaseline> baselines_;

    std::atomic<size_t> total_baselined_{0};
    std::atomic<size_t> total_changes_{0};
    std::atomic<size_t> total_alerts_{0};

    // Compiled critical/high path patterns
    std::vector<std::regex> critical_patterns_;
    std::vector<std::regex> high_patterns_;

    void init_default_paths() {
        auto compile = [](const std::string& pattern) -> std::regex {
            try {
                return std::regex(pattern,
                    std::regex_constants::icase | std::regex_constants::optimize);
            } catch (...) {
                return std::regex("(?!)");
            }
        };

        // Built-in critical patterns (OS core, auth, boot)
        std::vector<std::string> default_critical = {
            // Linux
            R"(/etc/passwd)", R"(/etc/shadow)", R"(/etc/sudoers)",
            R"(/etc/ssh/sshd_config)", R"(/etc/pam\.d/)",
            R"(/boot/)", R"(/usr/sbin/)",
            R"(/etc/crontab)", R"(/etc/cron\.d/)",
            // Windows
            R"(system32\\config\\)", R"(system32\\drivers\\)",
            R"(\\windows\\system32\\)", R"(\\windows\\syswow64\\)",
            R"(\\boot\\bcd)", R"(boot\.ini)",
        };

        // Built-in high patterns (config, services, web roots)
        std::vector<std::string> default_high = {
            // Linux
            R"(/etc/nginx/)", R"(/etc/apache2/)", R"(/etc/httpd/)",
            R"(/etc/systemd/)", R"(/usr/lib/systemd/)",
            R"(/var/www/)", R"(/opt/)",
            R"(/etc/hosts)", R"(/etc/resolv\.conf)",
            // Windows
            R"(\\inetpub\\)", R"(\\program files\\)",
            R"(\\programdata\\)", R"(\\users\\.*\\appdata\\roaming\\)",
        };

        // Merge user-configured paths with defaults
        for (const auto& p : default_critical)       critical_patterns_.push_back(compile(p));
        for (const auto& p : config_.critical_paths)  critical_patterns_.push_back(compile(p));
        for (const auto& p : default_high)            high_patterns_.push_back(compile(p));
        for (const auto& p : config_.high_paths)      high_patterns_.push_back(compile(p));
    }

    std::string classify_severity(const std::string& path) const {
        std::string lower = path;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

        for (const auto& pat : critical_patterns_) {
            if (std::regex_search(lower, pat)) return "critical";
        }
        for (const auto& pat : high_patterns_) {
            if (std::regex_search(lower, pat)) return "high";
        }
        return config_.default_severity;
    }

    void assign_mitre(FimAlert& alert) const {
        switch (alert.change_type) {
            case FimChangeType::FIM_ADDED:
                if (alert.severity == "critical") {
                    alert.mitre_id    = "T1505.003";
                    alert.mitre_tactic = "Persistence";
                } else {
                    alert.mitre_id    = "T1074";
                    alert.mitre_tactic = "Collection";
                }
                break;

            case FimChangeType::FIM_MODIFIED:
                // Modification of system files = indicator of tampering
                if (alert.severity == "critical") {
                    alert.mitre_id    = "T1565.001";
                    alert.mitre_tactic = "Impact";
                } else {
                    alert.mitre_id    = "T1027";
                    alert.mitre_tactic = "Defense Evasion";
                }
                break;

            case FimChangeType::FIM_DELETED:
                alert.mitre_id    = "T1070.004";
                alert.mitre_tactic = "Defense Evasion";
                break;
        }
    }

    std::string build_description(const FimAlert& alert) const {
        std::string change_str = fim_change_str(alert.change_type);
        std::string desc = "File " + change_str + ": " + alert.path;

        if (alert.change_type == FimChangeType::FIM_MODIFIED) {
            desc += " (hash changed, size "
                + std::to_string(alert.old_size) + " -> "
                + std::to_string(alert.new_size) + ")";
        } else if (alert.change_type == FimChangeType::FIM_ADDED) {
            desc += " (new file, " + std::to_string(alert.new_size) + " bytes)";
        } else if (alert.change_type == FimChangeType::FIM_DELETED) {
            desc += " (was " + std::to_string(alert.old_size) + " bytes)";
        }

        return desc;
    }
};

#endif
