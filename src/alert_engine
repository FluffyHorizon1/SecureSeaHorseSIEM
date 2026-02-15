#ifndef ALERT_ENGINE_H
#define ALERT_ENGINE_H

// =============================================================================
// SecureSeaHorse SIEM — Phase 2: Log-Based Threshold Alerting Engine
// =============================================================================
// Provides:
//   - Per-device, per-category event counting within a sliding time window
//   - Configurable thresholds per event category (from server.conf)
//   - Alerts written to a dedicated alert log file (separate from main log)
//   - Cooldown period to prevent alert floods
//   - Thread-safe: all state guarded by mutex
// =============================================================================

#include <string>
#include <map>
#include <vector>
#include <deque>
#include <mutex>
#include <chrono>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <atomic>

// Forward declaration
struct SecurityEvent;

// =============================================================================
// ALERT CONFIG — Per-category thresholds
// =============================================================================
struct AlertThreshold {
    std::string category;    // Matches SecurityEvent.category
    int         count;       // Number of events to trigger
    int         window_sec;  // Time window in seconds
    int         cooldown_sec;// Minimum seconds between alerts for same device+category
};

struct AlertConfig {
    std::string alert_log_path = "alerts.log";
    bool        enabled = true;

    // Default thresholds — can be overridden from server.conf
    std::vector<AlertThreshold> thresholds;

    // Load defaults
    void load_defaults() {
        // auth_failure:      5 events in 300s (5 min), 600s cooldown
        thresholds.push_back({ "auth_failure",         5, 300, 600 });
        // brute_force:       3 events in 60s, 300s cooldown
        thresholds.push_back({ "brute_force",          3,  60, 300 });
        // privilege_escalation: 2 events in 120s, 600s cooldown
        thresholds.push_back({ "privilege_escalation", 2, 120, 600 });
        // account_lockout:   1 event in 60s, 900s cooldown
        thresholds.push_back({ "account_lockout",      1,  60, 900 });
        // resource_exhaustion: 1 event in 60s, 600s cooldown
        thresholds.push_back({ "resource_exhaustion",  1,  60, 600 });
        // crash:             2 events in 300s, 600s cooldown
        thresholds.push_back({ "crash",                2, 300, 600 });
    }
};

// =============================================================================
// ALERT ENGINE
// =============================================================================
class AlertEngine {
public:
    explicit AlertEngine(const AlertConfig& cfg)
        : config_(cfg), total_alerts_fired_(0)
    {
        if (config_.enabled && !config_.alert_log_path.empty()) {
            alert_file_.open(config_.alert_log_path, std::ios::app);
            if (!alert_file_.is_open()) {
                // Fall back to stderr
                std::cerr << "[AlertEngine] Cannot open alert log: "
                    << config_.alert_log_path << "\n";
            }
        }
    }

    ~AlertEngine() {
        if (alert_file_.is_open()) {
            alert_file_.close();
        }
    }

    // Non-copyable
    AlertEngine(const AlertEngine&) = delete;
    AlertEngine& operator=(const AlertEngine&) = delete;

    // -------------------------------------------------------------------------
    // INGEST: Feed security events from the regex engine
    // Call this for each batch of events from a single telemetry report.
    // -------------------------------------------------------------------------
    void ingest(int32_t device_id, const std::string& machine_ip,
        const std::vector<SecurityEvent>& events)
    {
        if (!config_.enabled || events.empty()) return;

        auto now = std::chrono::steady_clock::now();

        std::lock_guard<std::mutex> lock(state_mutex_);

        for (const auto& ev : events) {
            // Record the event timestamp for this device+category
            DeviceCategoryKey key{ device_id, ev.category };
            event_history_[key].push_back(now);

            // Check if any threshold is breached
            for (const auto& thresh : config_.thresholds) {
                if (thresh.category != ev.category) continue;

                // Prune old events outside the window
                auto& history = event_history_[key];
                auto cutoff = now - std::chrono::seconds(thresh.window_sec);
                while (!history.empty() && history.front() < cutoff) {
                    history.pop_front();
                }

                // Check threshold
                if (static_cast<int>(history.size()) >= thresh.count) {
                    // Check cooldown
                    auto cooldown_it = last_alert_time_.find(key);
                    if (cooldown_it != last_alert_time_.end()) {
                        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                            now - cooldown_it->second).count();
                        if (elapsed < thresh.cooldown_sec) {
                            continue; // Still in cooldown
                        }
                    }

                    // FIRE ALERT
                    fire_alert(device_id, machine_ip, ev, thresh,
                        static_cast<int>(history.size()));
                    last_alert_time_[key] = now;

                    // Clear the window to prevent immediate re-fire
                    history.clear();
                }
            }
        }
    }

    // --- Diagnostics ---
    size_t total_alerts_fired() const { return total_alerts_fired_.load(); }

private:
    AlertConfig config_;

    // Per-device, per-category event timestamps
    struct DeviceCategoryKey {
        int32_t     device_id;
        std::string category;

        bool operator<(const DeviceCategoryKey& o) const {
            if (device_id != o.device_id) return device_id < o.device_id;
            return category < o.category;
        }
    };

    using TimePoint = std::chrono::steady_clock::time_point;

    std::mutex state_mutex_;
    std::map<DeviceCategoryKey, std::deque<TimePoint>> event_history_;
    std::map<DeviceCategoryKey, TimePoint>             last_alert_time_;

    std::ofstream alert_file_;
    std::atomic<size_t> total_alerts_fired_;

    // -------------------------------------------------------------------------
    // FIRE: Write alert to the alert log
    // -------------------------------------------------------------------------
    void fire_alert(int32_t device_id, const std::string& machine_ip,
        const SecurityEvent& trigger_event,
        const AlertThreshold& threshold, int event_count)
    {
        total_alerts_fired_++;

        // Build alert message
        auto wall_now = std::chrono::system_clock::now();
        std::time_t t = std::chrono::system_clock::to_time_t(wall_now);

        std::stringstream ss;
        ss << "[" << std::put_time(std::localtime(&t), "%Y-%m-%d %H:%M:%S") << "] "
            << "[ALERT] "
            << "device=" << device_id
            << " ip=" << machine_ip
            << " category=" << trigger_event.category
            << " severity=" << trigger_event.severity
            << " rule=" << trigger_event.rule_name
            << " count=" << event_count
            << "/" << threshold.count
            << " window=" << threshold.window_sec << "s"
            << " | " << trigger_event.matched_text;

        std::string alert_line = ss.str();

        // Write to alert log file
        if (alert_file_.is_open()) {
            alert_file_ << alert_line << "\n";
            alert_file_.flush();
        }

        // Also echo to stderr for operator visibility
        std::cerr << "\033[1;31m" << alert_line << "\033[0m\n";
    }
};

#endif
#pragma once
