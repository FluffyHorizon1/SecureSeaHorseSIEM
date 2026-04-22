#ifndef FLEET_MANAGER_H
#define FLEET_MANAGER_H

#ifndef NOMINMAX
#define NOMINMAX
#endif

// =============================================================================
// SecureSeaHorse SIEM -- Phase 9: Agent Fleet Management
// =============================================================================
// Provides:
//   - Device inventory: OS, hostname, IP, agent version, first/last seen
//   - Health scoring: connectivity freshness, telemetry rate, error state
//   - Device groups and tags for fleet organization
//   - Stale device detection (offline > threshold)
//   - JSON export for REST API integration
//   - Thread-safe: concurrent updates from telemetry handler
// =============================================================================

#include <string>
#include <vector>
#include <map>
#include <set>
#include <mutex>
#include <chrono>
#include <atomic>
#include <cstdint>
#include <sstream>
#include <algorithm>
#include <iomanip>

// =============================================================================
// DEVICE INFO -- Inventory record for a single agent
// =============================================================================
struct DeviceInfo {
    int32_t     device_id       = 0;
    std::string hostname;
    std::string machine_ip;
    std::string os_name;          // "Windows 10", "Ubuntu 24.04"
    std::string agent_version;    // "1.7.0"
    int64_t     first_seen_ms   = 0;
    int64_t     last_seen_ms    = 0;
    int64_t     last_telemetry_ms = 0;
    int64_t     last_heartbeat_ms = 0;
    int64_t     last_fim_scan_ms  = 0;
    uint64_t    total_reports   = 0;
    uint64_t    total_alerts    = 0;
    uint64_t    total_threats   = 0;
    uint64_t    total_ioc_hits  = 0;
    uint64_t    total_fim_changes = 0;

    // Tags/groups
    std::set<std::string> tags;       // "production","web-server","dc-east"
    std::string group;                // "servers","workstations","iot"

    // Health
    bool        quarantined     = false;
    std::string status;               // "online","stale","offline"
    double      health_score    = 1.0; // 0.0-1.0
};

// =============================================================================
// FLEET HEALTH THRESHOLDS
// =============================================================================
struct FleetConfig {
    int stale_threshold_s  = 300;   // Seconds before "stale" (5min)
    int offline_threshold_s = 900;  // Seconds before "offline" (15min)
    bool enabled = true;
};

// =============================================================================
// FLEET MANAGER
// =============================================================================
class FleetManager {
public:
    explicit FleetManager(const FleetConfig& cfg = {})
        : config_(cfg) {}

    // =========================================================================
    // UPDATE: Called on every telemetry report
    // =========================================================================
    void update_telemetry(int32_t device_id, const std::string& hostname,
                           const std::string& ip, const std::string& os_name,
                           int64_t timestamp_ms)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto now_ms = current_ms();

        auto& dev = devices_[device_id];
        if (dev.device_id == 0) {
            // New device
            dev.device_id = device_id;
            dev.first_seen_ms = now_ms;
            total_registered_++;
        }

        dev.hostname = hostname;
        dev.machine_ip = ip;
        if (!os_name.empty()) dev.os_name = os_name;
        dev.last_seen_ms = now_ms;
        dev.last_telemetry_ms = timestamp_ms;
        dev.total_reports++;

        update_health(dev, now_ms);
    }

    // =========================================================================
    // UPDATE: Heartbeat received
    // =========================================================================
    void update_heartbeat(int32_t device_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto now_ms = current_ms();
        auto it = devices_.find(device_id);
        if (it != devices_.end()) {
            it->second.last_heartbeat_ms = now_ms;
            it->second.last_seen_ms = now_ms;
            update_health(it->second, now_ms);
        }
    }

    // =========================================================================
    // UPDATE: FIM scan received
    // =========================================================================
    void update_fim(int32_t device_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = devices_.find(device_id);
        if (it != devices_.end()) {
            it->second.last_fim_scan_ms = current_ms();
        }
    }

    // =========================================================================
    // INCREMENT: Security counters
    // =========================================================================
    void increment_alerts(int32_t device_id, int count = 1) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = devices_.find(device_id);
        if (it != devices_.end()) it->second.total_alerts += count;
    }

    void increment_threats(int32_t device_id, int count = 1) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = devices_.find(device_id);
        if (it != devices_.end()) it->second.total_threats += count;
    }

    void increment_ioc_hits(int32_t device_id, int count = 1) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = devices_.find(device_id);
        if (it != devices_.end()) it->second.total_ioc_hits += count;
    }

    void increment_fim_changes(int32_t device_id, int count = 1) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = devices_.find(device_id);
        if (it != devices_.end()) it->second.total_fim_changes += count;
    }

    // =========================================================================
    // MANAGE: Tags and groups
    // =========================================================================
    void set_group(int32_t device_id, const std::string& group) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = devices_.find(device_id);
        if (it != devices_.end()) it->second.group = group;
    }

    void add_tag(int32_t device_id, const std::string& tag) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = devices_.find(device_id);
        if (it != devices_.end()) it->second.tags.insert(tag);
    }

    void remove_tag(int32_t device_id, const std::string& tag) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = devices_.find(device_id);
        if (it != devices_.end()) it->second.tags.erase(tag);
    }

    void set_quarantined(int32_t device_id, bool q) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = devices_.find(device_id);
        if (it != devices_.end()) it->second.quarantined = q;
    }

    void set_agent_version(int32_t device_id, const std::string& ver) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = devices_.find(device_id);
        if (it != devices_.end()) it->second.agent_version = ver;
    }

    // =========================================================================
    // QUERY: Get device info
    // =========================================================================
    DeviceInfo get_device(int32_t device_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = devices_.find(device_id);
        if (it != devices_.end()) return it->second;
        return {};
    }

    std::vector<DeviceInfo> get_all_devices() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<DeviceInfo> result;
        result.reserve(devices_.size());
        for (const auto& kv : devices_) result.push_back(kv.second);
        return result;
    }

    std::vector<DeviceInfo> get_devices_by_status(const std::string& status) const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<DeviceInfo> result;
        auto now_ms = current_ms();
        for (const auto& kv : devices_) {
            DeviceInfo d = kv.second;
            compute_status(d, now_ms);
            if (d.status == status) result.push_back(d);
        }
        return result;
    }

    std::vector<DeviceInfo> get_devices_by_group(const std::string& group) const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<DeviceInfo> result;
        for (const auto& kv : devices_) {
            if (kv.second.group == group) result.push_back(kv.second);
        }
        return result;
    }

    // =========================================================================
    // REFRESH: Update health status for all devices (call periodically)
    // =========================================================================
    void refresh_health() {
        std::lock_guard<std::mutex> lock(mutex_);
        auto now_ms = current_ms();
        for (auto& kv : devices_) {
            update_health(kv.second, now_ms);
        }
    }

    // =========================================================================
    // JSON EXPORT: For REST API
    // =========================================================================
    std::string to_json() const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto now_ms = current_ms();
        std::string json = "[";
        bool first = true;
        for (const auto& kv : devices_) {
            if (!first) json += ",";
            first = false;
            json += device_to_json(kv.second, now_ms);
        }
        json += "]";
        return json;
    }

    std::string device_to_json(int32_t device_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = devices_.find(device_id);
        if (it == devices_.end()) return "{}";
        return device_to_json(it->second, current_ms());
    }

    // =========================================================================
    // FLEET SUMMARY: For stats endpoint
    // =========================================================================
    struct FleetSummary {
        size_t total      = 0;
        size_t online     = 0;
        size_t stale      = 0;
        size_t offline    = 0;
        size_t quarantined = 0;
    };

    FleetSummary get_summary() const {
        std::lock_guard<std::mutex> lock(mutex_);
        FleetSummary s;
        auto now_ms = current_ms();
        s.total = devices_.size();
        for (const auto& kv : devices_) {
            DeviceInfo d = kv.second;
            compute_status(d, now_ms);
            if (d.quarantined) s.quarantined++;
            if (d.status == "online") s.online++;
            else if (d.status == "stale") s.stale++;
            else s.offline++;
        }
        return s;
    }

    // --- Diagnostics ---
    size_t total_devices() const     { std::lock_guard<std::mutex> lock(mutex_); return devices_.size(); }
    size_t total_registered() const  { return total_registered_.load(); }
    const FleetConfig& config() const { return config_; }

private:
    FleetConfig config_;
    mutable std::mutex mutex_;
    std::map<int32_t, DeviceInfo> devices_;
    std::atomic<size_t> total_registered_{0};

    static int64_t current_ms() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }

    void compute_status(DeviceInfo& dev, int64_t now_ms) const {
        if (dev.last_seen_ms == 0) { dev.status = "offline"; return; }
        int64_t age_s = (now_ms - dev.last_seen_ms) / 1000;
        if (age_s < config_.stale_threshold_s) dev.status = "online";
        else if (age_s < config_.offline_threshold_s) dev.status = "stale";
        else dev.status = "offline";
    }

    void update_health(DeviceInfo& dev, int64_t now_ms) {
        compute_status(dev, now_ms);
        // Health score: 1.0 = healthy, degrades with age
        double score = 1.0;
        if (dev.last_seen_ms > 0) {
            double age_s = static_cast<double>(now_ms - dev.last_seen_ms) / 1000.0;
            if (age_s > config_.stale_threshold_s)
                score -= 0.3;
            if (age_s > config_.offline_threshold_s)
                score -= 0.4;
        } else {
            score = 0.0;
        }
        if (dev.quarantined) score -= 0.2;
        if (dev.total_threats > 10) score -= 0.1;
        dev.health_score = std::max(0.0, std::min(1.0, score));
    }

    static std::string json_escape(const std::string& s) {
        std::string out;
        for (char c : s) {
            switch (c) {
                case '"':  out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\n': out += "\\n";  break;
                default:   out += c;
            }
        }
        return out;
    }

    std::string device_to_json(const DeviceInfo& d, int64_t now_ms) const {
        DeviceInfo dev = d;
        compute_status(dev, now_ms);
        std::ostringstream j;
        j << "{\"device_id\":" << dev.device_id
          << ",\"hostname\":\"" << json_escape(dev.hostname) << "\""
          << ",\"machine_ip\":\"" << json_escape(dev.machine_ip) << "\""
          << ",\"os_name\":\"" << json_escape(dev.os_name) << "\""
          << ",\"agent_version\":\"" << json_escape(dev.agent_version) << "\""
          << ",\"status\":\"" << dev.status << "\""
          << ",\"health_score\":" << std::fixed << std::setprecision(2) << dev.health_score
          << ",\"quarantined\":" << (dev.quarantined ? "true" : "false")
          << ",\"group\":\"" << json_escape(dev.group) << "\""
          << ",\"first_seen_ms\":" << dev.first_seen_ms
          << ",\"last_seen_ms\":" << dev.last_seen_ms
          << ",\"last_telemetry_ms\":" << dev.last_telemetry_ms
          << ",\"last_heartbeat_ms\":" << dev.last_heartbeat_ms
          << ",\"last_fim_scan_ms\":" << dev.last_fim_scan_ms
          << ",\"total_reports\":" << dev.total_reports
          << ",\"total_alerts\":" << dev.total_alerts
          << ",\"total_threats\":" << dev.total_threats
          << ",\"total_ioc_hits\":" << dev.total_ioc_hits
          << ",\"total_fim_changes\":" << dev.total_fim_changes
          << ",\"tags\":[";
        bool first = true;
        for (const auto& tag : dev.tags) {
            if (!first) j << ",";
            first = false;
            j << "\"" << json_escape(tag) << "\"";
        }
        j << "]}";
        return j.str();
    }
};

#endif
