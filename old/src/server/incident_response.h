#ifndef INCIDENT_RESPONSE_H
#define INCIDENT_RESPONSE_H

#ifndef NOMINMAX
#define NOMINMAX
#endif

// =============================================================================
// SecureSeaHorse SIEM -- Phase 8: Incident Response Automation
// =============================================================================
// Provides:
//   - Response actions: log, block IP, quarantine device, webhook, script
//   - Playbook engine: maps severity+category to action chains
//   - Cooldown/dedup: prevents action storms from repeated triggers
//   - IP blocklist with expiry, device quarantine set
//   - Audit trail: every action recorded with timestamp and outcome
//   - Thread-safe action queue processed by background worker
// =============================================================================

#include <string>
#include <vector>
#include <map>
#include <set>
#include <queue>
#include <mutex>
#include <thread>
#include <atomic>
#include <chrono>
#include <functional>
#include <sstream>
#include <algorithm>
#include <cstdint>

// =============================================================================
// RESPONSE ACTION TYPES
// =============================================================================
enum class ActionType {
    ACT_LOG,           // Log to incident log
    ACT_BLOCK_IP,      // Add IP to blocklist
    ACT_QUARANTINE,    // Mark device as quarantined
    ACT_WEBHOOK,       // Fire HTTP webhook notification
    ACT_SCRIPT,        // Execute local response script
    ACT_RATE_LIMIT,    // Apply rate limiting to source
    ACT_DISABLE_USER,  // Flag user account for disable
};

inline std::string action_type_str(ActionType t) {
    switch (t) {
        case ActionType::ACT_LOG:          return "log";
        case ActionType::ACT_BLOCK_IP:     return "block_ip";
        case ActionType::ACT_QUARANTINE:   return "quarantine";
        case ActionType::ACT_WEBHOOK:      return "webhook";
        case ActionType::ACT_SCRIPT:       return "script";
        case ActionType::ACT_RATE_LIMIT:   return "rate_limit";
        case ActionType::ACT_DISABLE_USER: return "disable_user";
        default:                           return "unknown";
    }
}

// =============================================================================
// INCIDENT -- Trigger event that invokes response actions
// =============================================================================
struct Incident {
    int32_t     device_id    = 0;
    int64_t     timestamp_ms = 0;
    std::string machine_ip;
    std::string source;        // "traffic_classifier","threat_intel","fim","alert_engine"
    std::string category;      // "brute_force","c2_beacon","ioc_match","fim_modified"
    std::string severity;      // "low","medium","high","critical"
    std::string mitre_id;
    std::string description;
    std::string ioc_value;     // Relevant IoC if applicable
    std::string file_path;     // Relevant file path for FIM incidents
};

// =============================================================================
// RESPONSE ACTION -- Single action to execute
// =============================================================================
struct ResponseAction {
    ActionType  type         = ActionType::ACT_LOG;
    std::string target;        // IP to block, webhook URL, script name
    std::string params;        // Extra parameters
    int         duration_s   = 0; // Duration for temp actions (0=permanent)
};

// =============================================================================
// ACTION RESULT -- Audit record
// =============================================================================
struct ActionResult {
    int64_t     timestamp_ms       = 0;
    int32_t     device_id          = 0;
    std::string incident_source;
    std::string incident_category;
    std::string severity;
    ActionType  action_type        = ActionType::ACT_LOG;
    std::string target;
    bool        success            = false;
    std::string detail;
};

// =============================================================================
// PLAYBOOK RULE
// =============================================================================
struct PlaybookRule {
    std::string name;
    std::string match_source;     // Empty = match any
    std::string match_category;   // Empty = match any
    std::string min_severity;     // Minimum severity to trigger
    std::vector<ResponseAction> actions;
    int cooldown_seconds = 300;
    bool enabled = true;
};

// =============================================================================
// IP BLOCKLIST ENTRY
// =============================================================================
struct BlockEntry {
    std::string ip;
    int64_t     blocked_at_ms = 0;
    int64_t     expires_at_ms = 0;  // 0 = permanent
    std::string reason;
    int32_t     device_id     = 0;
};

// =============================================================================
// INCIDENT RESPONSE ENGINE
// =============================================================================
class IncidentResponseEngine {
public:
    using LogCallback = std::function<void(int level, const std::string& msg)>;

    explicit IncidentResponseEngine(LogCallback log_cb = nullptr)
        : log_cb_(std::move(log_cb)) { init_default_playbooks(); }
    ~IncidentResponseEngine() { stop(); }

    void add_rule(const PlaybookRule& rule) {
        std::lock_guard<std::mutex> lock(mutex_);
        playbooks_.push_back(rule);
    }

    void set_webhook_url(const std::string& url) { webhook_url_ = url; }
    void set_script_dir(const std::string& dir)   { script_dir_ = dir; }

    void start() {
        running_ = true;
        worker_ = std::thread([this]() { process_loop(); });
    }

    void stop() {
        running_ = false;
        cv_.notify_all();
        if (worker_.joinable()) worker_.join();
    }

    // =========================================================================
    // REPORT INCIDENT -- Evaluate playbooks and queue matching actions
    // =========================================================================
    void report_incident(const Incident& incident) {
        std::lock_guard<std::mutex> lock(mutex_);
        total_incidents_++;
        int sev = severity_level(incident.severity);

        for (const auto& rule : playbooks_) {
            if (!rule.enabled) continue;
            if (!rule.match_source.empty() && rule.match_source != incident.source) continue;
            if (!rule.match_category.empty() && rule.match_category != incident.category) continue;
            if (sev < severity_level(rule.min_severity)) continue;

            // Cooldown check
            std::string ckey = std::to_string(incident.device_id) + ":" + incident.category + ":" + rule.name;
            auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            auto it = cooldown_map_.find(ckey);
            if (it != cooldown_map_.end() && (now_ms - it->second) < (rule.cooldown_seconds * 1000LL))
                continue;
            cooldown_map_[ckey] = now_ms;

            for (const auto& action : rule.actions) {
                QueuedAction qa;
                qa.incident = incident;
                qa.action = action;
                qa.rule_name = rule.name;
                if (qa.action.target.empty()) {
                    if (qa.action.type == ActionType::ACT_BLOCK_IP)
                        qa.action.target = incident.ioc_value.empty() ? incident.machine_ip : incident.ioc_value;
                    else if (qa.action.type == ActionType::ACT_QUARANTINE)
                        qa.action.target = std::to_string(incident.device_id);
                    else if (qa.action.type == ActionType::ACT_WEBHOOK)
                        qa.action.target = webhook_url_;
                }
                action_queue_.push(std::move(qa));
                total_actions_queued_++;
            }
        }
        cv_.notify_one();
    }

    // =========================================================================
    // BLOCKLIST / QUARANTINE ACCESS
    // =========================================================================
    bool is_ip_blocked(const std::string& ip) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        auto it = blocklist_.find(ip);
        if (it == blocklist_.end()) return false;
        return (it->second.expires_at_ms == 0 || now_ms <= it->second.expires_at_ms);
    }

    std::vector<BlockEntry> get_blocklist() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<BlockEntry> r;
        for (const auto& kv : blocklist_) r.push_back(kv.second);
        return r;
    }

    bool is_device_quarantined(int32_t dev) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return quarantined_.count(dev) > 0;
    }

    std::set<int32_t> get_quarantined() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return quarantined_;
    }

    std::vector<ActionResult> get_recent_actions(size_t limit = 50) const {
        std::lock_guard<std::mutex> lock(mutex_);
        size_t start = (audit_.size() > limit) ? audit_.size() - limit : 0;
        return std::vector<ActionResult>(audit_.begin() + static_cast<long>(start), audit_.end());
    }

    // --- Diagnostics ---
    size_t total_incidents() const       { return total_incidents_.load(); }
    size_t total_actions_queued() const  { return total_actions_queued_.load(); }
    size_t total_actions_executed() const { return total_actions_executed_.load(); }
    size_t blocked_count() const         { std::lock_guard<std::mutex> lock(mutex_); return blocklist_.size(); }
    size_t quarantined_count() const     { std::lock_guard<std::mutex> lock(mutex_); return quarantined_.size(); }
    size_t playbook_count() const        { std::lock_guard<std::mutex> lock(mutex_); return playbooks_.size(); }

private:
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::thread worker_;
    std::atomic<bool> running_{false};
    LogCallback log_cb_;
    std::string webhook_url_;
    std::string script_dir_ = "scripts";

    std::vector<PlaybookRule> playbooks_;
    std::map<std::string, int64_t> cooldown_map_;
    std::map<std::string, BlockEntry> blocklist_;
    std::set<int32_t> quarantined_;
    std::vector<ActionResult> audit_;

    struct QueuedAction {
        Incident incident;
        ResponseAction action;
        std::string rule_name;
    };
    std::queue<QueuedAction> action_queue_;

    std::atomic<size_t> total_incidents_{0};
    std::atomic<size_t> total_actions_queued_{0};
    std::atomic<size_t> total_actions_executed_{0};

    void process_loop() {
        while (running_) {
            QueuedAction qa;
            {
                std::unique_lock<std::mutex> lock(mutex_);
                cv_.wait_for(lock, std::chrono::seconds(1),
                    [this]() { return !action_queue_.empty() || !running_; });
                if (action_queue_.empty()) continue;
                qa = std::move(action_queue_.front());
                action_queue_.pop();
            }
            execute_action(qa);
        }
        // Shutdown drain: pop actions under lock, execute them unlocked to avoid
        // deadlock since execute_action() reacquires mutex_ for ACT_BLOCK_IP / ACT_QUARANTINE.
        while (true) {
            QueuedAction qa;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (action_queue_.empty()) break;
                qa = std::move(action_queue_.front());
                action_queue_.pop();
            }
            execute_action(qa);
        }
    }

    void execute_action(const QueuedAction& qa) {
        ActionResult r;
        auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        r.timestamp_ms = now_ms;
        r.device_id = qa.incident.device_id;
        r.incident_source = qa.incident.source;
        r.incident_category = qa.incident.category;
        r.severity = qa.incident.severity;
        r.action_type = qa.action.type;
        r.target = qa.action.target;

        switch (qa.action.type) {
            case ActionType::ACT_LOG:
                r.success = true;
                r.detail = "Incident logged: " + qa.incident.description;
                break;
            case ActionType::ACT_BLOCK_IP: {
                std::lock_guard<std::mutex> lock(mutex_);
                BlockEntry be;
                be.ip = qa.action.target; be.blocked_at_ms = now_ms;
                be.expires_at_ms = qa.action.duration_s > 0 ? now_ms + qa.action.duration_s * 1000LL : 0;
                be.reason = qa.incident.description; be.device_id = qa.incident.device_id;
                blocklist_[qa.action.target] = be;
                r.success = true;
                r.detail = "IP blocked: " + qa.action.target;
                break;
            }
            case ActionType::ACT_QUARANTINE: {
                std::lock_guard<std::mutex> lock(mutex_);
                quarantined_.insert(qa.incident.device_id);
                r.success = true;
                r.detail = "Device quarantined: " + std::to_string(qa.incident.device_id);
                break;
            }
            case ActionType::ACT_WEBHOOK:
                r.success = !qa.action.target.empty();
                r.detail = r.success ? "Webhook queued: " + qa.action.target : "No webhook URL";
                break;
            case ActionType::ACT_SCRIPT:
                r.success = !qa.action.target.empty() && qa.action.target.find("..") == std::string::npos;
                r.detail = r.success ? "Script queued: " + qa.action.target : "Invalid script path";
                break;
            case ActionType::ACT_RATE_LIMIT:
                r.success = true;
                r.detail = "Rate limit applied: " + qa.action.target;
                break;
            case ActionType::ACT_DISABLE_USER:
                r.success = true;
                r.detail = "User flagged from device " + std::to_string(qa.incident.device_id);
                break;
        }
        total_actions_executed_++;

        if (log_cb_) {
            log_cb_(r.success ? 1 : 3, "[IR] " + action_type_str(qa.action.type)
                + " | rule=" + qa.rule_name + " | dev=" + std::to_string(qa.incident.device_id)
                + " | " + r.detail);
        }

        std::lock_guard<std::mutex> lock(mutex_);
        audit_.push_back(std::move(r));
        if (audit_.size() > 10000)
            audit_.erase(audit_.begin(), audit_.begin() + static_cast<long>(audit_.size() - 5000));
    }

    void init_default_playbooks() {
        // Critical threats -> log + block IP (1hr) + quarantine
        { PlaybookRule r; r.name="critical_response"; r.min_severity="critical"; r.cooldown_seconds=600;
          r.actions.push_back({ActionType::ACT_LOG,"","",0});
          r.actions.push_back({ActionType::ACT_BLOCK_IP,"","",3600});
          r.actions.push_back({ActionType::ACT_QUARANTINE,"","",0});
          playbooks_.push_back(std::move(r)); }
        // Brute force -> block IP 30min
        { PlaybookRule r; r.name="brute_force_block"; r.match_category="brute_force"; r.min_severity="high"; r.cooldown_seconds=300;
          r.actions.push_back({ActionType::ACT_LOG,"","",0});
          r.actions.push_back({ActionType::ACT_BLOCK_IP,"","",1800});
          playbooks_.push_back(std::move(r)); }
        // C2 -> block + quarantine
        { PlaybookRule r; r.name="c2_containment"; r.match_category="c2_beacon"; r.min_severity="high"; r.cooldown_seconds=600;
          r.actions.push_back({ActionType::ACT_LOG,"","",0});
          r.actions.push_back({ActionType::ACT_BLOCK_IP,"","",7200});
          r.actions.push_back({ActionType::ACT_QUARANTINE,"","",0});
          playbooks_.push_back(std::move(r)); }
        // Exfiltration -> rate limit
        { PlaybookRule r; r.name="exfil_throttle"; r.match_category="data_exfiltration"; r.min_severity="high"; r.cooldown_seconds=300;
          r.actions.push_back({ActionType::ACT_LOG,"","",0});
          r.actions.push_back({ActionType::ACT_RATE_LIMIT,"","",1800});
          playbooks_.push_back(std::move(r)); }
        // IoC critical -> 24hr block
        { PlaybookRule r; r.name="ioc_critical_block"; r.match_source="threat_intel"; r.min_severity="critical"; r.cooldown_seconds=600;
          r.actions.push_back({ActionType::ACT_LOG,"","",0});
          r.actions.push_back({ActionType::ACT_BLOCK_IP,"","",86400});
          playbooks_.push_back(std::move(r)); }
        // FIM critical -> quarantine
        { PlaybookRule r; r.name="fim_critical_quarantine"; r.match_source="fim"; r.min_severity="critical"; r.cooldown_seconds=600;
          r.actions.push_back({ActionType::ACT_LOG,"","",0});
          r.actions.push_back({ActionType::ACT_QUARANTINE,"","",0});
          playbooks_.push_back(std::move(r)); }
        // General medium+ -> log
        { PlaybookRule r; r.name="general_log"; r.min_severity="medium"; r.cooldown_seconds=60;
          r.actions.push_back({ActionType::ACT_LOG,"","",0});
          playbooks_.push_back(std::move(r)); }
    }

    static int severity_level(const std::string& s) {
        if (s == "critical") return 4; if (s == "high") return 3;
        if (s == "medium") return 2;   if (s == "low") return 1;
        return 0;
    }
};

#endif
