#ifndef CORRELATION_ENGINE_H
#define CORRELATION_ENGINE_H

#ifndef NOMINMAX
#define NOMINMAX
#endif

// =============================================================================
// SecureSeaHorse SIEM -- Phase 15: Correlation Engine (Server-Side)
// =============================================================================
// Provides:
//   - Cross-device event correlation: link related events into incidents
//   - Kill-chain reconstruction: detect multi-stage attack sequences
//   - Sliding time-window analysis for temporal patterns
//   - Correlation rules: customizable detection patterns
//   - Thread-safe: concurrent event ingestion from multiple devices
// =============================================================================

#include <string>
#include <vector>
#include <map>
#include <deque>
#include <mutex>
#include <atomic>
#include <chrono>
#include <functional>
#include <sstream>
#include <algorithm>
#include <cstdint>

// =============================================================================
// CORRELATED INCIDENT
// =============================================================================
struct CorrelatedIncident {
    uint64_t    incident_id   = 0;
    int64_t     first_seen_ms = 0;
    int64_t     last_seen_ms  = 0;
    std::string rule_name;           // Which correlation rule matched
    std::string severity;
    std::string description;
    std::string mitre_tactic;        // Kill-chain phase
    std::string mitre_technique;
    std::vector<int32_t> device_ids; // All devices involved
    std::vector<std::string> events; // Summary of contributing events
    double      confidence    = 0.0;
    bool        is_active     = true;
};

// =============================================================================
// CORRELATION EVENT -- Lightweight event for the correlation window
// =============================================================================
struct CorrEvent {
    int32_t     device_id    = 0;
    int64_t     timestamp_ms = 0;
    std::string source;        // "traffic","ioc","fim","session","alert"
    std::string category;      // "brute_force","c2_beacon","ioc_match", etc.
    std::string severity;
    std::string machine_ip;
    std::string target_user;   // For auth events
    std::string indicator;     // IP, domain, hash involved
    std::string detail;
};

// =============================================================================
// CORRELATION RULE
// =============================================================================
struct CorrelationRule {
    std::string name;
    std::string description;
    std::string severity;
    std::string mitre_tactic;
    std::string mitre_technique;
    int         window_seconds = 300;   // Time window for correlation
    int         min_events     = 2;     // Minimum events to trigger

    // Event match criteria (all must match for an event to be "part of" this rule)
    struct EventMatcher {
        std::string source;      // Empty = any
        std::string category;    // Empty = any
        std::string min_severity;
    };

    std::vector<EventMatcher> stages;  // Ordered sequence of events

    // Scope
    bool cross_device = false;  // true = correlate across devices, false = single device
    bool enabled = true;
};

// =============================================================================
// CORRELATION ENGINE
// =============================================================================
class CorrelationEngine {
public:
    using AlertCallback = std::function<void(const CorrelatedIncident&)>;

    explicit CorrelationEngine(AlertCallback cb = nullptr)
        : alert_cb_(std::move(cb))
    {
        init_default_rules();
    }

    // =========================================================================
    // INGEST EVENT -- Add an event to the correlation window
    // =========================================================================
    void ingest(const CorrEvent& event) {
        // Collect any incidents generated so we can fire callbacks AFTER releasing
        // the lock. Calling user callbacks under a mutex risks deadlock and
        // latency spikes if the callback is slow or reenters this class.
        std::vector<CorrelatedIncident> pending_alerts;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            total_events_++;

            // Add to sliding window
            event_window_.push_back(event);

            // Prune old events (outside max window)
            prune_window();

            // Evaluate all rules -- each may append to pending_alerts
            for (const auto& rule : rules_) {
                if (!rule.enabled) continue;
                evaluate_rule(rule, event, pending_alerts);
            }
        }
        // Fire callbacks without holding the lock
        if (alert_cb_) {
            for (const auto& inc : pending_alerts) alert_cb_(inc);
        }
    }

    // =========================================================================
    // ADD RULE
    // =========================================================================
    void add_rule(const CorrelationRule& rule) {
        std::lock_guard<std::mutex> lock(mutex_);
        rules_.push_back(rule);
    }

    // =========================================================================
    // GET ACTIVE INCIDENTS
    // =========================================================================
    std::vector<CorrelatedIncident> get_active_incidents() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<CorrelatedIncident> active;
        for (const auto& inc : incidents_) {
            if (inc.is_active) active.push_back(inc);
        }
        return active;
    }

    std::vector<CorrelatedIncident> get_recent_incidents(size_t limit = 50) const {
        std::lock_guard<std::mutex> lock(mutex_);
        size_t start = incidents_.size() > limit ? incidents_.size() - limit : 0;
        return std::vector<CorrelatedIncident>(
            incidents_.begin() + static_cast<long>(start), incidents_.end());
    }

    // =========================================================================
    // JSON EXPORT
    // =========================================================================
    std::string incidents_to_json(size_t limit = 50) const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::string json = "[";
        size_t start = incidents_.size() > limit ? incidents_.size() - limit : 0;
        bool first = true;
        for (size_t i = start; i < incidents_.size(); i++) {
            const auto& inc = incidents_[i];
            if (!first) json += ",";
            first = false;
            json += "{\"incident_id\":" + std::to_string(inc.incident_id)
                + ",\"first_seen_ms\":" + std::to_string(inc.first_seen_ms)
                + ",\"last_seen_ms\":" + std::to_string(inc.last_seen_ms)
                + ",\"rule_name\":\"" + json_escape(inc.rule_name) + "\""
                + ",\"severity\":\"" + inc.severity + "\""
                + ",\"description\":\"" + json_escape(inc.description) + "\""
                + ",\"mitre_tactic\":\"" + json_escape(inc.mitre_tactic) + "\""
                + ",\"mitre_technique\":\"" + json_escape(inc.mitre_technique) + "\""
                + ",\"confidence\":" + std::to_string(inc.confidence)
                + ",\"is_active\":" + (inc.is_active ? "true" : "false")
                + ",\"device_count\":" + std::to_string(inc.device_ids.size())
                + ",\"event_count\":" + std::to_string(inc.events.size())
                + ",\"devices\":[";
            for (size_t d = 0; d < inc.device_ids.size(); d++) {
                if (d > 0) json += ",";
                json += std::to_string(inc.device_ids[d]);
            }
            json += "]}";
        }
        json += "]";
        return json;
    }

    // --- Diagnostics ---
    size_t total_events() const        { return total_events_.load(); }
    size_t total_incidents() const     { return total_incidents_.load(); }
    size_t active_incidents() const    { std::lock_guard<std::mutex> lock(mutex_); size_t n=0; for(const auto& i:incidents_) if(i.is_active) n++; return n; }
    size_t window_size() const         { std::lock_guard<std::mutex> lock(mutex_); return event_window_.size(); }
    size_t rule_count() const          { std::lock_guard<std::mutex> lock(mutex_); return rules_.size(); }

private:
    mutable std::mutex mutex_;
    AlertCallback alert_cb_;

    std::vector<CorrelationRule> rules_;
    std::deque<CorrEvent> event_window_;
    std::vector<CorrelatedIncident> incidents_;

    int max_window_s_ = 1800;  // 30 minute max window
    uint64_t next_incident_id_ = 1;

    std::atomic<size_t> total_events_{0};
    std::atomic<size_t> total_incidents_{0};

    // Cooldown: rule_name:scope_key -> last trigger time
    std::map<std::string, int64_t> cooldown_map_;
    static const int COOLDOWN_S = 300;

    void prune_window() {
        auto cutoff_ms = current_ms() - (max_window_s_ * 1000LL);
        while (!event_window_.empty() && event_window_.front().timestamp_ms < cutoff_ms) {
            event_window_.pop_front();
        }
        // Also cap size
        while (event_window_.size() > 50000) {
            event_window_.pop_front();
        }
    }

    void evaluate_rule(const CorrelationRule& rule, const CorrEvent& trigger,
                       std::vector<CorrelatedIncident>& pending_alerts) {
        auto now_ms = current_ms();
        auto window_start = now_ms - (rule.window_seconds * 1000LL);

        // Collect events matching rule stages within window
        std::vector<std::vector<const CorrEvent*>> stage_matches(rule.stages.size());

        for (const auto& ev : event_window_) {
            if (ev.timestamp_ms < window_start) continue;
            if (!rule.cross_device && ev.device_id != trigger.device_id) continue;

            for (size_t s = 0; s < rule.stages.size(); s++) {
                if (matches_stage(rule.stages[s], ev)) {
                    stage_matches[s].push_back(&ev);
                }
            }
        }

        // Check if all stages have at least one match
        bool all_stages_matched = true;
        int total_matches = 0;
        for (const auto& sm : stage_matches) {
            if (sm.empty()) { all_stages_matched = false; break; }
            total_matches += static_cast<int>(sm.size());
        }

        if (!all_stages_matched || total_matches < rule.min_events) return;

        // Cooldown check
        std::string scope_key = rule.cross_device ? "global" : std::to_string(trigger.device_id);
        std::string cooldown_key = rule.name + ":" + scope_key;
        auto cd_it = cooldown_map_.find(cooldown_key);
        if (cd_it != cooldown_map_.end() && (now_ms - cd_it->second) < COOLDOWN_S * 1000LL)
            return;
        cooldown_map_[cooldown_key] = now_ms;

        // Build correlated incident
        CorrelatedIncident inc;
        inc.incident_id = next_incident_id_++;
        inc.rule_name = rule.name;
        inc.severity = rule.severity;
        inc.mitre_tactic = rule.mitre_tactic;
        inc.mitre_technique = rule.mitre_technique;
        inc.confidence = std::min(1.0, 0.5 + (total_matches * 0.1));
        inc.first_seen_ms = now_ms;
        inc.last_seen_ms = now_ms;
        inc.is_active = true;

        // Collect involved devices and event summaries
        std::set<int32_t> devices;
        for (const auto& sm : stage_matches) {
            for (const auto* ev : sm) {
                devices.insert(ev->device_id);
                inc.events.push_back(ev->source + "/" + ev->category
                    + " from device " + std::to_string(ev->device_id));
            }
        }
        inc.device_ids.assign(devices.begin(), devices.end());

        // Build description
        std::ostringstream desc;
        desc << rule.description << " | " << inc.device_ids.size() << " device(s), "
             << total_matches << " events in " << rule.window_seconds << "s window";
        inc.description = desc.str();

        incidents_.push_back(inc);
        total_incidents_++;

        // Cap incidents
        if (incidents_.size() > 5000) {
            incidents_.erase(incidents_.begin(),
                incidents_.begin() + static_cast<long>(incidents_.size() - 2500));
        }

        // Queue for callback after lock release
        pending_alerts.push_back(inc);
    }

    static bool matches_stage(const CorrelationRule::EventMatcher& m, const CorrEvent& ev) {
        if (!m.source.empty() && m.source != ev.source) return false;
        if (!m.category.empty() && m.category != ev.category) return false;
        if (!m.min_severity.empty()) {
            if (sev_level(ev.severity) < sev_level(m.min_severity)) return false;
        }
        return true;
    }

    static int sev_level(const std::string& s) {
        if (s == "critical") return 4; if (s == "high") return 3;
        if (s == "medium") return 2; if (s == "low") return 1;
        return 0;
    }

    static int64_t current_ms() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }

    static std::string json_escape(const std::string& s) {
        std::string out;
        for (char c : s) {
            if (c == '"') out += "\\\"";
            else if (c == '\\') out += "\\\\";
            else if (c == '\n') out += "\\n";
            else out += c;
        }
        return out;
    }

    // =========================================================================
    // DEFAULT RULES
    // =========================================================================
    void init_default_rules() {
        // Rule 1: Brute force followed by successful login (lateral movement)
        {
            CorrelationRule r;
            r.name = "brute_force_then_login";
            r.description = "Brute force attack followed by successful authentication -- possible credential compromise";
            r.severity = "critical";
            r.mitre_tactic = "Lateral Movement";
            r.mitre_technique = "T1110";
            r.window_seconds = 600;
            r.min_events = 3;
            r.cross_device = true;
            r.stages.push_back({"traffic", "brute_force", "high"});
            r.stages.push_back({"session", "", "low"});
            rules_.push_back(std::move(r));
        }

        // Rule 2: IoC match + data exfiltration (compromised host exfiltrating)
        {
            CorrelationRule r;
            r.name = "ioc_then_exfil";
            r.description = "Known threat indicator followed by data exfiltration pattern";
            r.severity = "critical";
            r.mitre_tactic = "Exfiltration";
            r.mitre_technique = "T1041";
            r.window_seconds = 900;
            r.min_events = 2;
            r.cross_device = false;
            r.stages.push_back({"ioc", "", "medium"});
            r.stages.push_back({"traffic", "data_exfiltration", "medium"});
            rules_.push_back(std::move(r));
        }

        // Rule 3: FIM change + C2 beaconing (persistence + C2)
        {
            CorrelationRule r;
            r.name = "fim_and_c2";
            r.description = "File system modification paired with C2 communication -- possible malware installation";
            r.severity = "critical";
            r.mitre_tactic = "Command and Control";
            r.mitre_technique = "T1071";
            r.window_seconds = 600;
            r.min_events = 2;
            r.cross_device = false;
            r.stages.push_back({"fim", "", "medium"});
            r.stages.push_back({"traffic", "c2_beacon", "medium"});
            rules_.push_back(std::move(r));
        }

        // Rule 4: Multiple high-severity events across devices (campaign)
        {
            CorrelationRule r;
            r.name = "multi_device_campaign";
            r.description = "Multiple high-severity events across different devices -- possible coordinated attack";
            r.severity = "critical";
            r.mitre_tactic = "Impact";
            r.mitre_technique = "T1486";
            r.window_seconds = 300;
            r.min_events = 4;
            r.cross_device = true;
            r.stages.push_back({"", "", "high"});
            r.stages.push_back({"", "", "high"});
            rules_.push_back(std::move(r));
        }

        // Rule 5: Privilege escalation + suspicious process
        {
            CorrelationRule r;
            r.name = "privesc_suspicious_proc";
            r.description = "Privilege escalation followed by suspicious process execution";
            r.severity = "high";
            r.mitre_tactic = "Privilege Escalation";
            r.mitre_technique = "T1078";
            r.window_seconds = 300;
            r.min_events = 2;
            r.cross_device = false;
            r.stages.push_back({"session", "priv_escalation", "medium"});
            r.stages.push_back({"process", "suspicious", "medium"});
            rules_.push_back(std::move(r));
        }

        // Rule 6: Port scan + exploitation attempt
        {
            CorrelationRule r;
            r.name = "scan_then_exploit";
            r.description = "Network reconnaissance followed by exploitation attempt";
            r.severity = "high";
            r.mitre_tactic = "Initial Access";
            r.mitre_technique = "T1190";
            r.window_seconds = 600;
            r.min_events = 2;
            r.cross_device = true;
            r.stages.push_back({"traffic", "port_scan", "medium"});
            r.stages.push_back({"traffic", "exploit_attempt", "medium"});
            rules_.push_back(std::move(r));
        }

        // Rule 7: DNS tunneling + data exfiltration
        {
            CorrelationRule r;
            r.name = "dns_tunnel_exfil";
            r.description = "DNS tunneling activity paired with data exfiltration";
            r.severity = "critical";
            r.mitre_tactic = "Exfiltration";
            r.mitre_technique = "T1048.001";
            r.window_seconds = 900;
            r.min_events = 2;
            r.cross_device = false;
            r.stages.push_back({"network_inspector", "dns_tunnel", "medium"});
            r.stages.push_back({"traffic", "data_exfiltration", "medium"});
            rules_.push_back(std::move(r));
        }
    }
};

#endif
