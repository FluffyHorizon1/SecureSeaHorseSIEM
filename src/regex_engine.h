#ifndef REGEX_ENGINE_H
#define REGEX_ENGINE_H

// =============================================================================
// SecureSeaHorse SIEM — Phase 2: Regex-Based Log Analysis Engine
// =============================================================================
// Provides:
//   - Built-in default patterns for Linux syslog + Windows EventLog
//   - User-defined rules from external rules.conf file
//   - Structured SecurityEvent output per match
//   - Thread-safe (regex objects are read-only after init)
//   - Replaces the old count_failed_logins() basic string matching
// =============================================================================

#include <string>
#include <vector>
#include <regex>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iostream>

// =============================================================================
// SECURITY EVENT — Output structure from the regex engine
// =============================================================================
struct SecurityEvent {
    std::string rule_name;     // e.g. "ssh_failed_password"
    std::string severity;      // "low", "medium", "high", "critical"
    std::string category;      // e.g. "auth_failure", "brute_force", "privilege_escalation"
    std::string matched_text;  // The log line or fragment that matched
};

// =============================================================================
// DETECTION RULE — One compiled regex with metadata
// =============================================================================
struct DetectionRule {
    std::string name;
    std::string severity;      // low | medium | high | critical
    std::string category;
    std::regex  pattern;
    bool        is_builtin;    // true = shipped default, false = user-defined

    DetectionRule() : is_builtin(false) {}

    DetectionRule(const std::string& n, const std::string& sev,
        const std::string& cat, const std::string& regex_str,
        bool builtin = false)
        : name(n), severity(sev), category(cat), is_builtin(builtin)
    {
        try {
            pattern = std::regex(regex_str,
                std::regex_constants::ECMAScript |
                std::regex_constants::icase |
                std::regex_constants::optimize);
        }
        catch (const std::regex_error& e) {
            std::cerr << "[RegexEngine] Invalid pattern for rule '" << n
                << "': " << e.what() << "\n";
            pattern = std::regex("(?!)"); // Never matches
        }
    }
};

// =============================================================================
// REGEX ENGINE
// =============================================================================
class RegexEngine {
public:
    /// Initialize with built-in defaults, then optionally load user rules
    /// @param rules_file_path  Path to rules.conf (empty = skip user rules)
    RegexEngine(const std::string& rules_file_path = "") {
        load_builtin_rules();

        if (!rules_file_path.empty()) {
            user_rules_loaded_ = load_rules_file(rules_file_path);
        }
    }

    /// Analyze a raw log chunk and return all matching security events
    std::vector<SecurityEvent> analyze(const std::string& raw_log) const {
        std::vector<SecurityEvent> events;
        if (raw_log.empty()) return events;

        // Split into lines for per-line matching
        std::istringstream stream(raw_log);
        std::string line;

        while (std::getline(stream, line)) {
            if (line.empty()) continue;

            // Trim trailing \r (Windows line endings in mixed content)
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }
            if (line.empty()) continue;

            for (const auto& rule : rules_) {
                if (std::regex_search(line, rule.pattern)) {
                    SecurityEvent ev;
                    ev.rule_name = rule.name;
                    ev.severity = rule.severity;
                    ev.category = rule.category;
                    // Truncate matched text to 512 chars
                    ev.matched_text = line.substr(0, 512);
                    events.push_back(std::move(ev));
                    // Don't break — a line can match multiple rules
                }
            }
        }

        return events;
    }

    /// Count total events matching a specific category (backward-compat helper)
    int count_by_category(const std::vector<SecurityEvent>& events,
        const std::string& category) const {
        int count = 0;
        for (const auto& ev : events) {
            if (ev.category == category) count++;
        }
        return count;
    }

    /// Convenience: count failed logins (backward-compatible with Phase 1)
    int count_failed_logins(const std::string& raw_log) const {
        auto events = analyze(raw_log);
        return count_by_category(events, "auth_failure");
    }

    // --- Diagnostics ---
    size_t rule_count()        const { return rules_.size(); }
    size_t builtin_count()     const {
        size_t c = 0;
        for (const auto& r : rules_) if (r.is_builtin) c++;
        return c;
    }
    size_t user_rules_loaded() const { return user_rules_loaded_; }

    const std::vector<DetectionRule>& rules() const { return rules_; }

private:
    std::vector<DetectionRule> rules_;
    size_t user_rules_loaded_ = 0;

    // =========================================================================
    // BUILT-IN RULES — Ship with the binary, always active
    // =========================================================================
    void load_builtin_rules() {
        // ----- Authentication Failures -----
        rules_.emplace_back(
            "ssh_failed_password", "high", "auth_failure",
            R"(failed password for\s+\S+\s+from\s+[\d.]+)", true);

        rules_.emplace_back(
            "pam_auth_failure", "high", "auth_failure",
            R"(pam_unix\(.*\):\s*authentication failure)", true);

        rules_.emplace_back(
            "sshd_invalid_user", "high", "auth_failure",
            R"(invalid user\s+\S+\s+from\s+[\d.]+)", true);

        rules_.emplace_back(
            "win_logon_failure_4625", "high", "auth_failure",
            R"((<EventID>4625</EventID>|event\s*id[:\s]*4625))", true);

        rules_.emplace_back(
            "win_logon_failure_generic", "medium", "auth_failure",
            R"(audit failure.*logon)", true);

        rules_.emplace_back(
            "su_failed", "high", "auth_failure",
            R"(su\[.*\]:\s*failed su for\s+\S+)", true);

        // ----- Privilege Escalation -----
        rules_.emplace_back(
            "sudo_failed", "critical", "privilege_escalation",
            R"(sudo:.*NOT in sudoers)", true);

        rules_.emplace_back(
            "sudo_session_open", "low", "privilege_escalation",
            R"(sudo:.*session opened for user root)", true);

        rules_.emplace_back(
            "win_priv_escalation_4672", "medium", "privilege_escalation",
            R"((<EventID>4672</EventID>|event\s*id[:\s]*4672))", true);

        // ----- Service / Daemon Events -----
        rules_.emplace_back(
            "service_start_failed", "medium", "service_failure",
            R"(systemd\[.*\]:\s*\S+\.service.*failed)", true);

        rules_.emplace_back(
            "oom_killer", "critical", "resource_exhaustion",
            R"(out of memory:?\s*kill process)", true);

        rules_.emplace_back(
            "segfault", "high", "crash",
            R"(segfault at\s+[0-9a-fA-F]+)", true);

        // ----- Brute Force Indicators -----
        rules_.emplace_back(
            "sshd_max_auth_exceeded", "critical", "brute_force",
            R"(error:\s*maximum authentication attempts exceeded)", true);

        rules_.emplace_back(
            "sshd_connection_reset", "medium", "brute_force",
            R"(connection (reset|closed) by\s+[\d.]+.*\[preauth\])", true);

        // ----- Account Management (Windows) -----
        rules_.emplace_back(
            "win_account_locked_4740", "high", "account_lockout",
            R"((<EventID>4740</EventID>|event\s*id[:\s]*4740))", true);

        rules_.emplace_back(
            "win_password_changed_4723", "low", "account_change",
            R"((<EventID>4723</EventID>|event\s*id[:\s]*4723))", true);

        // ----- Firewall / Network -----
        rules_.emplace_back(
            "iptables_drop", "medium", "firewall",
            R"(iptables.*DROP)", true);

        rules_.emplace_back(
            "ufw_block", "medium", "firewall",
            R"(\[UFW BLOCK\])", true);
    }

    // =========================================================================
    // USER RULES FILE PARSER
    // =========================================================================
    // Format: one rule per line, pipe-delimited:
    //   name|severity|category|regex_pattern
    //
    // Lines starting with # are comments. Empty lines are skipped.
    // User rules that share a name with a built-in rule OVERRIDE the built-in.
    // =========================================================================
    size_t load_rules_file(const std::string& path) {
        std::ifstream file(path);
        if (!file.is_open()) {
            // Not an error — rules file is optional
            return 0;
        }

        size_t loaded = 0;
        std::string line;
        int line_num = 0;

        while (std::getline(file, line)) {
            line_num++;

            // Trim
            while (!line.empty() && (line.back() == '\r' || line.back() == '\n' ||
                line.back() == ' ' || line.back() == '\t')) {
                line.pop_back();
            }
            size_t start = line.find_first_not_of(" \t");
            if (start == std::string::npos) continue;
            line = line.substr(start);

            // Skip comments and empty lines
            if (line.empty() || line[0] == '#') continue;

            // Parse: name|severity|category|pattern
            std::vector<std::string> fields;
            std::istringstream ss(line);
            std::string field;
            while (std::getline(ss, field, '|')) {
                // Trim each field
                size_t fs = field.find_first_not_of(" \t");
                size_t fe = field.find_last_not_of(" \t");
                if (fs != std::string::npos) {
                    fields.push_back(field.substr(fs, fe - fs + 1));
                }
                else {
                    fields.push_back("");
                }
            }

            if (fields.size() < 4) {
                std::cerr << "[RegexEngine] rules.conf:" << line_num
                    << " — expected 4 pipe-delimited fields, got "
                    << fields.size() << ". Skipping.\n";
                continue;
            }

            const std::string& name = fields[0];
            const std::string& severity = fields[1];
            const std::string& category = fields[2];
            const std::string& pattern = fields[3];

            // Validate severity
            if (severity != "low" && severity != "medium" &&
                severity != "high" && severity != "critical") {
                std::cerr << "[RegexEngine] rules.conf:" << line_num
                    << " — invalid severity '" << severity
                    << "'. Use: low|medium|high|critical. Skipping.\n";
                continue;
            }

            // Check for override: remove existing built-in with same name
            rules_.erase(
                std::remove_if(rules_.begin(), rules_.end(),
                    [&name](const DetectionRule& r) {
                        return r.name == name;
                    }),
                rules_.end()
            );

            // Add user rule
            rules_.emplace_back(name, severity, category, pattern, false);
            loaded++;
        }

        return loaded;
    }
};

#endif
#pragma once
