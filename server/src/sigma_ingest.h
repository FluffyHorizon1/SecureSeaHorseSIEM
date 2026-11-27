// =============================================================================
// sigma_ingest.h -- v5.2 groundwork: wire SigmaEngine into log ingestion
// -----------------------------------------------------------------------------
// Small, header-only hook used by server.cpp and by test_sigma_ingest.
// Behind `sigma_enabled` (default false). Never throws: bad rules are
// skipped at load, and evaluate errors are swallowed so a bad pattern
// cannot crash the ingest path.
//
// The current agent telemetry path supplies a raw log chunk, not a field
// map, so keyword-style rules and message/_raw modifiers match; field-map
// rules (Image|endswith, ...) need structured fields the helper also
// accepts, but process_report does not populate them today.
// Auto-reload is still a no-op; call load() again to refresh.
// =============================================================================
#pragma once

#include "alert_engine.h"
#include "sigma_engine.h"

#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>
#include <vector>

namespace seahorse::sigma {

class SigmaPipeline {
public:
    using LogFn = std::function<void(const std::string&)>;

    struct Config {
        bool enabled = false;
        std::filesystem::path rules_dir;
    };

    bool enabled() const { return enabled_; }
    size_t rule_count() const { return engine_.rule_count(); }
    std::vector<LoadError> errors() const { return engine_.errors(); }

    // Never throws. When disabled, clears any previously loaded rules and
    // returns 0. Load errors (missing dir, malformed YAML, bad |re, caps)
    // are reported via `log` and errors(); they do not abort the load.
    size_t load(const Config& cfg, LogFn log = {}) {
        try {
            enabled_ = cfg.enabled;
            engine_.clear();
            if (!enabled_) {
                if (log) log("sigma engine: disabled (sigma_enabled=false)");
                return 0;
            }
            if (cfg.rules_dir.empty()) {
                if (log) log("sigma_enabled is true but sigma_rules_dir is empty; no rules loaded");
                return 0;
            }
            size_t n = engine_.load_directory(cfg.rules_dir);
            for (const auto& e : engine_.errors()) {
                if (!log) continue;
                std::string m = "sigma rule skipped: " + e.path;
                if (e.line > 0) m += ":" + std::to_string(e.line);
                m += ": " + e.message;
                log(m);
            }
            if (log) {
                log("sigma engine: loaded " + std::to_string(n) + " rule(s) from "
                    + cfg.rules_dir.string() + " ("
                    + std::to_string(engine_.errors().size()) + " skipped)");
            }
            return n;
        } catch (const std::exception& ex) {
            if (log) log(std::string("sigma load failed: ") + ex.what());
            return engine_.rule_count();
        } catch (...) {
            if (log) log("sigma load failed with an unknown error");
            return engine_.rule_count();
        }
    }

    // Evaluate a raw log chunk (the agent telemetry path) and raise one
    // alert per hit. Returns the hits. Never throws.
    std::vector<SigmaHit> evaluate_and_alert(const std::string& raw_log,
                                             int32_t device_id,
                                             const std::string& machine_ip,
                                             AlertEngine* alerts) {
        SigmaEvent ev;
        ev.raw = raw_log;
        return evaluate_and_alert(ev, device_id, machine_ip, alerts);
    }

    std::vector<SigmaHit> evaluate_and_alert(const SigmaEvent& ev,
                                             int32_t device_id,
                                             const std::string& machine_ip,
                                             AlertEngine* alerts) {
        std::vector<SigmaHit> hits;
        if (!enabled_) return hits;
        try {
            hits = engine_.evaluate(ev, device_id);
        } catch (...) {
            return {};
        }
        if (alerts) {
            for (const auto& h : hits) {
                try {
                    const std::string& text = ev.raw.empty() ? h.title : ev.raw;
                    alerts->raise_sigma(device_id, machine_ip,
                                        h.rule_id, h.title, h.level, text);
                } catch (...) {
                    // A logging failure must not take down ingest.
                }
            }
        }
        return hits;
    }

private:
    bool enabled_ = false;
    SigmaEngine engine_;
};

} // namespace seahorse::sigma
