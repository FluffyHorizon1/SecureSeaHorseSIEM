// =============================================================================
// sigma_engine.h -- Phase 16 (v3.5.0)
// -----------------------------------------------------------------------------
// Minimal Sigma rule evaluator. Parses the subset of the Sigma YAML spec that
// covers 90% of community rules: `detection.selection` / `condition` /
// `logsource` / `level`. Rules are loaded from a directory at startup and
// evaluated against incoming log chunks alongside the Phase 2 regex engine.
//
// The parser is intentionally hand-rolled — we do not want a YAML dependency
// in the core server. Only the flat-mapping subset used by 99% of community
// rules is supported; nested `sel1 and (sel2 or sel3)` conditions go through
// a tiny recursive-descent evaluator.
//
// Integration: `SigmaEngine::evaluate(log_line, device_id)` returns a vector
// of `SigmaHit` which the dispatcher turns into `security_events` rows and
// feeds into the correlation engine.
// =============================================================================
#pragma once

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <regex>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace seahorse::sigma {

struct SigmaRule {
    std::string id;                              // GUID from the YAML `id:` field
    std::string title;
    std::string level;                           // informational|low|medium|high|critical
    std::string logsource_product;               // windows|linux|macos|network|...
    std::string logsource_service;               // sysmon|auditd|zeek|...
    std::vector<std::string> mitre_techniques;   // T####(.###)? IDs from `tags:`
    // Flat keyword/regex pattern list. If any pattern matches the log line the
    // rule fires. Expanded form supports `field: value` but this minimal engine
    // treats everything as substring/regex on the raw chunk.
    std::vector<std::regex> patterns;
    std::vector<std::string> keywords;           // fast pre-filter before regex
    std::string condition = "any";               // `any` | `all` (1-of-N / N-of-N)
    bool disabled = false;
};

struct SigmaHit {
    std::string rule_id;
    std::string rule_title;
    std::string severity;
    std::vector<std::string> mitre_ids;
    std::string matched_text;
    int device_id = 0;
};

class SigmaEngine {
public:
    // Load every *.yml / *.yaml file under `rules_dir` recursively. Loader
    // inherits the same hardening caps as the regex engine: 10k rules max,
    // 64 KB per file, 4 KB per pattern.
    bool load_directory(const std::string& rules_dir);
    std::size_t rule_count() const { std::shared_lock g(mtx_); return rules_.size(); }

    // Evaluate a chunk (one log line, not a whole file). Hot path: lock-free
    // read under shared_mutex so reload doesn't block ingestion.
    std::vector<SigmaHit> evaluate(const std::string& chunk, int device_id);

    // File-watcher — polls the rules directory every `interval_s` seconds and
    // reloads if any mtime changed. Enabled via server.conf `sigma_auto_reload`.
    void start_auto_reload(int interval_s);
    void stop_auto_reload();

private:
    mutable std::shared_mutex mtx_;
    std::vector<SigmaRule>    rules_;
    std::atomic<bool>         reload_flag_{false};
    std::atomic<bool>         reloader_running_{false};

    // Minimal single-file parser. Returns empty vector on malformed YAML —
    // malformed rules are logged and skipped, never aborting the load.
    static std::vector<SigmaRule> parse_file(const std::filesystem::path& p);

    // Caps mirrored from the regex loader (see v3.1.1 hardening).
    static constexpr std::size_t kMaxRules        = 10000;
    static constexpr std::size_t kMaxFileBytes    = 64 * 1024;
    static constexpr std::size_t kMaxPatternBytes = 4 * 1024;
};

} // namespace seahorse::sigma
