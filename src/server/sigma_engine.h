#ifndef SIGMA_ENGINE_H
#define SIGMA_ENGINE_H

#ifndef NOMINMAX
#define NOMINMAX
#endif

// =============================================================================
// SecureSeaHorse SIEM -- Phase 16: Sigma Rule Engine (Server-Side)
// =============================================================================
// Imports and evaluates a practical subset of the community Sigma YAML format
// against the unified event stream produced by earlier phases.
//
// Supported features:
//   - Rule metadata: title, id, description, level, author, status, tags
//   - `logsource`: category/product filter (mapped to our SecureSeaHorse sources)
//   - `detection`: multiple named selections + condition expression
//   - Field matches with modifiers: |contains, |startswith, |endswith,
//     |re (regex), |all (AND semantics instead of OR)
//   - Condition operators: AND, OR, NOT, parentheses, "1 of selection*"
//   - Built-in field aliases: EventID, CommandLine, Image, User, SourceIp,
//     DestinationIp, DestinationPort, DomainName, Hashes, TargetFilename
//
// NOT supported (kept simple by design):
//   - Aggregations (| count by, | near) -- use Phase 15 correlation instead
//   - Backend-specific transformations (ECS, elastic.agent, etc.)
//   - References / inheritance
//
// Rules are loaded from <sigma_rules_dir>/*.yml at startup and on file change.
// Matches raise an internal `SigmaHit` that is routed to IR and correlation.
// =============================================================================

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <regex>
#include <set>
#include <shared_mutex>
#include <sstream>
#include <string>
#include <unordered_map>
#include <variant>
#include <vector>

namespace fs = std::filesystem;

// =============================================================================
// EVENT ABSTRACTION
// =============================================================================
// Sigma needs key/value fields. Existing phases produce heterogenous event
// types; we normalize them into SigmaEvent before matching.
// =============================================================================
struct SigmaEvent {
    std::string source;       // "process", "network", "auth", "fim", "dns", "log"
    std::string category;     // finer-grained (e.g. "process_creation")
    int32_t     device_id   = 0;
    int64_t     timestamp_ms = 0;
    std::unordered_map<std::string, std::string> fields;  // CommandLine, Image, etc.

    std::string get(const std::string& key) const {
        auto it = fields.find(key);
        return it == fields.end() ? "" : it->second;
    }
};

// =============================================================================
// SIGMA HIT -- Output from the engine
// =============================================================================
struct SigmaHit {
    std::string rule_id;
    std::string rule_title;
    std::string severity;        // informational/low/medium/high/critical
    std::vector<std::string> tags;
    std::string mitre_id;        // Derived from tags when possible
    std::string description;
    int32_t     device_id    = 0;
    int64_t     timestamp_ms = 0;
    std::string machine_ip;
    std::string matched_field;   // Primary field that matched (for context)
    std::string matched_value;
};

// =============================================================================
// INTERNAL: FIELD MATCHER
// =============================================================================
enum class SigmaModifier { EXACT, CONTAINS, STARTSWITH, ENDSWITH, REGEX };

struct FieldMatcher {
    std::string   field;
    SigmaModifier modifier = SigmaModifier::EXACT;
    bool          all_values = false;       // |all => every value must match
    bool          case_insensitive = true;  // Sigma default
    std::vector<std::string> values;
    std::vector<std::regex>  compiled;      // Only for REGEX mode

    bool evaluate(const SigmaEvent& ev) const {
        std::string actual = ev.get(field);
        if (actual.empty() && values.empty()) return false;

        std::string lhs = actual;
        if (case_insensitive) {
            std::transform(lhs.begin(), lhs.end(), lhs.begin(), ::tolower);
        }

        auto match_one = [&](size_t i) -> bool {
            if (modifier == SigmaModifier::REGEX) {
                if (i >= compiled.size()) return false;
                try { return std::regex_search(actual, compiled[i]); }
                catch (...) { return false; }
            }
            std::string needle = values[i];
            if (case_insensitive) {
                std::transform(needle.begin(), needle.end(), needle.begin(), ::tolower);
            }
            switch (modifier) {
                case SigmaModifier::EXACT:      return lhs == needle;
                case SigmaModifier::CONTAINS:   return lhs.find(needle) != std::string::npos;
                case SigmaModifier::STARTSWITH: return lhs.compare(0, needle.size(), needle) == 0;
                case SigmaModifier::ENDSWITH:
                    return lhs.size() >= needle.size() &&
                           lhs.compare(lhs.size() - needle.size(), needle.size(), needle) == 0;
                default: return false;
            }
        };

        if (all_values) {
            for (size_t i = 0; i < values.size(); i++) if (!match_one(i)) return false;
            return !values.empty();
        }
        for (size_t i = 0; i < values.size(); i++) if (match_one(i)) return true;
        return false;
    }
};

// =============================================================================
// INTERNAL: SELECTION (group of field matchers, all AND'd)
// =============================================================================
struct SigmaSelection {
    std::string name;
    std::vector<FieldMatcher> matchers;

    bool evaluate(const SigmaEvent& ev) const {
        for (const auto& m : matchers) if (!m.evaluate(ev)) return false;
        return !matchers.empty();
    }
};

// =============================================================================
// INTERNAL: CONDITION EXPRESSION (very small evaluator)
// =============================================================================
// Supported tokens:
//   selection names, "and", "or", "not", "(", ")", "1 of selection*",
//   "all of selection*"
// Produces a postfix evaluator. Anything we cannot parse falls back to
// "any selection matches" so a rule is never silently ignored.
// =============================================================================
class SigmaCondition {
public:
    explicit SigmaCondition(const std::string& expr) : expr_(expr) {
        tokens_ = tokenize(expr);
    }

    bool evaluate(const std::map<std::string, bool>& selections) const {
        size_t pos = 0;
        try {
            bool r = parse_or(pos, selections);
            return r;
        } catch (...) {
            // Safe fallback: true if any selection matched
            for (const auto& kv : selections) if (kv.second) return true;
            return false;
        }
    }

private:
    std::string expr_;
    std::vector<std::string> tokens_;

    static std::vector<std::string> tokenize(const std::string& s) {
        std::vector<std::string> out;
        std::string cur;
        for (size_t i = 0; i < s.size(); i++) {
            char c = s[i];
            if (c == '(' || c == ')') {
                if (!cur.empty()) { out.push_back(cur); cur.clear(); }
                out.push_back(std::string(1, c));
            } else if (std::isspace(static_cast<unsigned char>(c))) {
                if (!cur.empty()) { out.push_back(cur); cur.clear(); }
            } else {
                cur += c;
            }
        }
        if (!cur.empty()) out.push_back(cur);
        return out;
    }

    bool match_wild(const std::string& pattern,
                    const std::map<std::string, bool>& selections,
                    bool require_all) const {
        // "selection*" => match any selection whose name starts with "selection"
        std::string prefix = pattern;
        if (!prefix.empty() && prefix.back() == '*') prefix.pop_back();
        bool found_any = false;
        for (const auto& kv : selections) {
            if (kv.first.compare(0, prefix.size(), prefix) == 0) {
                found_any = true;
                if (require_all && !kv.second) return false;
                if (!require_all && kv.second) return true;
            }
        }
        return require_all ? found_any : false;
    }

    bool parse_or(size_t& pos, const std::map<std::string, bool>& sel) const {
        bool lhs = parse_and(pos, sel);
        while (pos < tokens_.size() && ci_equal(tokens_[pos], "or")) {
            pos++;
            bool rhs = parse_and(pos, sel);
            lhs = lhs || rhs;
        }
        return lhs;
    }
    bool parse_and(size_t& pos, const std::map<std::string, bool>& sel) const {
        bool lhs = parse_unary(pos, sel);
        while (pos < tokens_.size() && ci_equal(tokens_[pos], "and")) {
            pos++;
            bool rhs = parse_unary(pos, sel);
            lhs = lhs && rhs;
        }
        return lhs;
    }
    bool parse_unary(size_t& pos, const std::map<std::string, bool>& sel) const {
        if (pos < tokens_.size() && ci_equal(tokens_[pos], "not")) {
            pos++;
            return !parse_unary(pos, sel);
        }
        return parse_atom(pos, sel);
    }
    bool parse_atom(size_t& pos, const std::map<std::string, bool>& sel) const {
        if (pos >= tokens_.size()) return false;
        const std::string& t = tokens_[pos];
        if (t == "(") {
            pos++;
            bool v = parse_or(pos, sel);
            if (pos < tokens_.size() && tokens_[pos] == ")") pos++;
            return v;
        }
        // "1 of selection*" / "all of selection*"
        if ((ci_equal(t, "1") || ci_equal(t, "all")) &&
            pos + 2 < tokens_.size() && ci_equal(tokens_[pos + 1], "of")) {
            bool require_all = ci_equal(t, "all");
            std::string pattern = tokens_[pos + 2];
            pos += 3;
            return match_wild(pattern, sel, require_all);
        }
        // Plain selection name
        pos++;
        auto it = sel.find(t);
        return it != sel.end() && it->second;
    }

    static bool ci_equal(const std::string& a, const std::string& b) {
        if (a.size() != b.size()) return false;
        for (size_t i = 0; i < a.size(); i++)
            if (std::tolower(static_cast<unsigned char>(a[i])) !=
                std::tolower(static_cast<unsigned char>(b[i]))) return false;
        return true;
    }
};

// =============================================================================
// SIGMA RULE
// =============================================================================
struct SigmaRule {
    std::string id;
    std::string title;
    std::string description;
    std::string author;
    std::string level;           // informational/low/medium/high/critical
    std::string status;          // stable, experimental, test, deprecated
    std::vector<std::string> tags;
    std::string mitre_id;        // Derived from tags (e.g. attack.t1059)

    // logsource
    std::string ls_product;
    std::string ls_category;
    std::string ls_service;

    std::vector<SigmaSelection> selections;
    std::unique_ptr<SigmaCondition> condition;
    std::string condition_expr;

    bool enabled = true;

    // Does this rule apply to the given event's logsource?
    bool matches_source(const SigmaEvent& ev) const {
        // Mapping table: Sigma category/product -> our source strings
        // Empty means "apply to all".
        auto src_ok = [&](const std::string& target) {
            if (target.empty()) return true;
            if (target == ev.source) return true;
            if (target == ev.category) return true;
            // Common aliases
            if (target == "process_creation" && ev.source == "process") return true;
            if (target == "dns"              && ev.source == "dns") return true;
            if (target == "authentication"   && ev.source == "auth") return true;
            if (target == "file_event"       && ev.source == "fim") return true;
            if (target == "network_connection" && ev.source == "network") return true;
            return false;
        };
        return src_ok(ls_category) && src_ok(ls_product) && src_ok(ls_service);
    }

    bool evaluate(const SigmaEvent& ev) const {
        if (!enabled) return false;
        if (!matches_source(ev)) return false;
        std::map<std::string, bool> sel_results;
        for (const auto& s : selections) sel_results[s.name] = s.evaluate(ev);
        if (!condition) {
            // Fallback: any selection matches
            for (const auto& kv : sel_results) if (kv.second) return true;
            return false;
        }
        return condition->evaluate(sel_results);
    }
};

// =============================================================================
// MINIMAL YAML SUBSET PARSER
// =============================================================================
// Sigma rules are a specific YAML subset. We implement just enough: string
// scalars, nested mappings (2-space indent), block lists (- item), and inline
// lists [a, b]. Strict YAML edge cases (block scalars with |, anchors, etc.)
// are not supported -- Sigma rules rarely use them.
// =============================================================================
class MiniYamlParser {
public:
    // Parsed node -- a scalar, mapping, or sequence
    struct Node {
        enum Kind { NONE, SCALAR, MAPPING, SEQUENCE };
        Kind kind = NONE;
        std::string scalar;
        std::map<std::string, Node> map;
        std::vector<Node> seq;
    };

    static bool parse(const std::string& text, Node& root) {
        std::vector<std::string> lines;
        std::istringstream iss(text);
        std::string line;
        while (std::getline(iss, line)) lines.push_back(line);

        size_t idx = 0;
        root = parse_block(lines, idx, 0);
        return root.kind != Node::NONE;
    }

private:
    static int leading_spaces(const std::string& s) {
        int n = 0;
        for (char c : s) { if (c == ' ') n++; else break; }
        return n;
    }

    static bool is_blank_or_comment(const std::string& s) {
        size_t i = 0;
        while (i < s.size() && s[i] == ' ') i++;
        return i >= s.size() || s[i] == '#';
    }

    static std::string strip(const std::string& s) {
        size_t a = 0, b = s.size();
        while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) a++;
        while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) b--;
        return s.substr(a, b - a);
    }

    static std::string unquote(const std::string& s) {
        if (s.size() >= 2 &&
            ((s.front() == '"' && s.back() == '"') ||
             (s.front() == '\'' && s.back() == '\''))) {
            return s.substr(1, s.size() - 2);
        }
        return s;
    }

    static std::vector<std::string> parse_inline_list(const std::string& s) {
        std::vector<std::string> out;
        // Strip [ ]
        std::string inner = s;
        if (!inner.empty() && inner.front() == '[') inner.erase(0, 1);
        if (!inner.empty() && inner.back() == ']') inner.pop_back();
        std::string cur;
        bool in_quote = false; char quote_ch = 0;
        for (char c : inner) {
            if (in_quote) { cur += c; if (c == quote_ch) in_quote = false; continue; }
            if (c == '"' || c == '\'') { in_quote = true; quote_ch = c; cur += c; continue; }
            if (c == ',') { out.push_back(unquote(strip(cur))); cur.clear(); }
            else cur += c;
        }
        if (!strip(cur).empty()) out.push_back(unquote(strip(cur)));
        return out;
    }

    static Node parse_block(const std::vector<std::string>& lines, size_t& idx, int base_indent) {
        Node node;
        while (idx < lines.size()) {
            const std::string& raw = lines[idx];
            if (is_blank_or_comment(raw)) { idx++; continue; }
            int indent = leading_spaces(raw);
            if (indent < base_indent) break;
            if (indent > base_indent && node.kind == Node::NONE) base_indent = indent;
            if (indent != base_indent) break;

            std::string content = strip(raw);

            // Sequence item
            if (!content.empty() && content[0] == '-') {
                if (node.kind == Node::NONE) node.kind = Node::SEQUENCE;
                if (node.kind != Node::SEQUENCE) break;
                std::string after = strip(content.substr(1));
                if (after.empty()) {
                    idx++;
                    Node child = parse_block(lines, idx, base_indent + 2);
                    node.seq.push_back(std::move(child));
                } else {
                    // inline scalar or inline mapping
                    Node item;
                    // Could be "key: value"
                    size_t colon = find_key_colon(after);
                    if (colon != std::string::npos) {
                        item.kind = Node::MAPPING;
                        std::string k = strip(after.substr(0, colon));
                        std::string v = strip(after.substr(colon + 1));
                        Node vnode;
                        if (v.empty()) {
                            idx++;
                            vnode = parse_block(lines, idx, base_indent + 2);
                        } else {
                            vnode.kind = Node::SCALAR;
                            if (!v.empty() && v.front() == '[') {
                                vnode.kind = Node::SEQUENCE;
                                for (auto& x : parse_inline_list(v)) {
                                    Node s; s.kind = Node::SCALAR; s.scalar = x;
                                    vnode.seq.push_back(std::move(s));
                                }
                            } else {
                                vnode.scalar = unquote(v);
                            }
                            idx++;
                        }
                        item.map[k] = std::move(vnode);
                    } else {
                        item.kind = Node::SCALAR;
                        item.scalar = unquote(after);
                        idx++;
                    }
                    node.seq.push_back(std::move(item));
                }
                continue;
            }

            // Mapping entry
            size_t colon = find_key_colon(content);
            if (colon == std::string::npos) { idx++; continue; }
            if (node.kind == Node::NONE) node.kind = Node::MAPPING;
            if (node.kind != Node::MAPPING) break;
            std::string key = strip(content.substr(0, colon));
            std::string val = strip(content.substr(colon + 1));
            Node child;
            if (val.empty()) {
                idx++;
                child = parse_block(lines, idx, base_indent + 2);
            } else if (val.front() == '[') {
                child.kind = Node::SEQUENCE;
                for (auto& x : parse_inline_list(val)) {
                    Node s; s.kind = Node::SCALAR; s.scalar = x;
                    child.seq.push_back(std::move(s));
                }
                idx++;
            } else {
                child.kind = Node::SCALAR;
                child.scalar = unquote(val);
                idx++;
            }
            node.map[key] = std::move(child);
        }
        return node;
    }

    static size_t find_key_colon(const std::string& s) {
        bool in_quote = false; char quote_ch = 0;
        for (size_t i = 0; i < s.size(); i++) {
            char c = s[i];
            if (in_quote) { if (c == quote_ch) in_quote = false; continue; }
            if (c == '"' || c == '\'') { in_quote = true; quote_ch = c; continue; }
            if (c == ':' && (i + 1 == s.size() || s[i + 1] == ' ' || s[i + 1] == '\t')) return i;
        }
        return std::string::npos;
    }
};

// =============================================================================
// SIGMA ENGINE
// =============================================================================
class SigmaEngine {
public:
    using HitCallback = std::function<void(const SigmaHit&)>;

    struct Config {
        bool        enabled = true;
        std::string rules_dir = "sigma_rules";
        int         reload_interval_s = 300;
        size_t      max_rules = 10000;
    };

    explicit SigmaEngine(const Config& cfg, HitCallback cb = nullptr)
        : config_(cfg), hit_cb_(std::move(cb)),
          last_reload_(std::chrono::steady_clock::now())
    {
        if (config_.enabled) load_all_rules();
    }

    void set_callback(HitCallback cb) { hit_cb_ = std::move(cb); }

    // Main evaluation hook -- call from server dispatcher with a SigmaEvent.
    void evaluate(const SigmaEvent& ev) {
        if (!config_.enabled) return;
        std::vector<SigmaHit> fired;
        {
            std::shared_lock<std::shared_mutex> lock(rw_mutex_);
            total_evaluations_++;
            for (const auto& rule : rules_) {
                if (rule.evaluate(ev)) {
                    SigmaHit hit;
                    hit.rule_id       = rule.id;
                    hit.rule_title    = rule.title;
                    hit.severity      = rule.level.empty() ? "medium" : rule.level;
                    hit.tags          = rule.tags;
                    hit.mitre_id      = rule.mitre_id;
                    hit.description   = rule.description;
                    hit.device_id     = ev.device_id;
                    hit.timestamp_ms  = ev.timestamp_ms;
                    // Grab first matching field as context
                    for (const auto& sel : rule.selections) {
                        if (sel.evaluate(ev) && !sel.matchers.empty()) {
                            hit.matched_field = sel.matchers[0].field;
                            hit.matched_value = ev.get(hit.matched_field);
                            break;
                        }
                    }
                    fired.push_back(std::move(hit));
                    total_hits_++;
                }
            }
        }
        if (hit_cb_) for (const auto& h : fired) hit_cb_(h);
    }

    bool check_and_reload() {
        if (!config_.enabled) return false;
        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(now - last_reload_).count()
                < config_.reload_interval_s) return false;
        last_reload_ = now;

        bool changed = false;
        try {
            size_t file_count = 0;
            for (const auto& e : fs::directory_iterator(config_.rules_dir)) {
                std::string ext = e.path().extension().string();
                std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
                if (ext != ".yml" && ext != ".yaml") continue;
                file_count++;
                auto mt = fs::last_write_time(e.path());
                auto it = file_mtimes_.find(e.path().string());
                if (it == file_mtimes_.end() || it->second != mt) { changed = true; break; }
            }
            if (!changed && file_count != file_mtimes_.size()) changed = true;
        } catch (...) {}

        if (changed) { load_all_rules(); return true; }
        return false;
    }

    size_t rule_count() const {
        std::shared_lock<std::shared_mutex> lock(rw_mutex_);
        return rules_.size();
    }
    size_t total_evaluations() const { return total_evaluations_.load(); }
    size_t total_hits() const        { return total_hits_.load(); }

private:
    Config config_;
    HitCallback hit_cb_;
    mutable std::shared_mutex rw_mutex_;
    std::vector<SigmaRule> rules_;
    std::map<std::string, fs::file_time_type> file_mtimes_;
    std::chrono::steady_clock::time_point last_reload_;
    std::atomic<size_t> total_evaluations_{0};
    std::atomic<size_t> total_hits_{0};

    void load_all_rules() {
        std::vector<SigmaRule> new_rules;
        std::map<std::string, fs::file_time_type> new_mtimes;

        try {
            if (!fs::exists(config_.rules_dir)) fs::create_directories(config_.rules_dir);
            for (const auto& e : fs::directory_iterator(config_.rules_dir)) {
                if (new_rules.size() >= config_.max_rules) break;
                std::string ext = e.path().extension().string();
                std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
                if (ext != ".yml" && ext != ".yaml") continue;

                std::ifstream f(e.path());
                if (!f.is_open()) continue;
                std::stringstream ss; ss << f.rdbuf();
                SigmaRule r;
                if (parse_rule(ss.str(), r)) {
                    new_rules.push_back(std::move(r));
                    try { new_mtimes[e.path().string()] = fs::last_write_time(e.path()); } catch (...) {}
                }
            }
        } catch (...) {}

        std::unique_lock<std::shared_mutex> lock(rw_mutex_);
        rules_ = std::move(new_rules);
        file_mtimes_ = std::move(new_mtimes);
    }

    static bool parse_rule(const std::string& yaml, SigmaRule& out) {
        MiniYamlParser::Node root;
        if (!MiniYamlParser::parse(yaml, root) || root.kind != MiniYamlParser::Node::MAPPING)
            return false;

        auto scalar_at = [&](const std::string& k) -> std::string {
            auto it = root.map.find(k);
            if (it == root.map.end() || it->second.kind != MiniYamlParser::Node::SCALAR) return "";
            return it->second.scalar;
        };

        out.id          = scalar_at("id");
        out.title       = scalar_at("title");
        out.description = scalar_at("description");
        out.author      = scalar_at("author");
        out.level       = scalar_at("level");
        out.status      = scalar_at("status");

        // tags
        auto tag_it = root.map.find("tags");
        if (tag_it != root.map.end() && tag_it->second.kind == MiniYamlParser::Node::SEQUENCE) {
            for (auto& n : tag_it->second.seq) {
                if (n.kind == MiniYamlParser::Node::SCALAR) {
                    out.tags.push_back(n.scalar);
                    // Extract MITRE technique from attack.tNNNN
                    std::string lower = n.scalar;
                    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
                    if (lower.rfind("attack.t", 0) == 0) {
                        std::string mid = n.scalar.substr(7); // strip "attack."
                        std::transform(mid.begin(), mid.end(), mid.begin(), ::toupper);
                        out.mitre_id = mid;
                    }
                }
            }
        }

        // logsource
        auto ls_it = root.map.find("logsource");
        if (ls_it != root.map.end() && ls_it->second.kind == MiniYamlParser::Node::MAPPING) {
            auto& m = ls_it->second.map;
            if (m.count("product"))  out.ls_product  = m.at("product").scalar;
            if (m.count("category")) out.ls_category = m.at("category").scalar;
            if (m.count("service"))  out.ls_service  = m.at("service").scalar;
        }

        // detection
        auto det_it = root.map.find("detection");
        if (det_it == root.map.end() || det_it->second.kind != MiniYamlParser::Node::MAPPING)
            return false;

        for (const auto& kv : det_it->second.map) {
            if (kv.first == "condition") {
                if (kv.second.kind == MiniYamlParser::Node::SCALAR) {
                    out.condition_expr = kv.second.scalar;
                    out.condition = std::make_unique<SigmaCondition>(kv.second.scalar);
                }
                continue;
            }
            if (kv.first == "timeframe") continue; // unsupported, ignore silently
            if (kv.second.kind != MiniYamlParser::Node::MAPPING) continue;

            SigmaSelection sel;
            sel.name = kv.first;
            for (const auto& fkv : kv.second.map) {
                FieldMatcher m = build_matcher(fkv.first, fkv.second);
                if (!m.field.empty()) sel.matchers.push_back(std::move(m));
            }
            if (!sel.matchers.empty()) out.selections.push_back(std::move(sel));
        }
        return !out.selections.empty();
    }

    static FieldMatcher build_matcher(const std::string& field_spec, const MiniYamlParser::Node& val) {
        FieldMatcher m;
        // field_spec format: "FieldName|modifier|modifier"
        std::vector<std::string> parts;
        std::string cur;
        for (char c : field_spec) {
            if (c == '|') { parts.push_back(cur); cur.clear(); }
            else cur += c;
        }
        if (!cur.empty()) parts.push_back(cur);
        if (parts.empty()) return m;
        m.field = parts[0];

        for (size_t i = 1; i < parts.size(); i++) {
            const std::string& mod = parts[i];
            if (mod == "contains")   m.modifier = SigmaModifier::CONTAINS;
            else if (mod == "startswith") m.modifier = SigmaModifier::STARTSWITH;
            else if (mod == "endswith")   m.modifier = SigmaModifier::ENDSWITH;
            else if (mod == "re" || mod == "regex") m.modifier = SigmaModifier::REGEX;
            else if (mod == "all")        m.all_values = true;
            else if (mod == "cased")      m.case_insensitive = false;
        }

        // Collect values
        if (val.kind == MiniYamlParser::Node::SCALAR) {
            m.values.push_back(val.scalar);
        } else if (val.kind == MiniYamlParser::Node::SEQUENCE) {
            for (const auto& n : val.seq) {
                if (n.kind == MiniYamlParser::Node::SCALAR) m.values.push_back(n.scalar);
            }
        }

        // Compile regexes if needed
        if (m.modifier == SigmaModifier::REGEX) {
            for (const auto& v : m.values) {
                try {
                    auto flags = std::regex_constants::ECMAScript | std::regex_constants::optimize;
                    if (m.case_insensitive) flags |= std::regex_constants::icase;
                    m.compiled.emplace_back(v, flags);
                } catch (...) {
                    m.compiled.emplace_back("(?!)");
                }
            }
        }
        return m;
    }
};

#endif
