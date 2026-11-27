// =============================================================================
// sigma_engine.h -- Phase 16 stub, implemented as v5.2 groundwork
// -----------------------------------------------------------------------------
// Minimal Sigma YAML subset: load rules from a directory and evaluate them
// against a raw log line or a small field map. Header-only, no YAML library;
// vcpkg CI installs only OpenSSL and libpq, so a hand-rolled subset is the
// path that stays Windows-buildable.
//
// Supported (this groundwork):
//   - One mapping per file, or several documents separated by `---`
//   - Maps, lists, plain / single-quoted / double-quoted scalars, `#` comments,
//     and wrapped plain scalars (common for `description:`)
//   - Named selections as field maps: `Field: value` or `Field|modifier:`
//     with modifiers contains / startswith / endswith / re
//   - A list of values under one field is OR; fields in one selection are AND
//   - Keyword-style selections: a list of strings matched as substrings of
//     the raw line (and of any supplied field values) -- this is the format
//     already used by server/config/sigma/*.yml
//   - condition: and / or / not, parentheses, `1 of` / `all of` (also
//     `1-of` / `all-of`) over a name, a prefix glob (`selection*`), or `them`
//   - Caps: 10 000 rules, 64 KiB per file, 4 KiB per pattern
//   - Case-insensitive equals / contains / startswith / endswith
//   - `|re` is ECMAScript, case-sensitive, compiled at load (bad patterns skip
//     the rule)
//
// Not supported (honest subset -- see the PR draft):
//   - Anchors, aliases, merge keys, folded (`>`) / literal (`|`) scalars
//   - Tabs for indent, modifier chains (`|contains|all`), `|cidr`,
//     `|base64offset`, `|wide`, `|all`, `|re|i`, fieldref
//   - Aggregations (count, near, timeframe), correlation, wildcards other
//     than a trailing `*` on `1 of` / `all of` names
//   - Logsource filtering at evaluate time (logsource is stored, not applied)
//   - Auto-reload threads (start_auto_reload is a documented no-op)
// Live wiring: server.cpp loads this via SigmaPipeline when sigma_enabled
// is true (default false) and raises hits on the existing AlertEngine.
// =============================================================================
#pragma once

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <map>
#include <mutex>
#include <regex>
#include <shared_mutex>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace seahorse::sigma {

struct SigmaRule {
    std::string id;
    std::string title;
    std::string level;
    std::string logsource;
    std::string condition;
    std::vector<std::string> keywords;         // keyword-style selections, if any
    std::vector<std::string> selection_names;
};

struct SigmaHit {
    std::string rule_id;
    std::string title;
    std::string level;
    int         device_id = 0;
};

struct SigmaEvent {
    std::string raw;
    // Keys are matched case-insensitively; store any case, lookup lowercases.
    std::map<std::string, std::string> fields;
};

struct LoadError {
    std::string path;
    std::string message;
    int line = 0;
};

namespace detail {

inline constexpr size_t kMaxRules       = 10000;
inline constexpr size_t kMaxFileBytes   = 64 * 1024;
inline constexpr size_t kMaxPatternBytes = 4 * 1024;

inline std::string to_lower(std::string s) {
    for (char& c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

inline std::string ltrim(const std::string& s) {
    size_t i = 0;
    while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) ++i;
    return s.substr(i);
}

inline std::string rtrim(const std::string& s) {
    size_t i = s.size();
    while (i > 0 && (s[i - 1] == ' ' || s[i - 1] == '\t' || s[i - 1] == '\r')) --i;
    return s.substr(0, i);
}

inline std::string trim(const std::string& s) { return rtrim(ltrim(s)); }

inline bool ci_equals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i])))
            return false;
    }
    return true;
}

inline bool ci_contains(const std::string& hay, const std::string& needle) {
    if (needle.empty()) return true;
    if (hay.size() < needle.size()) return false;
    auto h = to_lower(hay);
    auto n = to_lower(needle);
    return h.find(n) != std::string::npos;
}

inline bool ci_starts(const std::string& hay, const std::string& needle) {
    if (hay.size() < needle.size()) return false;
    for (size_t i = 0; i < needle.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(hay[i])) !=
            std::tolower(static_cast<unsigned char>(needle[i])))
            return false;
    }
    return true;
}

inline bool ci_ends(const std::string& hay, const std::string& needle) {
    if (hay.size() < needle.size()) return false;
    size_t off = hay.size() - needle.size();
    for (size_t i = 0; i < needle.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(hay[off + i])) !=
            std::tolower(static_cast<unsigned char>(needle[i])))
            return false;
    }
    return true;
}

// ---- tiny YAML subset ------------------------------------------------------

struct YamlVal {
    enum Type { kNull, kScalar, kList, kMap } type = kNull;
    std::string scalar;
    std::vector<YamlVal> list;
    std::vector<std::pair<std::string, YamlVal>> map;

    const YamlVal* map_get(const std::string& key) const {
        for (const auto& kv : map)
            if (kv.first == key) return &kv.second;
        return nullptr;
    }
    std::string map_str(const std::string& key) const {
        const YamlVal* v = map_get(key);
        if (!v || v->type != kScalar) return {};
        return v->scalar;
    }
};

struct Line {
    int indent = 0;
    int lineno = 0;
    std::string text; // comment-stripped, rtrimmed, indent removed
};

struct ParseErr : std::exception {
    std::string msg;
    int line = 0;
    ParseErr(std::string m, int l) : msg(std::move(m)), line(l) {}
    const char* what() const noexcept override { return msg.c_str(); }
};

// Strip a `#` comment that is not inside quotes.
inline std::string strip_comment(const std::string& raw) {
    bool in_s = false, in_d = false;
    for (size_t i = 0; i < raw.size(); ++i) {
        char c = raw[i];
        if (in_s) {
            if (c == '\'' && i + 1 < raw.size() && raw[i + 1] == '\'') { ++i; continue; }
            if (c == '\'') in_s = false;
        } else if (in_d) {
            if (c == '\\' && i + 1 < raw.size()) { ++i; continue; }
            if (c == '"') in_d = false;
        } else {
            if (c == '\'') in_s = true;
            else if (c == '"') in_d = true;
            else if (c == '#') return rtrim(raw.substr(0, i));
        }
    }
    return rtrim(raw);
}

inline std::string unquote(const std::string& s, int lineno) {
    if (s.empty()) return s;
    if (s.front() == '\'' && s.back() == '\'' && s.size() >= 2) {
        std::string out;
        for (size_t i = 1; i + 1 < s.size(); ++i) {
            if (s[i] == '\'' && i + 1 + 1 <= s.size() - 1 && s[i + 1] == '\'') {
                out.push_back('\'');
                ++i;
            } else {
                out.push_back(s[i]);
            }
        }
        return out;
    }
    if (s.front() == '"' && s.back() == '"' && s.size() >= 2) {
        std::string out;
        for (size_t i = 1; i + 1 < s.size(); ++i) {
            if (s[i] == '\\' && i + 1 + 1 <= s.size() - 1) {
                char n = s[i + 1];
                if (n == 'n') out.push_back('\n');
                else if (n == 't') out.push_back('\t');
                else if (n == 'r') out.push_back('\r');
                else if (n == '\\' || n == '"') out.push_back(n);
                else out.push_back(n);
                ++i;
            } else {
                out.push_back(s[i]);
            }
        }
        return out;
    }
    if ((s.front() == '|' || s.front() == '>') && (s.size() == 1 || s[1] == ' ' || s[1] == '+' || s[1] == '-'))
        throw ParseErr("folded/literal block scalars are not supported", lineno);
    return s;
}

inline std::vector<Line> lex_lines(const std::string& src) {
    std::vector<Line> out;
    std::istringstream in(src);
    std::string raw;
    int lineno = 0;
    while (std::getline(in, raw)) {
        ++lineno;
        if (!raw.empty() && raw.back() == '\r') raw.pop_back();
        int indent = 0;
        while (indent < static_cast<int>(raw.size()) && raw[static_cast<size_t>(indent)] == ' ')
            ++indent;
        if (indent < static_cast<int>(raw.size()) && raw[static_cast<size_t>(indent)] == '\t')
            throw ParseErr("tabs are not allowed for indent", lineno);
        std::string body = strip_comment(raw.substr(static_cast<size_t>(indent)));
        if (body.empty()) continue;
        if (body == "---" || body == "...") continue;
        Line ln;
        ln.indent = indent;
        ln.lineno = lineno;
        ln.text = body;
        out.push_back(std::move(ln));
    }
    return out;
}

// Parse one node starting at `i` whose indent is `base`. Advances `i`.
inline YamlVal parse_node(const std::vector<Line>& ls, size_t& i, int base);

inline YamlVal parse_scalar(const std::string& s, int lineno) {
    YamlVal v;
    v.type = YamlVal::kScalar;
    v.scalar = unquote(trim(s), lineno);
    return v;
}

inline YamlVal parse_list(const std::vector<Line>& ls, size_t& i, int base) {
    YamlVal v;
    v.type = YamlVal::kList;
    while (i < ls.size() && ls[i].indent == base && !ls[i].text.empty() && ls[i].text[0] == '-') {
        const Line& ln = ls[i];
        std::string rest = trim(ln.text.substr(1));
        ++i;
        if (rest.empty()) {
            if (i < ls.size() && ls[i].indent > base)
                v.list.push_back(parse_node(ls, i, ls[i].indent));
            else
                v.list.emplace_back();
            continue;
        }
        // `- key: value`  (inline map item) or `- scalar`
        auto colon = std::string::npos;
        bool in_s = false, in_d = false;
        for (size_t c = 0; c < rest.size(); ++c) {
            char ch = rest[c];
            if (in_s) { if (ch == '\'') in_s = false; }
            else if (in_d) { if (ch == '\\' && c + 1 < rest.size()) ++c; else if (ch == '"') in_d = false; }
            else if (ch == '\'') in_s = true;
            else if (ch == '"') in_d = true;
            else if (ch == ':') { colon = c; break; }
        }
        bool looks_like_key = false;
        if (colon != std::string::npos) {
            std::string k = trim(rest.substr(0, colon));
            looks_like_key = !k.empty() && k.front() != '\'' && k.front() != '"' &&
                             k.find(' ') == std::string::npos;
        }
        if (looks_like_key) {
            YamlVal item;
            item.type = YamlVal::kMap;
            std::string key = unquote(trim(rest.substr(0, colon)), ln.lineno);
            std::string after = trim(rest.substr(colon + 1));
            YamlVal child;
            if (after.empty()) {
                if (i < ls.size() && ls[i].indent > base)
                    child = parse_node(ls, i, ls[i].indent);
            } else {
                child = parse_scalar(after, ln.lineno);
            }
            item.map.emplace_back(std::move(key), std::move(child));
            // Continuation keys of the same list item (indent > base, not a dash at base)
            while (i < ls.size() && ls[i].indent > base &&
                   (ls[i].text.empty() || ls[i].text[0] != '-' || ls[i].indent > base + 2)) {
                // If the continuation is a nested structure under the first key, parse_node
                // already consumed it. Remaining same-indent keys belong to this map item.
                // Detect `key:` lines whose indent is the indent of the first key column.
                int key_indent = -1;
                // Reconstruct: the first key sat at `base` plus "- ". Approximate
                // sibling keys as indent > base and text not starting with '-'.
                const Line& nln = ls[i];
                if (!nln.text.empty() && nln.text[0] == '-') break;
                auto col2 = nln.text.find(':');
                if (col2 == std::string::npos) break;
                if (key_indent < 0) key_indent = nln.indent;
                if (nln.indent != key_indent) {
                    // nested under previous key -- shouldn't happen if previous was scalar
                    break;
                }
                std::string k2 = unquote(trim(nln.text.substr(0, col2)), nln.lineno);
                std::string a2 = trim(nln.text.substr(col2 + 1));
                ++i;
                YamlVal c2;
                if (a2.empty()) {
                    if (i < ls.size() && ls[i].indent > nln.indent)
                        c2 = parse_node(ls, i, ls[i].indent);
                } else {
                    c2 = parse_scalar(a2, nln.lineno);
                }
                item.map.emplace_back(std::move(k2), std::move(c2));
            }
            v.list.push_back(std::move(item));
        } else {
            v.list.push_back(parse_scalar(rest, ln.lineno));
        }
    }
    return v;
}

inline YamlVal parse_map(const std::vector<Line>& ls, size_t& i, int base) {
    YamlVal v;
    v.type = YamlVal::kMap;
    while (i < ls.size() && ls[i].indent == base) {
        const Line& ln = ls[i];
        if (!ln.text.empty() && ln.text[0] == '-')
            throw ParseErr("unexpected list item in a mapping", ln.lineno);
        auto colon = std::string::npos;
        bool in_s = false, in_d = false;
        for (size_t c = 0; c < ln.text.size(); ++c) {
            char ch = ln.text[c];
            if (in_s) { if (ch == '\'') in_s = false; }
            else if (in_d) { if (ch == '\\' && c + 1 < ln.text.size()) ++c; else if (ch == '"') in_d = false; }
            else if (ch == '\'') in_s = true;
            else if (ch == '"') in_d = true;
            else if (ch == ':') { colon = c; break; }
        }
        if (colon == std::string::npos)
            throw ParseErr("expected 'key:' in mapping", ln.lineno);
        std::string key = unquote(trim(ln.text.substr(0, colon)), ln.lineno);
        if (key.empty()) throw ParseErr("empty mapping key", ln.lineno);
        std::string after = trim(ln.text.substr(colon + 1));
        ++i;
        YamlVal child;
        if (after.empty()) {
            if (i < ls.size() && ls[i].indent > base)
                child = parse_node(ls, i, ls[i].indent);
            else {
                child.type = YamlVal::kScalar;
                child.scalar.clear();
            }
        } else {
            child = parse_scalar(after, ln.lineno);
            // YAML plain scalars may wrap onto more-indented continuation
            // lines (common for Sigma `description:`). Join with a space.
            while (i < ls.size() && ls[i].indent > base) {
                const std::string& tx = ls[i].text;
                if (!tx.empty() && tx[0] == '-') break;
                child.scalar += " ";
                child.scalar += tx;
                ++i;
            }
        }
        v.map.emplace_back(std::move(key), std::move(child));
    }
    return v;
}

inline YamlVal parse_node(const std::vector<Line>& ls, size_t& i, int base) {
    if (i >= ls.size()) return {};
    if (ls[i].indent != base)
        throw ParseErr("inconsistent indent", ls[i].lineno);
    if (!ls[i].text.empty() && ls[i].text[0] == '-')
        return parse_list(ls, i, base);
    return parse_map(ls, i, base);
}

inline std::vector<YamlVal> parse_yaml_docs(const std::string& src) {
    auto ls = lex_lines(src);
    std::vector<YamlVal> docs;
    size_t i = 0;
    while (i < ls.size()) {
        int base = ls[i].indent;
        docs.push_back(parse_node(ls, i, base));
        // If leftover lines are shallower/deeper unexpectedly, start a new doc
        // only when we still have input (e.g. a second top-level mapping).
    }
    return docs;
}

// ---- selectors + condition -------------------------------------------------

enum class MatchOp { Equals, Contains, StartsWith, EndsWith, Regex };

struct FieldMatcher {
    std::string field; // lowercased; empty = raw/keyword
    MatchOp op = MatchOp::Equals;
    std::vector<std::string> values;
    std::vector<std::regex> regexes;
};

struct Selection {
    std::string name;
    bool keyword_mode = false;
    std::vector<std::string> keywords;
    std::vector<FieldMatcher> fields;
};

struct CondNode {
    enum Kind { And, Or, Not, Sel, OneOf, AllOf, LitTrue, LitFalse } kind = LitFalse;
    std::string name;          // selection name, or glob prefix (without *)
    bool prefix = false;       // true if name was `foo*`
    bool them = false;
    std::vector<CondNode> kids;
};

inline bool parse_modifier(const std::string& raw_key, std::string& field, MatchOp& op) {
    auto bar = raw_key.find('|');
    if (bar == std::string::npos) {
        field = to_lower(raw_key);
        op = MatchOp::Equals;
        return true;
    }
    field = to_lower(raw_key.substr(0, bar));
    std::string mod = to_lower(trim(raw_key.substr(bar + 1)));
    // Reject modifier chains (contains|all, re|i, ...)
    if (mod.find('|') != std::string::npos) return false;
    if (mod == "contains") op = MatchOp::Contains;
    else if (mod == "startswith") op = MatchOp::StartsWith;
    else if (mod == "endswith") op = MatchOp::EndsWith;
    else if (mod == "re") op = MatchOp::Regex;
    else return false;
    return true;
}

inline std::vector<std::string> collect_scalars(const YamlVal& v, int lineno, std::string& err) {
    std::vector<std::string> out;
    if (v.type == YamlVal::kScalar) {
        if (v.scalar.size() > kMaxPatternBytes) {
            err = "pattern exceeds 4 KiB cap";
            return {};
        }
        out.push_back(v.scalar);
        return out;
    }
    if (v.type == YamlVal::kList) {
        for (const auto& item : v.list) {
            if (item.type != YamlVal::kScalar) {
                err = "selection lists must be scalars";
                return {};
            }
            if (item.scalar.size() > kMaxPatternBytes) {
                err = "pattern exceeds 4 KiB cap";
                return {};
            }
            out.push_back(item.scalar);
        }
        return out;
    }
    (void)lineno;
    err = "expected a scalar or a list of scalars";
    return {};
}

inline bool compile_selection(const std::string& name, const YamlVal& v,
                              Selection& out, std::string& err, int lineno) {
    out.name = name;
    if (v.type == YamlVal::kList) {
        // Keyword-style (legacy server/config/sigma samples).
        bool all_scalar = true;
        for (const auto& item : v.list)
            if (item.type != YamlVal::kScalar) all_scalar = false;
        if (all_scalar) {
            out.keyword_mode = true;
            out.keywords = collect_scalars(v, lineno, err);
            return err.empty();
        }
        err = "keyword selections must be a list of strings";
        return false;
    }
    if (v.type == YamlVal::kMap) {
        out.keyword_mode = false;
        for (const auto& kv : v.map) {
            FieldMatcher fm;
            if (!parse_modifier(kv.first, fm.field, fm.op)) {
                err = "unsupported field modifier on '" + kv.first + "'";
                return false;
            }
            auto vals = collect_scalars(kv.second, lineno, err);
            if (!err.empty()) return false;
            if (fm.op == MatchOp::Regex) {
                for (const auto& pat : vals) {
                    try {
                        fm.regexes.emplace_back(pat, std::regex_constants::ECMAScript);
                    } catch (const std::regex_error& e) {
                        err = "invalid |re pattern: " + std::string(e.what());
                        return false;
                    }
                }
            } else {
                fm.values = std::move(vals);
            }
            out.fields.push_back(std::move(fm));
        }
        return true;
    }
    if (v.type == YamlVal::kScalar) {
        out.keyword_mode = true;
        if (v.scalar.size() > kMaxPatternBytes) {
            err = "pattern exceeds 4 KiB cap";
            return false;
        }
        out.keywords.push_back(v.scalar);
        return true;
    }
    err = "selection must be a map or a list";
    return false;
}

// Condition tokenizer
enum class CTok { Ident, And, Or, Not, LParen, RParen, OneOf, AllOf, End, Err };

struct Tok {
    CTok kind = CTok::Err;
    std::string text;
};

inline std::vector<Tok> lex_condition(const std::string& s, std::string& err) {
    std::vector<Tok> out;
    size_t i = 0;
    auto skip = [&]() {
        while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i]))) ++i;
    };
    auto word = [&]() -> std::string {
        size_t a = i;
        while (i < s.size() && (std::isalnum(static_cast<unsigned char>(s[i])) ||
                                s[i] == '_' || s[i] == '-' || s[i] == '*'))
            ++i;
        return s.substr(a, i - a);
    };
    while (true) {
        skip();
        if (i >= s.size()) { out.push_back({CTok::End, {}}); break; }
        if (s[i] == '(') { ++i; out.push_back({CTok::LParen, {}}); continue; }
        if (s[i] == ')') { ++i; out.push_back({CTok::RParen, {}}); continue; }
        if (!(std::isalnum(static_cast<unsigned char>(s[i])) || s[i] == '_' || s[i] == '*')) {
            err = "unexpected character in condition";
            return {};
        }
        std::string w = word();
        std::string lw = to_lower(w);
        if (lw == "and") { out.push_back({CTok::And, {}}); continue; }
        if (lw == "or")  { out.push_back({CTok::Or, {}}); continue; }
        if (lw == "not") { out.push_back({CTok::Not, {}}); continue; }
        // `1 of` / `1-of` / `all of` / `all-of`
        if (lw == "1-of" || lw == "all-of") {
            out.push_back({lw == "1-of" ? CTok::OneOf : CTok::AllOf, {}});
            continue;
        }
        if (lw == "1" || lw == "all") {
            skip();
            if (i < s.size()) {
                size_t save = i;
                std::string nxt = word();
                if (to_lower(nxt) == "of") {
                    out.push_back({lw == "1" ? CTok::OneOf : CTok::AllOf, {}});
                    continue;
                }
                i = save;
            }
        }
        out.push_back({CTok::Ident, w});
    }
    return out;
}

struct CondParser {
    std::vector<Tok> toks;
    size_t i = 0;
    std::string err;

    const Tok& peek() const { return toks[i]; }
    const Tok& take() { return toks[i++]; }

    CondNode parse_or() {
        CondNode left = parse_and();
        if (!err.empty()) return {};
        if (peek().kind != CTok::Or) return left;
        CondNode n;
        n.kind = CondNode::Or;
        n.kids.push_back(std::move(left));
        while (peek().kind == CTok::Or) {
            take();
            n.kids.push_back(parse_and());
            if (!err.empty()) return {};
        }
        return n;
    }
    CondNode parse_and() {
        CondNode left = parse_not();
        if (!err.empty()) return {};
        if (peek().kind != CTok::And) return left;
        CondNode n;
        n.kind = CondNode::And;
        n.kids.push_back(std::move(left));
        while (peek().kind == CTok::And) {
            take();
            n.kids.push_back(parse_not());
            if (!err.empty()) return {};
        }
        return n;
    }
    CondNode parse_not() {
        if (peek().kind == CTok::Not) {
            take();
            CondNode n;
            n.kind = CondNode::Not;
            n.kids.push_back(parse_not());
            return n;
        }
        return parse_primary();
    }
    CondNode parse_primary() {
        if (peek().kind == CTok::LParen) {
            take();
            CondNode n = parse_or();
            if (peek().kind != CTok::RParen) {
                err = "missing ')' in condition";
                return {};
            }
            take();
            return n;
        }
        if (peek().kind == CTok::OneOf || peek().kind == CTok::AllOf) {
            bool one = peek().kind == CTok::OneOf;
            take();
            if (peek().kind != CTok::Ident) {
                err = "expected a name or glob after 1 of / all of";
                return {};
            }
            CondNode n;
            n.kind = one ? CondNode::OneOf : CondNode::AllOf;
            std::string name = take().text;
            if (to_lower(name) == "them") {
                n.them = true;
            } else if (!name.empty() && name.back() == '*') {
                n.prefix = true;
                n.name = name.substr(0, name.size() - 1);
            } else {
                n.name = name;
            }
            return n;
        }
        if (peek().kind == CTok::Ident) {
            CondNode n;
            n.kind = CondNode::Sel;
            n.name = take().text;
            return n;
        }
        err = "expected a selection name or '(' in condition";
        return {};
    }
};

inline bool compile_condition(const std::string& text, CondNode& out, std::string& err) {
    auto toks = lex_condition(text, err);
    if (!err.empty()) return false;
    CondParser p;
    p.toks = std::move(toks);
    out = p.parse_or();
    if (!p.err.empty()) { err = p.err; return false; }
    if (p.peek().kind != CTok::End) { err = "trailing tokens in condition"; return false; }
    return true;
}

inline const std::string* field_lookup(const SigmaEvent& ev, const std::string& key_lc) {
    if (key_lc.empty() || key_lc == "_raw" || key_lc == "message") {
        return &ev.raw;
    }
    for (const auto& kv : ev.fields) {
        if (to_lower(kv.first) == key_lc) return &kv.second;
    }
    // Convenience: if the caller only supplied raw, no structured fields.
    return nullptr;
}

inline bool match_one(const FieldMatcher& fm, const std::string& value) {
    if (fm.op == MatchOp::Regex) {
        for (const auto& rx : fm.regexes) {
            try {
                if (std::regex_search(value, rx)) return true;
            } catch (const std::regex_error&) {
                continue;
            }
        }
        return false;
    }
    for (const auto& pat : fm.values) {
        switch (fm.op) {
        case MatchOp::Equals:     if (ci_equals(value, pat)) return true; break;
        case MatchOp::Contains:   if (ci_contains(value, pat)) return true; break;
        case MatchOp::StartsWith: if (ci_starts(value, pat)) return true; break;
        case MatchOp::EndsWith:   if (ci_ends(value, pat)) return true; break;
        default: break;
        }
    }
    return false;
}

inline bool selection_matches(const Selection& sel, const SigmaEvent& ev) {
    if (sel.keyword_mode) {
        if (sel.keywords.empty()) return false;
        auto hay_ok = [&](const std::string& hay) {
            for (const auto& kw : sel.keywords)
                if (ci_contains(hay, kw)) return true;
            return false;
        };
        if (hay_ok(ev.raw)) return true;
        for (const auto& kv : ev.fields)
            if (hay_ok(kv.second)) return true;
        return false;
    }
    if (sel.fields.empty()) return false;
    for (const auto& fm : sel.fields) {
        const std::string* val = field_lookup(ev, fm.field);
        if (!val) return false;
        std::string use = *val;
        if (use.size() > kMaxPatternBytes) use.resize(kMaxPatternBytes);
        if (!match_one(fm, use)) return false;
    }
    return true;
}

struct CompiledRule {
    SigmaRule meta;
    std::vector<Selection> selections;
    CondNode cond;
};

inline bool cond_eval(const CondNode& n, const std::vector<char>& hit,
                      const std::vector<Selection>& sels) {
    auto index_of = [&](const std::string& name) -> int {
        for (size_t i = 0; i < sels.size(); ++i)
            if (sels[i].name == name) return static_cast<int>(i);
        return -1;
    };
    switch (n.kind) {
    case CondNode::LitTrue:  return true;
    case CondNode::LitFalse: return false;
    case CondNode::Sel: {
        int ix = index_of(n.name);
        return ix >= 0 && hit[static_cast<size_t>(ix)];
    }
    case CondNode::Not:
        return n.kids.empty() ? false : !cond_eval(n.kids[0], hit, sels);
    case CondNode::And:
        for (const auto& k : n.kids)
            if (!cond_eval(k, hit, sels)) return false;
        return !n.kids.empty();
    case CondNode::Or:
        for (const auto& k : n.kids)
            if (cond_eval(k, hit, sels)) return true;
        return false;
    case CondNode::OneOf:
    case CondNode::AllOf: {
        bool any = false, all = true, saw = false;
        for (size_t i = 0; i < sels.size(); ++i) {
            bool include = false;
            if (n.them) include = true;
            else if (n.prefix) include = ci_starts(sels[i].name, n.name);
            else include = sels[i].name == n.name;
            if (!include) continue;
            saw = true;
            if (hit[i]) any = true;
            else all = false;
        }
        if (!saw) return false;
        return n.kind == CondNode::OneOf ? any : all;
    }
    }
    return false;
}

inline bool compile_rule_doc(const YamlVal& doc, CompiledRule& out, std::string& err) {
    if (doc.type != YamlVal::kMap) {
        err = "rule document must be a mapping";
        return false;
    }
    if (doc.map_str("disabled") == "true" || doc.map_str("disabled") == "yes") {
        err = "rule is disabled";
        return false;
    }
    out.meta.title = doc.map_str("title");
    out.meta.id    = doc.map_str("id");
    out.meta.level = doc.map_str("level");
    if (out.meta.level.empty()) out.meta.level = "medium";
    if (const YamlVal* ls = doc.map_get("logsource")) {
        if (ls->type == YamlVal::kScalar) out.meta.logsource = ls->scalar;
        else if (ls->type == YamlVal::kMap) {
            std::string p = ls->map_str("product");
            std::string c = ls->map_str("category");
            std::string s = ls->map_str("service");
            if (!p.empty()) out.meta.logsource = p;
            if (!c.empty()) out.meta.logsource += (out.meta.logsource.empty() ? "" : "/") + c;
            if (!s.empty()) out.meta.logsource += (out.meta.logsource.empty() ? "" : "/") + s;
        }
    }
    const YamlVal* det = doc.map_get("detection");
    if (!det || det->type != YamlVal::kMap) {
        err = "missing detection mapping";
        return false;
    }
    std::string cond_text;
    for (const auto& kv : det->map) {
        if (kv.first == "condition") {
            if (kv.second.type != YamlVal::kScalar) {
                err = "condition must be a string";
                return false;
            }
            cond_text = kv.second.scalar;
            continue;
        }
        if (kv.first == "timeframe") continue;
        Selection sel;
        if (!compile_selection(kv.first, kv.second, sel, err, 0)) return false;
        out.meta.selection_names.push_back(kv.first);
        if (sel.keyword_mode) {
            for (const auto& kw : sel.keywords) out.meta.keywords.push_back(kw);
        }
        out.selections.push_back(std::move(sel));
    }
    if (out.selections.empty()) {
        err = "detection has no selections";
        return false;
    }
    if (cond_text.empty()) {
        // Default: the first selection must match (common for simple samples).
        cond_text = out.selections.front().name;
    }
    out.meta.condition = cond_text;
    if (!compile_condition(cond_text, out.cond, err)) return false;
    return true;
}

} // namespace detail

class SigmaEngine {
public:
    size_t load_directory(const std::filesystem::path& dir) {
        std::unique_lock<std::shared_mutex> lock(mu_);
        size_t added = 0;
        std::error_code ec;
        if (!std::filesystem::exists(dir, ec) || !std::filesystem::is_directory(dir, ec)) {
            errors_.push_back({dir.string(), "directory not found", 0});
            return 0;
        }
        std::vector<std::filesystem::path> files;
        for (const auto& ent : std::filesystem::directory_iterator(dir, ec)) {
            if (ec) break;
            if (!ent.is_regular_file()) continue;
            auto ext = ent.path().extension().string();
            for (char& c : ext) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            if (ext != ".yml" && ext != ".yaml") continue;
            auto stem = ent.path().filename().string();
            if (!stem.empty() && stem[0] == '.') continue;
            files.push_back(ent.path());
        }
        std::sort(files.begin(), files.end());
        for (const auto& p : files) {
            if (rules_.size() >= detail::kMaxRules) {
                errors_.push_back({p.string(), "rule cap (10000) reached, remaining files skipped", 0});
                break;
            }
            added += load_file_locked(p);
        }
        return added;
    }

    // Parse a YAML string (tests and embedded rules). Returns rules added.
    size_t load_yaml(const std::string& yaml, const std::string& origin = "<string>") {
        std::unique_lock<std::shared_mutex> lock(mu_);
        return load_yaml_locked(yaml, origin);
    }

    std::vector<SigmaHit> evaluate(const std::string& chunk, int device_id) const {
        SigmaEvent ev;
        ev.raw = chunk;
        return evaluate(ev, device_id);
    }

    std::vector<SigmaHit> evaluate(const SigmaEvent& ev, int device_id) const {
        std::shared_lock<std::shared_mutex> lock(mu_);
        std::vector<SigmaHit> hits;
        SigmaEvent ev_use = ev;
        if (ev_use.raw.size() > detail::kMaxPatternBytes)
            ev_use.raw.resize(detail::kMaxPatternBytes);
        for (const auto& rule : rules_) {
            std::vector<char> hit(rule.selections.size(), 0);
            for (size_t i = 0; i < rule.selections.size(); ++i)
                hit[i] = detail::selection_matches(rule.selections[i], ev_use) ? 1 : 0;
            if (!detail::cond_eval(rule.cond, hit, rule.selections)) continue;
            SigmaHit h;
            h.rule_id = rule.meta.id;
            h.title = rule.meta.title;
            h.level = rule.meta.level;
            h.device_id = device_id;
            hits.push_back(std::move(h));
        }
        return hits;
    }

    // Documented no-op in this groundwork: no background thread is started.
    // Callers that want a refresh should call load_directory again.
    void start_auto_reload(int /*interval_seconds*/) {}
    void stop_auto_reload() {}

    size_t rule_count() const {
        std::shared_lock<std::shared_mutex> lock(mu_);
        return rules_.size();
    }

    std::vector<SigmaRule> rules() const {
        std::shared_lock<std::shared_mutex> lock(mu_);
        std::vector<SigmaRule> out;
        out.reserve(rules_.size());
        for (const auto& r : rules_) out.push_back(r.meta);
        return out;
    }

    std::vector<LoadError> errors() const {
        std::shared_lock<std::shared_mutex> lock(mu_);
        return errors_;
    }

    void clear() {
        std::unique_lock<std::shared_mutex> lock(mu_);
        rules_.clear();
        errors_.clear();
    }

    static std::vector<SigmaRule> parse_file(const std::filesystem::path& p) {
        SigmaEngine tmp;
        tmp.load_file_locked(p);
        return tmp.rules();
    }

private:
    size_t load_file_locked(const std::filesystem::path& p) {
        std::ifstream in(p, std::ios::binary);
        if (!in) {
            errors_.push_back({p.string(), "cannot open file", 0});
            return 0;
        }
        in.seekg(0, std::ios::end);
        auto sz = in.tellg();
        if (sz < 0 || static_cast<size_t>(sz) > detail::kMaxFileBytes) {
            errors_.push_back({p.string(), "file exceeds 64 KiB cap (or is unreadable)", 0});
            return 0;
        }
        in.seekg(0);
        std::string src(static_cast<size_t>(sz), '\0');
        in.read(src.data(), sz);
        return load_yaml_locked(src, p.string());
    }

    size_t load_yaml_locked(const std::string& yaml, const std::string& origin) {
        if (yaml.size() > detail::kMaxFileBytes) {
            errors_.push_back({origin, "payload exceeds 64 KiB cap", 0});
            return 0;
        }
        size_t added = 0;
        try {
            auto docs = detail::parse_yaml_docs(yaml);
            for (const auto& doc : docs) {
                if (rules_.size() >= detail::kMaxRules) {
                    errors_.push_back({origin, "rule cap (10000) reached", 0});
                    break;
                }
                detail::CompiledRule cr;
                std::string err;
                if (!detail::compile_rule_doc(doc, cr, err)) {
                    errors_.push_back({origin, err, 0});
                    continue;
                }
                if (cr.meta.id.empty())
                    cr.meta.id = origin + "#" + std::to_string(rules_.size());
                rules_.push_back(std::move(cr));
                ++added;
            }
        } catch (const detail::ParseErr& e) {
            errors_.push_back({origin, e.msg, e.line});
        } catch (const std::exception& e) {
            errors_.push_back({origin, e.what(), 0});
        }
        return added;
    }

    mutable std::shared_mutex mu_;
    std::vector<detail::CompiledRule> rules_;
    std::vector<LoadError> errors_;
};

} // namespace seahorse::sigma
