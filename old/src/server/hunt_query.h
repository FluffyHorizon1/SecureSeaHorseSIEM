#ifndef HUNT_QUERY_H
#define HUNT_QUERY_H

#ifndef NOMINMAX
#define NOMINMAX
#endif

// =============================================================================
// SecureSeaHorse SIEM -- Phase 23: Threat Hunting Query Language
// =============================================================================
// A small, SPL-inspired DSL for interactive searches over the detection tables
// already persisted in PostgreSQL. Goal: let analysts express questions in one
// line without writing SQL, while keeping the implementation safe (always
// translates to parameterised queries; no user-controlled SQL).
//
// Grammar (simplified):
//
//   query      ::= source pipeline*
//   source     ::= "search" ident               (ident picks a source table)
//   pipeline   ::= "|" command
//   command    ::= "where" predicate_list
//                | "limit" INT
//                | "head"  INT
//                | "sort"  FIELD ["asc"|"desc"]
//                | "stats" "count" ["by" FIELD]
//                | "fields" FIELD ("," FIELD)*
//
//   predicate  ::= FIELD ("=" | "!=" | ">" | "<" | ">=" | "<=" | "~") VALUE
//   predicate  ::= predicate "AND" predicate
//   predicate  ::= predicate "OR"  predicate
//
// Valid sources: events, threats, ioc, fim, correlations, audit
// Example:
//   search threats | where severity=critical AND mitre_id~T1110 | head 20
//   search ioc     | where feed_source=malicious_ips | stats count by ioc_value
//
// Designed to be executed by PgStore: we render a safe prepared statement.
// =============================================================================

#include <algorithm>
#include <cstdint>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <set>

// =============================================================================
// TOKEN
// =============================================================================
enum class HuntTok {
    IDENT, STRING, NUMBER, PIPE, COMMA, EOF_TOK,
    EQ, NEQ, GT, LT, GE, LE, LIKE
};

struct HuntToken {
    HuntTok type = HuntTok::EOF_TOK;
    std::string value;
};

// =============================================================================
// LEXER
// =============================================================================
class HuntLexer {
public:
    explicit HuntLexer(const std::string& s) : src_(s) {}
    HuntToken next() {
        skip_ws();
        if (pos_ >= src_.size()) return {HuntTok::EOF_TOK, ""};
        char c = src_[pos_];
        if (c == '|') { pos_++; return {HuntTok::PIPE, "|"}; }
        if (c == ',') { pos_++; return {HuntTok::COMMA, ","}; }
        if (c == '=') { pos_++; return {HuntTok::EQ, "="}; }
        if (c == '~') { pos_++; return {HuntTok::LIKE, "~"}; }
        if (c == '!' && pos_ + 1 < src_.size() && src_[pos_ + 1] == '=') {
            pos_ += 2; return {HuntTok::NEQ, "!="};
        }
        if (c == '>') { pos_++;
            if (pos_ < src_.size() && src_[pos_] == '=') { pos_++; return {HuntTok::GE, ">="}; }
            return {HuntTok::GT, ">"};
        }
        if (c == '<') { pos_++;
            if (pos_ < src_.size() && src_[pos_] == '=') { pos_++; return {HuntTok::LE, "<="}; }
            return {HuntTok::LT, "<"};
        }
        if (c == '"' || c == '\'') {
            char quote = c;
            pos_++;
            std::string s;
            while (pos_ < src_.size() && src_[pos_] != quote) s += src_[pos_++];
            if (pos_ < src_.size()) pos_++;
            return {HuntTok::STRING, s};
        }
        if (std::isdigit(static_cast<unsigned char>(c)) ||
            (c == '-' && pos_ + 1 < src_.size() && std::isdigit(static_cast<unsigned char>(src_[pos_ + 1])))) {
            std::string n;
            n += src_[pos_++];
            while (pos_ < src_.size() && (std::isdigit(static_cast<unsigned char>(src_[pos_])) || src_[pos_] == '.'))
                n += src_[pos_++];
            return {HuntTok::NUMBER, n};
        }
        // Identifier / keyword
        std::string id;
        while (pos_ < src_.size() && (std::isalnum(static_cast<unsigned char>(src_[pos_])) ||
               src_[pos_] == '_' || src_[pos_] == '.' || src_[pos_] == '-')) {
            id += src_[pos_++];
        }
        return {HuntTok::IDENT, id};
    }

private:
    std::string src_;
    size_t pos_ = 0;
    void skip_ws() { while (pos_ < src_.size() && std::isspace(static_cast<unsigned char>(src_[pos_]))) pos_++; }
};

// =============================================================================
// AST
// =============================================================================
struct HuntPredicate {
    std::string field;
    std::string op;            // =, !=, >, <, >=, <=, ~
    std::string value;
    std::string connector;     // "", "AND", "OR"
};

struct HuntStats {
    bool enabled = false;
    std::string group_by;      // Empty = no grouping
};

struct HuntQuery {
    std::string source;        // table alias
    std::vector<HuntPredicate> predicates;
    std::vector<std::string> projected_fields;
    std::string sort_field;
    bool sort_desc = true;
    int limit = 50;
    HuntStats stats;
};

// =============================================================================
// PARSER
// =============================================================================
class HuntParser {
public:
    HuntParser() = default;

    bool parse(const std::string& text, HuntQuery& out, std::string& error) {
        HuntLexer lex(text);
        HuntToken tk = lex.next();

        if (tk.type != HuntTok::IDENT || ci_equal(tk.value, "search") == false) {
            error = "expected 'search' at start";
            return false;
        }
        tk = lex.next();
        if (tk.type != HuntTok::IDENT) { error = "expected source after 'search'"; return false; }
        if (!is_valid_source(tk.value)) {
            error = "unknown source '" + tk.value + "'";
            return false;
        }
        out.source = tk.value;

        // Pipeline
        tk = lex.next();
        while (tk.type == HuntTok::PIPE) {
            tk = lex.next();
            if (tk.type != HuntTok::IDENT) { error = "expected command"; return false; }
            std::string cmd = tk.value;
            std::transform(cmd.begin(), cmd.end(), cmd.begin(), ::tolower);

            if (cmd == "where") {
                if (!parse_where(lex, out, tk, error)) return false;
                continue;
            }
            if (cmd == "limit" || cmd == "head") {
                tk = lex.next();
                if (tk.type != HuntTok::NUMBER) { error = "limit expects number"; return false; }
                try { out.limit = std::min(std::max(1, std::stoi(tk.value)), 10000); }
                catch (...) { out.limit = 50; }
                tk = lex.next();
                continue;
            }
            if (cmd == "sort") {
                tk = lex.next();
                if (tk.type != HuntTok::IDENT) { error = "sort expects field"; return false; }
                if (!is_valid_field(out.source, tk.value)) {
                    error = "sort field '" + tk.value + "' not valid for source '" + out.source + "'";
                    return false;
                }
                out.sort_field = tk.value;
                tk = lex.next();
                if (tk.type == HuntTok::IDENT) {
                    if (ci_equal(tk.value, "asc")) { out.sort_desc = false; tk = lex.next(); }
                    else if (ci_equal(tk.value, "desc")) { out.sort_desc = true; tk = lex.next(); }
                }
                continue;
            }
            if (cmd == "stats") {
                tk = lex.next();
                if (tk.type != HuntTok::IDENT || !ci_equal(tk.value, "count")) {
                    error = "only 'count' is supported with stats";
                    return false;
                }
                out.stats.enabled = true;
                tk = lex.next();
                if (tk.type == HuntTok::IDENT && ci_equal(tk.value, "by")) {
                    tk = lex.next();
                    if (tk.type != HuntTok::IDENT) { error = "stats by expects field"; return false; }
                    if (!is_valid_field(out.source, tk.value)) {
                        error = "stats field '" + tk.value + "' not valid for source";
                        return false;
                    }
                    out.stats.group_by = tk.value;
                    tk = lex.next();
                }
                continue;
            }
            if (cmd == "fields") {
                tk = lex.next();
                while (tk.type == HuntTok::IDENT) {
                    if (!is_valid_field(out.source, tk.value)) {
                        error = "field '" + tk.value + "' not valid for source";
                        return false;
                    }
                    out.projected_fields.push_back(tk.value);
                    tk = lex.next();
                    if (tk.type != HuntTok::COMMA) break;
                    tk = lex.next();
                }
                continue;
            }
            error = "unknown command '" + cmd + "'";
            return false;
        }

        if (tk.type != HuntTok::EOF_TOK) { error = "trailing tokens"; return false; }
        return true;
    }

private:
    bool parse_where(HuntLexer& lex, HuntQuery& out, HuntToken& tk, std::string& error) {
        std::string connector;
        while (true) {
            tk = lex.next();
            if (tk.type != HuntTok::IDENT) { error = "where expects field"; return false; }
            HuntPredicate p;
            p.connector = connector;
            p.field = tk.value;
            if (!is_valid_field(out.source, p.field)) {
                error = "field '" + p.field + "' not valid for source '" + out.source + "'";
                return false;
            }
            tk = lex.next();
            switch (tk.type) {
                case HuntTok::EQ:   p.op = "=";  break;
                case HuntTok::NEQ:  p.op = "!="; break;
                case HuntTok::GT:   p.op = ">";  break;
                case HuntTok::LT:   p.op = "<";  break;
                case HuntTok::GE:   p.op = ">="; break;
                case HuntTok::LE:   p.op = "<="; break;
                case HuntTok::LIKE: p.op = "~";  break;
                default: error = "expected operator"; return false;
            }
            tk = lex.next();
            if (tk.type != HuntTok::IDENT && tk.type != HuntTok::STRING && tk.type != HuntTok::NUMBER) {
                error = "expected value";
                return false;
            }
            p.value = tk.value;
            out.predicates.push_back(std::move(p));

            tk = lex.next();
            if (tk.type == HuntTok::IDENT && (ci_equal(tk.value, "AND") || ci_equal(tk.value, "OR"))) {
                connector = ci_equal(tk.value, "OR") ? "OR" : "AND";
                continue;
            }
            break;
        }
        return true;
    }

    static bool ci_equal(const std::string& a, const std::string& b) {
        if (a.size() != b.size()) return false;
        for (size_t i = 0; i < a.size(); i++)
            if (std::tolower(static_cast<unsigned char>(a[i])) !=
                std::tolower(static_cast<unsigned char>(b[i]))) return false;
        return true;
    }

    static const std::map<std::string, std::set<std::string>>& schema() {
        static const std::map<std::string, std::set<std::string>> s = {
            {"events",      {"device_id","timestamp_ms","machine_ip","rule_name",
                             "severity","category","matched_text","received_at"}},
            {"threats",     {"device_id","timestamp_ms","machine_ip","category",
                             "sub_type","severity","confidence","mitre_id",
                             "mitre_name","mitre_tactic","description","received_at"}},
            {"ioc",         {"device_id","timestamp_ms","machine_ip","ioc_type",
                             "ioc_value","severity","feed_source","matched_in",
                             "mitre_id","description","tags","received_at"}},
            {"fim",         {"device_id","timestamp_ms","machine_ip","change_type",
                             "file_path","old_hash","new_hash","severity",
                             "mitre_id","description","received_at"}},
            {"correlations",{"incident_id","rule_name","severity","mitre_tactic",
                             "mitre_technique","description","first_seen_ms","last_seen_ms"}},
            {"audit",       {"username","tenant_id","action","source_ip","success","timestamp_ms"}},
        };
        return s;
    }

    static bool is_valid_source(const std::string& s) {
        return schema().count(s) > 0;
    }
    static bool is_valid_field(const std::string& src, const std::string& f) {
        auto it = schema().find(src);
        if (it == schema().end()) return false;
        return it->second.count(f) > 0;
    }
};

// =============================================================================
// COMPILER -- HuntQuery -> parameterised SQL
// =============================================================================
struct CompiledSql {
    std::string sql;
    std::vector<std::string> params;
};

class HuntCompiler {
public:
    static CompiledSql compile(const HuntQuery& q) {
        CompiledSql out;
        const std::map<std::string, std::string> table_map = {
            {"events",       "security_events"},
            {"threats",      "threat_detections"},
            {"ioc",          "ioc_matches"},
            {"fim",          "fim_events"},
            {"correlations", "correlations_view"},   // view created at startup if needed
            {"audit",        "audit_log"}
        };
        auto it = table_map.find(q.source);
        if (it == table_map.end()) return out;

        std::ostringstream sql;

        if (q.stats.enabled) {
            if (q.stats.group_by.empty()) {
                sql << "SELECT COUNT(*) AS count FROM " << it->second;
            } else {
                sql << "SELECT " << q.stats.group_by << ", COUNT(*) AS count FROM " << it->second;
            }
        } else {
            sql << "SELECT ";
            if (q.projected_fields.empty()) sql << "*";
            else {
                for (size_t i = 0; i < q.projected_fields.size(); i++) {
                    if (i > 0) sql << ", ";
                    sql << q.projected_fields[i];
                }
            }
            sql << " FROM " << it->second;
        }

        if (!q.predicates.empty()) {
            sql << " WHERE ";
            int param_idx = 1;
            for (size_t i = 0; i < q.predicates.size(); i++) {
                const auto& p = q.predicates[i];
                if (i > 0) sql << " " << (p.connector.empty() ? "AND" : p.connector) << " ";
                if (p.op == "~") {
                    // LIKE-style; translate ~ to ILIKE %val%
                    sql << p.field << " ILIKE $" << param_idx++;
                    out.params.push_back("%" + p.value + "%");
                } else {
                    sql << p.field << " " << p.op << " $" << param_idx++;
                    out.params.push_back(p.value);
                }
            }
        }

        if (q.stats.enabled && !q.stats.group_by.empty()) {
            sql << " GROUP BY " << q.stats.group_by;
        }

        if (!q.stats.enabled) {
            if (!q.sort_field.empty()) {
                sql << " ORDER BY " << q.sort_field << (q.sort_desc ? " DESC" : " ASC");
            } else {
                sql << " ORDER BY received_at DESC";
            }
        }

        int lim = q.limit > 0 ? q.limit : 50;
        if (lim > 10000) lim = 10000;
        sql << " LIMIT " << lim;

        out.sql = sql.str();
        return out;
    }
};

// =============================================================================
// PUBLIC API
// =============================================================================
struct HuntResult {
    bool ok = false;
    std::string error;
    CompiledSql compiled;
};

inline HuntResult compile_hunt(const std::string& text) {
    HuntResult r;
    HuntParser p;
    HuntQuery q;
    if (!p.parse(text, q, r.error)) return r;
    r.compiled = HuntCompiler::compile(q);
    r.ok = !r.compiled.sql.empty();
    return r;
}

#endif
