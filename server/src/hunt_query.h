// =============================================================================
// hunt_query.h -- Phase 23 (v4.5.0)
// -----------------------------------------------------------------------------
// SeaHorse Hunt Query Language -- a minimal, Splunk-inspired DSL compiled
// down to a parameterized SQL plan against the existing Phase 2+ tables.
// No embedded SQL is ever exposed to the API; the planner validates every
// identifier against a whitelist and binds every literal via $N parameters.
//
// Grammar (EBNF, trimmed):
//   query      := search_clause { "|" pipe_stage }
//   search_clause := "search" term { ( "AND" | "OR" | "NOT" ) term }
//   term       := field ( "=" | "!=" | ">" | "<" | "~" ) literal
//   pipe_stage := ( "where" term
//                 | "stats" agg { "," agg } [ "by" field { "," field } ]
//                 | "top"   INT field
//                 | "sort"  ( "asc" | "desc" ) field
//                 | "limit" INT
//                 | "table" field { "," field } )
//
// Example:
//   search category=brute_force device_id=42
//   | stats count by source_ip
//   | sort desc count
//   | limit 10
// =============================================================================
#pragma once

#include <chrono>
#include <cstdint>
#include <exception>
#include <optional>
#include <string>
#include <unordered_map>
#include <variant>
#include <vector>

namespace seahorse::hunt {

enum class FieldKind { Int, Bigint, Text, Timestamp, Inet };

struct FieldSchema {
    std::string name;
    FieldKind   kind = FieldKind::Text;
    std::string sql_column;
};

struct TableSchema {
    std::string name;                               // "threats" | "events" | ...
    std::string sql_table;                          // "threat_detections" | ...
    std::unordered_map<std::string, FieldSchema> fields;
};

using Literal = std::variant<std::int64_t, double, std::string>;

struct CompiledPlan {
    std::string          sql;                       // WITH $1 = ? style
    std::vector<Literal> params;
    std::size_t          estimated_row_cap = 1000;  // LIMIT cap applied last
    std::vector<std::string> touched_tables;
};

struct QueryResult {
    std::vector<std::string>                      columns;
    std::vector<std::vector<std::string>>         rows;
    std::chrono::milliseconds                     planning_ms{0};
    std::chrono::milliseconds                     execution_ms{0};
    bool                                          truncated = false;
};

class HuntCompiler {
public:
    // Plan-only (no execution) — used by the REST "validate" endpoint and by
    // unit tests. Throws `HuntQueryError` on lex / parse / validation errors.
    CompiledPlan compile(const std::string& query) const;

    // Register a table with its field whitelist. All field names referenced
    // by incoming queries must resolve through this registry.
    void register_table(const TableSchema& t);

private:
    std::unordered_map<std::string, TableSchema> tables_;
};

class HuntExecutor {
public:
    // Execute a plan against PostgreSQL. Enforces:
    //   - 30 s query timeout (statement_timeout locally scoped)
    //   - 10 k row hard cap (adds LIMIT even if the user omits one)
    //   - tenant scope (appends `AND tenant_id = $N`)
    QueryResult run(const CompiledPlan& plan, const std::string& tenant_id);
};

// Saved-search catalog. Surfaced in the React UI at /hunt.
struct SavedSearch {
    std::string id;
    std::string owner_user_id;
    std::string tenant_id;
    std::string name;
    std::string query;
    bool        pinned = false;
};

class SavedSearchStore {
public:
    SavedSearch create(const std::string& tenant, const std::string& owner,
                       const std::string& name, const std::string& query);
    std::vector<SavedSearch> list(const std::string& tenant) const;
    bool remove(const std::string& id, const std::string& owner);
};

class HuntQueryError : public std::exception {
public:
    explicit HuntQueryError(std::string msg) : msg_(std::move(msg)) {}
    const char* what() const noexcept override { return msg_.c_str(); }
private:
    std::string msg_;
};

} // namespace seahorse::hunt
