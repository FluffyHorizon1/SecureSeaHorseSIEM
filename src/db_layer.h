#ifndef DB_LAYER_H
#define DB_LAYER_H

// =============================================================================
// SecureSeaHorse SIEM — Phase 2: PostgreSQL Persistence Layer
// =============================================================================
// Provides:
//   - Auto-schema creation (telemetry + security_events tables)
//   - Thread-safe INSERT via mutex-guarded connection
//   - Configurable via server.conf (db_host, db_port, db_name, db_user, db_pass)
//   - Graceful fallback logging on connection failure
// =============================================================================

#include <string>
#include <mutex>
#include <sstream>
#include <chrono>
#include <cstring>
#include <functional>

#include <libpq-fe.h>

// Forward declaration — logger must be defined externally (from server_protocol.h)
class AsyncLogger;

// =============================================================================
// DATABASE CONFIGURATION
// =============================================================================
struct DbConfig {
    std::string host = "127.0.0.1";
    std::string port = "5432";
    std::string dbname = "seahorse";
    std::string user = "seahorse";
    std::string password = "";
    bool        enabled = true;      // Set false to disable DB entirely
};

// =============================================================================
// PostgreSQL STORE
// =============================================================================
class PgStore {
public:
    PgStore(const DbConfig& cfg, AsyncLogger* log)
        : config_(cfg), logger_(log), conn_(nullptr)
    {
        if (!config_.enabled) {
            log_msg("DB persistence disabled by config.");
            return;
        }
        connect();
        if (conn_ && PQstatus(conn_) == CONNECTION_OK) {
            ensure_schema();
        }
    }

    ~PgStore() {
        std::lock_guard<std::mutex> lock(conn_mutex_);
        if (conn_) {
            PQfinish(conn_);
            conn_ = nullptr;
        }
    }

    // Non-copyable
    PgStore(const PgStore&) = delete;
    PgStore& operator=(const PgStore&) = delete;

    // -------------------------------------------------------------------------
    // INSERT: Telemetry record
    // -------------------------------------------------------------------------
    bool insert_telemetry(int32_t device_id, int64_t timestamp_ms,
        const char* machine_name, const char* machine_ip,
        const char* os_user,
        double cpu_usage_pct,
        uint64_t ram_total, uint64_t ram_avail,
        uint64_t disk_total, uint64_t disk_free,
        uint64_t net_in, uint64_t net_out)
    {
        if (!config_.enabled) return false;

        // Use parameterized query to prevent SQL injection
        const char* sql =
            "INSERT INTO telemetry "
            "(device_id, timestamp_ms, machine_name, machine_ip, os_user, "
            " cpu_usage_pct, ram_total_bytes, ram_avail_bytes, "
            " disk_total_bytes, disk_free_bytes, net_bytes_in, net_bytes_out) "
            "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)";

        std::string s_dev = std::to_string(device_id);
        std::string s_ts = std::to_string(timestamp_ms);
        std::string s_cpu = std::to_string(cpu_usage_pct);
        std::string s_ramt = std::to_string(ram_total);
        std::string s_rama = std::to_string(ram_avail);
        std::string s_diskt = std::to_string(disk_total);
        std::string s_diskf = std::to_string(disk_free);
        std::string s_netin = std::to_string(net_in);
        std::string s_neto = std::to_string(net_out);

        const char* params[12] = {
            s_dev.c_str(), s_ts.c_str(),
            machine_name, machine_ip, os_user,
            s_cpu.c_str(),
            s_ramt.c_str(), s_rama.c_str(),
            s_diskt.c_str(), s_diskf.c_str(),
            s_netin.c_str(), s_neto.c_str()
        };

        return exec_params(sql, 12, params);
    }

    // -------------------------------------------------------------------------
    // INSERT: Security event (from regex engine)
    // -------------------------------------------------------------------------
    bool insert_security_event(int32_t device_id, int64_t timestamp_ms,
        const char* machine_ip,
        const std::string& rule_name,
        const std::string& severity,
        const std::string& category,
        const std::string& matched_text)
    {
        if (!config_.enabled) return false;

        const char* sql =
            "INSERT INTO security_events "
            "(device_id, timestamp_ms, machine_ip, rule_name, severity, category, matched_text) "
            "VALUES ($1,$2,$3,$4,$5,$6,$7)";

        std::string s_dev = std::to_string(device_id);
        std::string s_ts = std::to_string(timestamp_ms);

        // Truncate matched_text to 512 chars to prevent oversized inserts
        std::string safe_match = matched_text.substr(0, 512);

        const char* params[7] = {
            s_dev.c_str(), s_ts.c_str(), machine_ip,
            rule_name.c_str(), severity.c_str(),
            category.c_str(), safe_match.c_str()
        };

        return exec_params(sql, 7, params);
    }

    // -------------------------------------------------------------------------
    // STATUS: Check if connected
    // -------------------------------------------------------------------------
    bool is_connected() {
        std::lock_guard<std::mutex> lock(conn_mutex_);
        return conn_ && PQstatus(conn_) == CONNECTION_OK;
    }

    // -------------------------------------------------------------------------
    // RECONNECT: Try to re-establish lost connection
    // -------------------------------------------------------------------------
    bool reconnect() {
        std::lock_guard<std::mutex> lock(conn_mutex_);
        if (conn_) {
            PQfinish(conn_);
            conn_ = nullptr;
        }
        return connect_internal();
    }

private:
    DbConfig     config_;
    AsyncLogger* logger_;
    PGconn* conn_;
    std::mutex   conn_mutex_;

    // Logging helper — uses logger if available, otherwise stderr
    void log_msg(const std::string& msg, bool is_error = false);

    // Connect (internal, assumes lock is NOT held by caller)
    void connect() {
        std::lock_guard<std::mutex> lock(conn_mutex_);
        connect_internal();
    }

    // Connect (internal, assumes lock IS held by caller)
    bool connect_internal() {
        std::string conninfo =
            "host=" + config_.host +
            " port=" + config_.port +
            " dbname=" + config_.dbname +
            " user=" + config_.user;

        if (!config_.password.empty()) {
            conninfo += " password=" + config_.password;
        }

        // Set a reasonable connection timeout
        conninfo += " connect_timeout=5";

        conn_ = PQconnectdb(conninfo.c_str());

        if (PQstatus(conn_) != CONNECTION_OK) {
            std::string err = PQerrorMessage(conn_);
            log_msg("PostgreSQL connection failed: " + err, true);
            PQfinish(conn_);
            conn_ = nullptr;
            return false;
        }

        log_msg("PostgreSQL connected: " + config_.host + ":" + config_.port + "/" + config_.dbname);
        return true;
    }

    // Execute parameterized query (thread-safe)
    bool exec_params(const char* sql, int n_params, const char* const* params) {
        std::lock_guard<std::mutex> lock(conn_mutex_);

        if (!conn_ || PQstatus(conn_) != CONNECTION_OK) {
            // Try one reconnect
            if (!connect_internal()) return false;
        }

        PGresult* res = PQexecParams(conn_, sql, n_params, nullptr,
            params, nullptr, nullptr, 0);

        if (PQresultStatus(res) != PGRES_COMMAND_OK) {
            std::string err = PQresultErrorMessage(res);
            log_msg("DB INSERT failed: " + err, true);
            PQclear(res);

            // Check if connection died — reset for next attempt
            if (PQstatus(conn_) != CONNECTION_OK) {
                PQfinish(conn_);
                conn_ = nullptr;
            }
            return false;
        }

        PQclear(res);
        return true;
    }

    // Execute plain SQL (for schema creation)
    bool exec_sql(const char* sql) {
        // Assumes conn_mutex_ is already held
        PGresult* res = PQexec(conn_, sql);
        ExecStatusType status = PQresultStatus(res);

        if (status != PGRES_COMMAND_OK && status != PGRES_TUPLES_OK) {
            std::string err = PQresultErrorMessage(res);
            log_msg("DB exec failed: " + err, true);
            PQclear(res);
            return false;
        }

        PQclear(res);
        return true;
    }

    // Create tables if they don't exist
    void ensure_schema() {
        // Assumes conn_mutex_ is already held (called from constructor under lock via connect())
        // Actually, constructor calls connect() which locks, then calls ensure_schema() outside lock.
        // Let's re-acquire for safety:
        std::lock_guard<std::mutex> lock(conn_mutex_);

        const char* telemetry_ddl =
            "CREATE TABLE IF NOT EXISTS telemetry ("
            "  id             BIGSERIAL PRIMARY KEY,"
            "  device_id      INTEGER NOT NULL,"
            "  timestamp_ms   BIGINT NOT NULL,"
            "  machine_name   VARCHAR(64),"
            "  machine_ip     VARCHAR(32),"
            "  os_user        VARCHAR(32),"
            "  cpu_usage_pct  DOUBLE PRECISION,"
            "  ram_total_bytes BIGINT,"
            "  ram_avail_bytes BIGINT,"
            "  disk_total_bytes BIGINT,"
            "  disk_free_bytes  BIGINT,"
            "  net_bytes_in   BIGINT,"
            "  net_bytes_out  BIGINT,"
            "  received_at    TIMESTAMPTZ DEFAULT NOW()"
            ")";

        const char* events_ddl =
            "CREATE TABLE IF NOT EXISTS security_events ("
            "  id             BIGSERIAL PRIMARY KEY,"
            "  device_id      INTEGER NOT NULL,"
            "  timestamp_ms   BIGINT NOT NULL,"
            "  machine_ip     VARCHAR(32),"
            "  rule_name      VARCHAR(128) NOT NULL,"
            "  severity       VARCHAR(16) NOT NULL,"
            "  category       VARCHAR(64),"
            "  matched_text   VARCHAR(512),"
            "  received_at    TIMESTAMPTZ DEFAULT NOW()"
            ")";

        // Indexes for common query patterns
        const char* idx_telemetry_device =
            "CREATE INDEX IF NOT EXISTS idx_telemetry_device_ts "
            "ON telemetry (device_id, timestamp_ms DESC)";

        const char* idx_events_device =
            "CREATE INDEX IF NOT EXISTS idx_events_device_ts "
            "ON security_events (device_id, timestamp_ms DESC)";

        const char* idx_events_rule =
            "CREATE INDEX IF NOT EXISTS idx_events_rule "
            "ON security_events (rule_name, received_at DESC)";

        if (exec_sql(telemetry_ddl)) {
            log_msg("Schema OK: telemetry table ready.");
        }
        if (exec_sql(events_ddl)) {
            log_msg("Schema OK: security_events table ready.");
        }

        exec_sql(idx_telemetry_device);
        exec_sql(idx_events_device);
        exec_sql(idx_events_rule);

        log_msg("Database schema verified with indexes.");
    }
};

// =============================================================================
// Deferred implementation of log_msg (depends on AsyncLogger being fully defined)
// This is implemented in server.cpp after all headers are included.
// For header-only use, provide inline stub:
// =============================================================================
// NOTE: The actual implementation is in server.cpp where AsyncLogger is available.
// The declaration here allows the header to compile independently.

#endif
