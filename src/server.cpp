#define NOMINMAX

#define _CRT_SECURE_NO_WARNINGS 

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <map>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <queue>
#include <functional>
#include <condition_variable>
#include <memory> 
#include <chrono> 
#include <algorithm>
#include <csignal>   
#include <atomic>    

// --- OPENSSL INCLUDES ---
#include <openssl/ssl.h>
#include <openssl/err.h>

// --- Phase 1 + 2 Headers ---
#include "server_protocol.h" 
#include "regex_engine.h"    // Phase 2: Regex-based log analysis
#include "alert_engine.h"    // Phase 2: Log-based threshold alerting
#include "db_layer.h"        // Phase 2: PostgreSQL persistence

#ifdef _WIN32
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libpq.lib")
typedef int socklen_t;
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#define INVALID_SOCKET -1
#define closesocket close
typedef int SOCKET;
#endif

// =============================================================================
// GLOBAL CONTROL
// =============================================================================
std::atomic<bool> g_running(true);

void handle_signal(int sig) {
    g_running = false;
}

// =============================================================================
// GLOBAL SERVICES (initialized in main after config load)
// =============================================================================
static std::unique_ptr<AsyncLogger>   logger;
static std::unique_ptr<PgStore>       pg_store;       // Phase 2: PostgreSQL
static std::unique_ptr<RegexEngine>   regex_engine;   // Phase 2: Regex log parser
static std::unique_ptr<AlertEngine>   alert_engine;   // Phase 2: Threshold alerting

// =============================================================================
// PgStore::log_msg IMPLEMENTATION
// (Deferred from db_layer.h because it depends on AsyncLogger being defined)
// =============================================================================
void PgStore::log_msg(const std::string& msg, bool is_error) {
    if (logger_) {
        logger_->log(is_error ? AsyncLogger::ERROR_LOG : AsyncLogger::INFO, "[DB] " + msg);
    }
    else {
        std::cerr << "[DB] " << msg << "\n";
    }
}

// =============================================================================
// LEGACY CSV WRITER (kept for backward compatibility alongside PostgreSQL)
// =============================================================================
class CsvWriter {
    std::mutex csv_mutex;
    std::ofstream csv_file;
public:
    CsvWriter(const std::string& filename) {
        csv_file.open(filename, std::ios::app);
        if (!csv_file.is_open() && logger) {
            logger->log(AsyncLogger::ERROR_LOG, "Could not open CSV file: " + filename);
        }
    }
    void write(int64_t ts, int dev_id, float cpu, int fails) {
        std::lock_guard<std::mutex> lock(csv_mutex);
        if (csv_file.is_open()) {
            csv_file << ts << "," << dev_id << "," << std::fixed << std::setprecision(1) << cpu << "," << fails << "\n";
            csv_file.flush();
        }
    }
};

static std::unique_ptr<CsvWriter> csv_writer;

// =============================================================================
// STATE MANAGEMENT
// =============================================================================
struct DeviceState {
    std::mutex device_mutex;
    RawTelemetry last_report = {};
    bool has_history = false;
    int failed_login_count = 0;
};

std::mutex registry_mutex;
std::map<int, std::shared_ptr<DeviceState>> device_registry;

// =============================================================================
// NETWORK HELPER
// =============================================================================
bool recv_exact_ssl(SSL* ssl, char* buf, int len) {
    int total = 0;
    while (total < len) {
        int b = SSL_read(ssl, buf + total, len - total);
        if (b <= 0) return false;
        total += b;
    }
    return true;
}

// =============================================================================
// OPENSSL HELPERS
// =============================================================================
void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

SSL_CTX* create_server_context(const std::string& ca_path, const std::string& cert_path, const std::string& key_path) {
    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        logger->log(AsyncLogger::ERROR_LOG, "Unable to create SSL context");
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_certificate_file(ctx, cert_path.c_str(), SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, key_path.c_str(), SSL_FILETYPE_PEM) <= 0) {
        logger->log(AsyncLogger::ERROR_LOG, "Failed to load server certificate or key.");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_load_verify_locations(ctx, ca_path.c_str(), NULL) <= 0) {
        logger->log(AsyncLogger::ERROR_LOG, "Failed to load CA certificate.");
        exit(EXIT_FAILURE);
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    return ctx;
}

// =============================================================================
// PROCESSING LOGIC — Phase 2 Upgraded
// =============================================================================
// Pipeline: Decode → CPU calc → Regex analysis → DB persist → Alert eval → CSV
// =============================================================================
void process_report(RawTelemetry& current) {
    // --- Byte Order Conversion ---
    current.device_id = ntohl(current.device_id);
    current.timestamp_ms = ntohll_custom(current.timestamp_ms);
    current.cpu_idle_ticks = ntohll_custom(current.cpu_idle_ticks);
    current.cpu_kernel_ticks = ntohll_custom(current.cpu_kernel_ticks);
    current.cpu_user_ticks = ntohll_custom(current.cpu_user_ticks);
    current.ram_total_bytes = ntohll_custom(current.ram_total_bytes);
    current.ram_avail_bytes = ntohll_custom(current.ram_avail_bytes);
    current.disk_total_bytes = ntohll_custom(current.disk_total_bytes);
    current.disk_free_bytes = ntohll_custom(current.disk_free_bytes);
    current.net_bytes_in = ntohll_custom(current.net_bytes_in);
    current.net_bytes_out = ntohll_custom(current.net_bytes_out);

    // --- Device Registration ---
    std::shared_ptr<DeviceState> state;
    {
        std::lock_guard<std::mutex> lock(registry_mutex);
        if (device_registry.find(current.device_id) == device_registry.end()) {
            device_registry[current.device_id] = std::make_shared<DeviceState>();
            logger->log(AsyncLogger::INFO, "New Device Registered: " + std::to_string(current.device_id));
        }
        state = device_registry[current.device_id];
    }

    {
        std::lock_guard<std::mutex> dev_lock(state->device_mutex);
        if (state->has_history && current.timestamp_ms <= state->last_report.timestamp_ms) return;

        // =================================================================
        // PHASE 2 [REGEX ENGINE]: Analyze raw log chunk
        // =================================================================
        std::string raw_log(current.raw_log_chunk,
            strnlen(current.raw_log_chunk, sizeof(current.raw_log_chunk)));

        std::vector<SecurityEvent> sec_events;
        int new_fails = 0;

        if (regex_engine) {
            sec_events = regex_engine->analyze(raw_log);
            new_fails = regex_engine->count_by_category(sec_events, "auth_failure");
        }

        state->failed_login_count += new_fails;

        // =================================================================
        // PHASE 2 [DB PERSISTENCE]: Insert security events into PostgreSQL
        // =================================================================
        if (pg_store) {
            for (const auto& ev : sec_events) {
                pg_store->insert_security_event(
                    current.device_id, current.timestamp_ms,
                    current.machine_ip,
                    ev.rule_name, ev.severity,
                    ev.category, ev.matched_text);
            }
        }

        // =================================================================
        // PHASE 2 [ALERT ENGINE]: Evaluate thresholds
        // =================================================================
        if (alert_engine && !sec_events.empty()) {
            alert_engine->ingest(current.device_id, current.machine_ip, sec_events);
        }

        // --- Baseline Check ---
        if (!state->has_history) {
            state->last_report = current;
            state->has_history = true;
            logger->log(AsyncLogger::INFO, "Device " + std::to_string(current.device_id) + " baseline established.");

            // Still persist the first report to DB
            if (pg_store) {
                pg_store->insert_telemetry(
                    current.device_id, current.timestamp_ms,
                    current.machine_name, current.machine_ip, current.os_user,
                    0.0, // CPU unknown on first sample
                    current.ram_total_bytes, current.ram_avail_bytes,
                    current.disk_total_bytes, current.disk_free_bytes,
                    current.net_bytes_in, current.net_bytes_out);
            }
            return;
        }

        // --- CPU Delta Calculation ---
        const RawTelemetry& last = state->last_report;
        uint64_t prev_total = last.cpu_user_ticks + last.cpu_kernel_ticks + last.cpu_idle_ticks;
        uint64_t curr_total = current.cpu_user_ticks + current.cpu_kernel_ticks + current.cpu_idle_ticks;
        uint64_t total_delta = curr_total - prev_total;
        uint64_t idle_delta = current.cpu_idle_ticks - last.cpu_idle_ticks;

        float cpu_usage = (total_delta > 0) ? 100.0f * (1.0f - ((float)idle_delta / (float)total_delta)) : 0.0f;
        state->last_report = current;

        // =================================================================
        // PHASE 2 [DB PERSISTENCE]: Insert telemetry record
        // =================================================================
        if (pg_store) {
            pg_store->insert_telemetry(
                current.device_id, current.timestamp_ms,
                current.machine_name, current.machine_ip, current.os_user,
                static_cast<double>(cpu_usage),
                current.ram_total_bytes, current.ram_avail_bytes,
                current.disk_total_bytes, current.disk_free_bytes,
                current.net_bytes_in, current.net_bytes_out);
        }

        // --- Legacy CSV Output (kept for backward compatibility) ---
        if (csv_writer) {
            csv_writer->write(current.timestamp_ms, current.device_id, cpu_usage, new_fails);
        }

        // --- Log Summary ---
        std::stringstream ss;
        ss << "Dev: " << current.device_id << " | CPU: " << std::fixed << std::setprecision(1) << cpu_usage
            << "% | Events: " << sec_events.size()
            << " | Fails: " << new_fails << " | IP: " << current.machine_ip;
        logger->log(AsyncLogger::INFO, ss.str());
    }
}

// =============================================================================
// CLIENT HANDLER
// =============================================================================
void handle_client_ssl(SSL* ssl, SOCKET sock) {
    PacketHeader h;
    std::vector<char> rx_buffer;

    if (SSL_accept(ssl) <= 0) {
        logger->log(AsyncLogger::WARN, "TLS handshake failed (Mutual Auth required).");
    }
    else {
        logger->log(AsyncLogger::INFO, "TLS session established with verified client.");
        while (g_running) {
            if (!recv_exact_ssl(ssl, (char*)&h, sizeof(h))) break;

            uint32_t payload_len = ntohl(h.payload_len);
            uint32_t magic = ntohl(h.magic);

            if (magic != PROTOCOL_MAGIC || payload_len != sizeof(RawTelemetry)) {
                logger->log(AsyncLogger::WARN, "Invalid magic or payload size mismatch.");
                break;
            }

            rx_buffer.assign(payload_len, 0);
            if (!recv_exact_ssl(ssl, rx_buffer.data(), payload_len)) break;

            uint32_t received_checksum = ntohl(h.checksum);
            uint32_t computed_crc = calculate_crc32(reinterpret_cast<const uint8_t*>(rx_buffer.data()), payload_len);
            if (computed_crc != received_checksum) {
                logger->log(AsyncLogger::WARN, "CRC mismatch. Dropping packet.");
                continue;
            }

            RawTelemetry* r = reinterpret_cast<RawTelemetry*>(rx_buffer.data());
            process_report(*r);
        }
    }
    SSL_shutdown(ssl);
    SSL_free(ssl);
    closesocket(sock);
}

// =============================================================================
// MAIN — Phase 2 Upgraded
// =============================================================================
int main(int argc, char* argv[]) {
    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    // -------------------------------------------------------------------------
    // PHASE 1 [CLI]: Parse command-line arguments
    // -------------------------------------------------------------------------
    CliArgs cli = parse_server_cli(argc, argv);

    if (cli.show_help) {
        print_server_usage(argv[0]);
        return 0;
    }
    if (cli.show_version) {
        std::cout << "SecureSeaHorse Server v1.2.0 (Phase 2)\n";
        return 0;
    }

#ifdef _WIN32
    WSADATA w;
    if (WSAStartup(MAKEWORD(2, 2), &w) != 0) return 1;
#endif

    // -------------------------------------------------------------------------
    // 1. Load Configuration, then apply CLI overrides
    // -------------------------------------------------------------------------
    AppConfig conf = load_config(cli.config_path);
    cli.apply_overrides(conf);

    int port = conf.get_int("port", 65432);

    // -------------------------------------------------------------------------
    // PHASE 1 [ASYNC LOGGER]: Initialize with configurable rotation
    // -------------------------------------------------------------------------
    {
        std::string log_path = conf.get("log_file", "server.log");
        size_t max_log_size = conf.get_size("log_max_bytes", 10 * 1024 * 1024);
        int max_log_files = conf.get_int("log_max_files", 5);
        logger = std::make_unique<AsyncLogger>(log_path, max_log_size, max_log_files, true);
    }

    logger->log(AsyncLogger::INFO, "=== SecureSeaHorse Server v1.2.0 (Phase 2) starting ===");
    logger->log(AsyncLogger::INFO, "Config loaded from: " + cli.config_path);

    // -------------------------------------------------------------------------
    // Legacy CSV writer (kept alongside PostgreSQL for backward compat)
    // -------------------------------------------------------------------------
    std::string csv_path = conf.get("csv_output", "s_log.csv");
    if (!csv_path.empty() && csv_path != "none") {
        csv_writer = std::make_unique<CsvWriter>(csv_path);
        logger->log(AsyncLogger::INFO, "CSV output: " + csv_path);
    }

    // -------------------------------------------------------------------------
    // PHASE 2 [POSTGRESQL]: Initialize database persistence
    // -------------------------------------------------------------------------
    {
        DbConfig db_cfg;
        db_cfg.enabled = conf.get_bool("db_enabled", true);
        db_cfg.host = conf.get("db_host", "127.0.0.1");
        db_cfg.port = conf.get("db_port", "5432");
        db_cfg.dbname = conf.get("db_name", "seahorse");
        db_cfg.user = conf.get("db_user", "seahorse");
        db_cfg.password = conf.get("db_pass", "");

        pg_store = std::make_unique<PgStore>(db_cfg, logger.get());

        if (db_cfg.enabled) {
            if (pg_store->is_connected()) {
                logger->log(AsyncLogger::INFO, "PostgreSQL: connected to "
                    + db_cfg.host + ":" + db_cfg.port + "/" + db_cfg.dbname);
            }
            else {
                logger->log(AsyncLogger::WARN,
                    "PostgreSQL: connection failed — telemetry will use CSV fallback only. "
                    "Check db_host/db_port/db_name/db_user/db_pass in server.conf.");
            }
        }
        else {
            logger->log(AsyncLogger::INFO, "PostgreSQL: disabled by config (db_enabled=false).");
        }
    }

    // -------------------------------------------------------------------------
    // PHASE 2 [REGEX ENGINE]: Initialize with built-in + user rules
    // -------------------------------------------------------------------------
    {
        std::string rules_path = conf.get("rules_file", "rules.conf");
        regex_engine = std::make_unique<RegexEngine>(rules_path);

        logger->log(AsyncLogger::INFO, "Regex engine: "
            + std::to_string(regex_engine->builtin_count()) + " built-in rules, "
            + std::to_string(regex_engine->user_rules_loaded()) + " user rules loaded"
            + (regex_engine->user_rules_loaded() > 0 ? " from " + rules_path : ""));
    }

    // -------------------------------------------------------------------------
    // PHASE 2 [ALERT ENGINE]: Initialize log-based threshold alerting
    // -------------------------------------------------------------------------
    {
        AlertConfig alert_cfg;
        alert_cfg.enabled = conf.get_bool("alert_enabled", true);
        alert_cfg.alert_log_path = conf.get("alert_log", "alerts.log");
        alert_cfg.load_defaults();

        // Allow per-category threshold overrides from config
        // Format: alert_threshold_<category> = count,window_sec,cooldown_sec
        for (auto& thresh : alert_cfg.thresholds) {
            std::string key = "alert_threshold_" + thresh.category;
            if (conf.data.count(key)) {
                std::istringstream iss(conf.get(key, ""));
                std::string tok;
                std::vector<int> vals;
                while (std::getline(iss, tok, ',')) {
                    try { vals.push_back(std::stoi(tok)); }
                    catch (...) {}
                }
                if (vals.size() >= 1) thresh.count = vals[0];
                if (vals.size() >= 2) thresh.window_sec = vals[1];
                if (vals.size() >= 3) thresh.cooldown_sec = vals[2];
            }
        }

        alert_engine = std::make_unique<AlertEngine>(alert_cfg);

        if (alert_cfg.enabled) {
            logger->log(AsyncLogger::INFO, "Alert engine: enabled, writing to " + alert_cfg.alert_log_path
                + " (" + std::to_string(alert_cfg.thresholds.size()) + " threshold rules)");
        }
        else {
            logger->log(AsyncLogger::INFO, "Alert engine: disabled by config.");
        }
    }

    // -------------------------------------------------------------------------
    // 2. Initialize Security
    // -------------------------------------------------------------------------
    init_openssl();
    SSL_CTX* ctx = create_server_context(
        conf.get("ca_path", "ca.crt"),
        conf.get("server_crt", "server.crt"),
        conf.get("server_key", "server.key")
    );

    // -------------------------------------------------------------------------
    // 3. Network Setup
    // -------------------------------------------------------------------------
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) {
        logger->log(AsyncLogger::ERROR_LOG, "Socket creation failed.");
        return 1;
    }

    int optval = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&optval, sizeof(optval));

#ifdef _WIN32
    DWORD timeout = 1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
#else
    struct timeval tv;
    tv.tv_sec = 1; tv.tv_usec = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
#endif

    sockaddr_in a = { AF_INET, htons(static_cast<uint16_t>(port)) };
    a.sin_addr.s_addr = INADDR_ANY;

    if (bind(s, (sockaddr*)&a, sizeof(a)) < 0) {
        logger->log(AsyncLogger::ERROR_LOG, "Bind failed. Port " + std::to_string(port) + " might be in use.");
        return 1;
    }

    listen(s, 10);
    logger->log(AsyncLogger::INFO, "Secure mTLS Server started on Port " + std::to_string(port));

    // -------------------------------------------------------------------------
    // PHASE 1 [DYNAMIC THREAD POOL]: Configure from server.conf / CLI
    // -------------------------------------------------------------------------
    DynamicThreadPool::Config pool_cfg;
    pool_cfg.min_threads = conf.get_size("pool_min", 2);
    pool_cfg.max_threads = conf.get_size("pool_max", 32);
    pool_cfg.idle_timeout_seconds = conf.get_int("pool_idle_timeout_s", 30);

    logger->log(AsyncLogger::INFO, "Thread pool: min=" + std::to_string(pool_cfg.min_threads)
        + " max=" + std::to_string(pool_cfg.max_threads)
        + " idle_timeout=" + std::to_string(pool_cfg.idle_timeout_seconds) + "s");

    // -------------------------------------------------------------------------
    // 4. Execution Loop (with Dynamic Thread Pool)
    // -------------------------------------------------------------------------
    {
        DynamicThreadPool pool(pool_cfg);

        std::thread diagnostics([&pool]() {
            while (g_running) {
                std::this_thread::sleep_for(std::chrono::seconds(30));
                if (!g_running) break;

                std::stringstream ss;
                ss << "Pool: active=" << pool.active_count()
                    << " total=" << pool.total_count()
                    << " pending=" << pool.pending_count();

                if (alert_engine)
                    ss << " | Alerts fired: " << alert_engine->total_alerts_fired();
                if (pg_store)
                    ss << " | DB: " << (pg_store->is_connected() ? "connected" : "disconnected");

                logger->log(AsyncLogger::INFO, ss.str());
            }
            });

        while (g_running) {
            SOCKET c = accept(s, 0, 0);
            if (c != INVALID_SOCKET) {
                pool.enqueue([c, ctx] {
                    SSL* ssl = SSL_new(ctx);
                    SSL_set_fd(ssl, (int)c);
                    handle_client_ssl(ssl, c);
                    });
            }
        }

        logger->log(AsyncLogger::INFO, "Shutdown signal received. Stopping thread pool...");
        g_running = false;
        if (diagnostics.joinable()) diagnostics.join();
    }
    //Secured Cyber Solutions, Inc. © 2024 - All Rights Reserved
    // -------------------------------------------------------------------------
    // 5. Cleanup (reverse initialization order)
    // -------------------------------------------------------------------------
    logger->log(AsyncLogger::INFO, "=== Server exiting gracefully ===");

    alert_engine.reset();
    pg_store.reset();
    regex_engine.reset();
    csv_writer.reset();
    logger.reset();

    closesocket(s);
    SSL_CTX_free(ctx);

#ifdef _WIN32
    WSACleanup();
#endif
    system("pause");  // <--- ADD THIS LINE
    return 0;
}

