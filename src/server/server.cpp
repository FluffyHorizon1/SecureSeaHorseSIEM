#define _CRT_SECURE_NO_WARNINGS 
#define NOMINMAX   // Prevent Windows.h from defining min/max macros

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

// --- Phase 1 + 2 + 3 + 4 + 5 Headers ---
#include "server_protocol.h" 
#include "crypto_utils.h"         // Phase 3: HMAC, CRL, OCSP, heartbeat
#include "regex_engine.h"         // Phase 2: Regex-based log analysis
#include "alert_engine.h"         // Phase 2: Log-based threshold alerting
#include "db_layer.h"             // Phase 2+4: PostgreSQL persistence
#include "traffic_classifier.h"   // Phase 4: Traffic classification + MITRE
#include "threat_intel.h"         // Phase 5: Threat intelligence feeds

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
// GLOBAL SERVICES
// =============================================================================
static std::unique_ptr<AsyncLogger>        logger;
static std::unique_ptr<PgStore>            pg_store;        // Phase 2
static std::unique_ptr<RegexEngine>        regex_engine;    // Phase 2
static std::unique_ptr<AlertEngine>        alert_engine;    // Phase 2
static std::unique_ptr<TrafficClassifier>  classifier;      // Phase 4
static std::unique_ptr<ThreatIntelEngine>  threat_intel;     // Phase 5

// Phase 3 config
static bool g_hmac_enabled       = true;
static int  g_connection_timeout = 120;

// Phase 4 stats
static std::atomic<size_t> g_total_threats{0};

// PgStore log bridge
void PgStore::log_msg(const std::string& msg, bool is_error) {
    if (logger_) logger_->log(is_error ? AsyncLogger::ERROR_LOG : AsyncLogger::INFO, "[DB] " + msg);
    else std::cerr << "[DB] " << msg << "\n";
}

// =============================================================================
// LEGACY CSV WRITER
// =============================================================================
class CsvWriter {
    std::mutex csv_mutex;
    std::ofstream csv_file;
public:
    CsvWriter(const std::string& filename) {
        csv_file.open(filename, std::ios::app);
        if (!csv_file.is_open() && logger)
            logger->log(AsyncLogger::ERROR_LOG, "Could not open CSV file: " + filename);
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
// NETWORK HELPERS
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

bool send_exact_ssl(SSL* ssl, const void* buf, int len) {
    int total = 0;
    while (total < len) {
        int b = SSL_write(ssl, (const char*)buf + total, len - total);
        if (b <= 0) return false;
        total += b;
    }
    return true;
}

// =============================================================================
// OPENSSL HELPERS — Phase 3
// =============================================================================
void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

SSL_CTX* create_server_context(const AppConfig& conf) {
    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) { logger->log(AsyncLogger::ERROR_LOG, "Unable to create SSL context"); exit(EXIT_FAILURE); }

    std::string ca_path   = conf.get("ca_path", "ca.crt");
    std::string cert_path = conf.get("server_crt", "server.crt");
    std::string key_path  = conf.get("server_key", "server.key");

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

    // Phase 3: CRL
    std::string crl_path = conf.get("crl_path", "");
    if (!crl_path.empty()) {
        if (load_crl(ctx, crl_path)) logger->log(AsyncLogger::INFO, "CRL loaded: " + crl_path);
        else logger->log(AsyncLogger::WARN, "CRL load failed: " + crl_path);
    }

    // Phase 3: OCSP
    if (conf.get_bool("ocsp_stapling", false)) {
        enable_ocsp_stapling_server(ctx);
        logger->log(AsyncLogger::INFO, "OCSP stapling: server support enabled.");
    }

    return ctx;
}

// =============================================================================
// PROCESSING LOGIC — Phase 2 + 3 + 4
// =============================================================================
// Pipeline: Decode → CPU calc → Regex → DB persist → Alert eval
//           → Traffic classify → DB persist threats → Log threats
// =============================================================================
void process_report(RawTelemetry& current) {
    // --- Byte Order Conversion ---
    current.device_id       = ntohl(current.device_id);
    current.timestamp_ms    = ntohll_custom(current.timestamp_ms);
    current.cpu_idle_ticks  = ntohll_custom(current.cpu_idle_ticks);
    current.cpu_kernel_ticks= ntohll_custom(current.cpu_kernel_ticks);
    current.cpu_user_ticks  = ntohll_custom(current.cpu_user_ticks);
    current.ram_total_bytes = ntohll_custom(current.ram_total_bytes);
    current.ram_avail_bytes = ntohll_custom(current.ram_avail_bytes);
    current.disk_total_bytes= ntohll_custom(current.disk_total_bytes);
    current.disk_free_bytes = ntohll_custom(current.disk_free_bytes);
    current.net_bytes_in    = ntohll_custom(current.net_bytes_in);
    current.net_bytes_out   = ntohll_custom(current.net_bytes_out);

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
            new_fails  = regex_engine->count_by_category(sec_events, "auth_failure");
        }
        state->failed_login_count += new_fails;

        // Phase 2: DB persistence — security events
        if (pg_store) {
            for (const auto& ev : sec_events) {
                pg_store->insert_security_event(
                    current.device_id, current.timestamp_ms,
                    current.machine_ip,
                    ev.rule_name, ev.severity,
                    ev.category, ev.matched_text);
            }
        }

        // Phase 2: Alert evaluation
        if (alert_engine && !sec_events.empty()) {
            alert_engine->ingest(current.device_id, current.machine_ip, sec_events);
        }

        // --- Baseline check ---
        if (!state->has_history) {
            state->last_report = current;
            state->has_history = true;
            logger->log(AsyncLogger::INFO, "Device " + std::to_string(current.device_id) + " baseline established.");
            if (pg_store) {
                pg_store->insert_telemetry(
                    current.device_id, current.timestamp_ms,
                    current.machine_name, current.machine_ip, current.os_user,
                    0.0, current.ram_total_bytes, current.ram_avail_bytes,
                    current.disk_total_bytes, current.disk_free_bytes,
                    current.net_bytes_in, current.net_bytes_out);
            }
            // Phase 4: Feed first sample to classifier (for baseline warmup)
            if (classifier) {
                classifier->classify(
                    current.device_id, current.timestamp_ms, current.machine_ip,
                    current.net_bytes_in, current.net_bytes_out,
                    0.0, 0.0, raw_log, sec_events);
            }
            return;
        }

        // --- CPU Delta Calculation ---
        const RawTelemetry& last = state->last_report;
        uint64_t prev_total = last.cpu_user_ticks + last.cpu_kernel_ticks + last.cpu_idle_ticks;
        uint64_t curr_total = current.cpu_user_ticks + current.cpu_kernel_ticks + current.cpu_idle_ticks;
        uint64_t total_delta = curr_total - prev_total;
        uint64_t idle_delta  = current.cpu_idle_ticks - last.cpu_idle_ticks;
        float cpu_usage = (total_delta > 0) ? 100.0f * (1.0f - ((float)idle_delta / (float)total_delta)) : 0.0f;
        state->last_report = current;

        // Phase 2: DB persistence — telemetry
        if (pg_store) {
            pg_store->insert_telemetry(
                current.device_id, current.timestamp_ms,
                current.machine_name, current.machine_ip, current.os_user,
                static_cast<double>(cpu_usage),
                current.ram_total_bytes, current.ram_avail_bytes,
                current.disk_total_bytes, current.disk_free_bytes,
                current.net_bytes_in, current.net_bytes_out);
        }

        // Legacy CSV
        if (csv_writer)
            csv_writer->write(current.timestamp_ms, current.device_id, cpu_usage, new_fails);

        // =================================================================
        // PHASE 4 [TRAFFIC CLASSIFIER]: Classify traffic and detect exploits
        // =================================================================
        if (classifier) {
            double ram_pct = (current.ram_total_bytes > 0)
                ? 100.0 * (1.0 - (double)current.ram_avail_bytes / (double)current.ram_total_bytes)
                : 0.0;

            std::vector<ThreatDetection> threats = classifier->classify(
                current.device_id,
                current.timestamp_ms,
                current.machine_ip,
                current.net_bytes_in,
                current.net_bytes_out,
                static_cast<double>(cpu_usage),
                ram_pct,
                raw_log,
                sec_events);

            // Persist + log each threat
            for (const auto& t : threats) {
                g_total_threats++;

                // DB persistence
                if (pg_store) {
                    pg_store->insert_threat_detection(
                        t.device_id, t.timestamp_ms, t.machine_ip.c_str(),
                        t.category, t.sub_type, t.severity, t.confidence,
                        t.mitre_id, t.mitre_name, t.mitre_tactic,
                        t.description, t.evidence);
                }

                // Log to server log
                std::stringstream ss;
                ss << "\033[1;33m[THREAT]\033[0m "
                   << "device=" << t.device_id
                   << " ip=" << t.machine_ip
                   << " | " << t.category << "/" << t.sub_type
                   << " | " << t.severity
                   << " conf=" << std::fixed << std::setprecision(2) << t.confidence
                   << " | MITRE " << t.mitre_id << " (" << t.mitre_tactic << ")"
                   << " | " << t.description;

                // Route severity to appropriate log level
                if (t.severity == "critical") {
                    logger->log(AsyncLogger::ERROR_LOG, ss.str());
                } else if (t.severity == "high") {
                    logger->log(AsyncLogger::WARN, ss.str());
                } else {
                    logger->log(AsyncLogger::INFO, ss.str());
                }
            }
        }

        // =================================================================
        // PHASE 5 [THREAT INTEL]: Match telemetry against IoC feeds
        // =================================================================
        if (threat_intel) {
            std::vector<IoCMatch> ioc_matches = threat_intel->match(
                current.machine_ip,
                current.machine_name,
                current.os_user,
                raw_log);

            for (const auto& m : ioc_matches) {
                threat_intel->total_matches++;

                // DB persistence
                if (pg_store) {
                    pg_store->insert_ioc_match(
                        current.device_id, current.timestamp_ms,
                        current.machine_ip,
                        ioc_type_str(m.ioc.type),
                        m.ioc.value,
                        m.ioc.severity,
                        m.ioc.feed_source,
                        m.matched_in,
                        m.ioc.mitre_id,
                        m.ioc.description,
                        m.ioc.tags);
                }

                // Log to server log
                std::stringstream iss;
                iss << "\033[1;31m[IoC HIT]\033[0m "
                    << "device=" << current.device_id
                    << " ip=" << current.machine_ip
                    << " | " << ioc_type_str(m.ioc.type) << "=" << m.ioc.value
                    << " | " << m.ioc.severity
                    << " | feed=" << m.ioc.feed_source
                    << " | found_in=" << m.matched_in;
                if (!m.ioc.mitre_id.empty())
                    iss << " | MITRE " << m.ioc.mitre_id;
                if (!m.ioc.description.empty())
                    iss << " | " << m.ioc.description;

                if (m.ioc.severity == "critical") {
                    logger->log(AsyncLogger::ERROR_LOG, iss.str());
                } else if (m.ioc.severity == "high") {
                    logger->log(AsyncLogger::WARN, iss.str());
                } else {
                    logger->log(AsyncLogger::INFO, iss.str());
                }
            }
        }

        // --- Standard log line ---
        std::stringstream ss;
        ss << "Dev: " << current.device_id << " | CPU: " << std::fixed << std::setprecision(1) << cpu_usage
           << "% | Events: " << sec_events.size()
           << " | Fails: " << new_fails << " | IP: " << current.machine_ip;
        logger->log(AsyncLogger::INFO, ss.str());
    }
}

// =============================================================================
// PHASE 3: SEND HEARTBEAT PONG
// =============================================================================
bool send_heartbeat_pong(SSL* ssl, const HeartbeatPayload& ping, const uint8_t* hmac_key) {
    HeartbeatPayload pong = ping;
    PacketHeaderV2 hdr = build_v2_header(MSG_HEARTBEAT_PONG, sizeof(pong),
        reinterpret_cast<const uint8_t*>(&pong), hmac_key);
    if (!send_exact_ssl(ssl, &hdr, sizeof(hdr))) return false;
    if (!send_exact_ssl(ssl, &pong, sizeof(pong))) return false;
    return true;
}

// =============================================================================
// CLIENT HANDLER — Dual-protocol v1/v2
// =============================================================================
void handle_client_ssl(SSL* ssl, SOCKET sock) {
    if (SSL_accept(ssl) <= 0) {
        logger->log(AsyncLogger::WARN, "TLS handshake failed (Mutual Auth required).");
        SSL_free(ssl);
        closesocket(sock);
        return;
    }

    logger->log(AsyncLogger::INFO, "TLS session established. Cipher: " + std::string(SSL_get_cipher(ssl)));

    // Phase 3: HMAC key derivation
    uint8_t hmac_key[HMAC_KEY_LEN] = {0};
    bool hmac_ready = false;
    if (g_hmac_enabled) {
        if (derive_hmac_key(ssl, hmac_key)) {
            hmac_ready = true;
            logger->log(AsyncLogger::DEBUG, "HMAC session key derived.");
        } else {
            logger->log(AsyncLogger::WARN, "HMAC derivation failed — v1 fallback.");
        }
    }

    // Connection timeout
#ifdef _WIN32
    DWORD read_timeout = g_connection_timeout * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&read_timeout, sizeof(read_timeout));
#else
    struct timeval tv;
    tv.tv_sec = g_connection_timeout; tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
#endif

    // --- Message loop: auto-detect v1 vs v2 ---
    while (g_running) {
        uint8_t prefix[6];
        if (!recv_exact_ssl(ssl, (char*)prefix, 6)) break;

        uint32_t magic; uint16_t version;
        std::memcpy(&magic, prefix, 4);
        std::memcpy(&version, prefix + 4, 2);
        magic = ntohl(magic); version = ntohs(version);

        if (magic != PROTOCOL_MAGIC) {
            logger->log(AsyncLogger::WARN, "Invalid magic. Dropping client.");
            break;
        }

        if (version == 2) {
            uint8_t rest[38];
            if (!recv_exact_ssl(ssl, (char*)rest, 38)) break;
            PacketHeaderV2 hdr;
            std::memcpy(&hdr, prefix, 6);
            std::memcpy(((uint8_t*)&hdr) + 6, rest, 38);

            uint8_t msg_type = hdr.msg_type;
            uint32_t plen    = ntohl(hdr.payload_len);
            if (plen > 1048576) { logger->log(AsyncLogger::WARN, "V2 payload too large."); break; }

            std::vector<char> payload(plen);
            if (plen > 0 && !recv_exact_ssl(ssl, payload.data(), plen)) break;

            if (hmac_ready && plen > 0) {
                if (!verify_hmac(hmac_key, HMAC_KEY_LEN,
                        reinterpret_cast<const uint8_t*>(payload.data()), plen, hdr.hmac)) {
                    logger->log(AsyncLogger::WARN, "HMAC verification FAILED. Dropping packet.");
                    continue;
                }
            }

            switch (msg_type) {
                case MSG_TELEMETRY: {
                    if (plen != sizeof(RawTelemetry)) break;
                    RawTelemetry* r = reinterpret_cast<RawTelemetry*>(payload.data());
                    process_report(*r);
                    break;
                }
                case MSG_HEARTBEAT_PING: {
                    if (plen >= sizeof(HeartbeatPayload)) {
                        HeartbeatPayload* ping = reinterpret_cast<HeartbeatPayload*>(payload.data());
                        logger->log(AsyncLogger::DEBUG, "PING from device " + std::to_string(ntohl(ping->device_id)));
                        if (!send_heartbeat_pong(ssl, *ping, hmac_key)) goto session_end;
                    }
                    break;
                }
                default:
                    logger->log(AsyncLogger::WARN, "Unknown v2 msg_type: " + std::to_string(msg_type));
                    break;
            }

        } else if (version == 1) {
            uint8_t rest[8];
            if (!recv_exact_ssl(ssl, (char*)rest, 8)) break;
            PacketHeader h;
            std::memcpy(&h, prefix, 6);
            std::memcpy(((uint8_t*)&h) + 6, rest, 8);

            uint32_t payload_len = ntohl(h.payload_len);
            if (payload_len != sizeof(RawTelemetry)) break;

            std::vector<char> rx_buffer(payload_len);
            if (!recv_exact_ssl(ssl, rx_buffer.data(), payload_len)) break;

            uint32_t received_crc = ntohl(h.checksum);
            uint32_t computed_crc = calculate_crc32(reinterpret_cast<const uint8_t*>(rx_buffer.data()), payload_len);
            if (computed_crc != received_crc) { logger->log(AsyncLogger::WARN, "V1 CRC mismatch."); continue; }

            RawTelemetry* r = reinterpret_cast<RawTelemetry*>(rx_buffer.data());
            process_report(*r);
        } else {
            logger->log(AsyncLogger::WARN, "Unsupported protocol version: " + std::to_string(version));
            break;
        }
    }

session_end:
    OPENSSL_cleanse(hmac_key, HMAC_KEY_LEN);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    closesocket(sock);
}

// =============================================================================
// MAIN — Phase 4 Upgraded
// =============================================================================
int main(int argc, char* argv[]) {
    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    CliArgs cli = parse_server_cli(argc, argv);
    if (cli.show_help) { print_server_usage(argv[0]); return 0; }
    if (cli.show_version) { std::cout << "SecureSeaHorse Server v1.5.0 (Phase 5)\n"; return 0; }

#ifdef _WIN32
    WSADATA w;
    if (WSAStartup(MAKEWORD(2, 2), &w) != 0) return 1;
#endif

    // -------------------------------------------------------------------------
    // 1. Load Configuration
    // -------------------------------------------------------------------------
    AppConfig conf = load_config(cli.config_path);
    cli.apply_overrides(conf);
    int port = conf.get_int("port", 65432);

    // Phase 3 config
    g_hmac_enabled       = conf.get_bool("hmac_enabled", true);
    g_connection_timeout = conf.get_int("connection_timeout_s", 120);

    // -------------------------------------------------------------------------
    // ASYNC LOGGER
    // -------------------------------------------------------------------------
    {
        std::string log_path = conf.get("log_file", "server.log");
        size_t max_log_size  = conf.get_size("log_max_bytes", 10 * 1024 * 1024);
        int max_log_files    = conf.get_int("log_max_files", 5);
        logger = std::make_unique<AsyncLogger>(log_path, max_log_size, max_log_files, true);
    }

    logger->log(AsyncLogger::INFO, "=== SecureSeaHorse Server v1.5.0 (Phase 5) starting ===");
    logger->log(AsyncLogger::INFO, "Config loaded from: " + cli.config_path);

    // Legacy CSV
    std::string csv_path = conf.get("csv_output", "s_log.csv");
    if (!csv_path.empty() && csv_path != "none") {
        csv_writer = std::make_unique<CsvWriter>(csv_path);
    }

    // -------------------------------------------------------------------------
    // PHASE 2 [POSTGRESQL]
    // -------------------------------------------------------------------------
    {
        DbConfig db_cfg;
        db_cfg.enabled  = conf.get_bool("db_enabled", true);
        db_cfg.host     = conf.get("db_host", "127.0.0.1");
        db_cfg.port     = conf.get("db_port", "5432");
        db_cfg.dbname   = conf.get("db_name", "seahorse");
        db_cfg.user     = conf.get("db_user", "seahorse");
        db_cfg.password = conf.get("db_pass", "");
        pg_store = std::make_unique<PgStore>(db_cfg, logger.get());
        if (db_cfg.enabled)
            logger->log(AsyncLogger::INFO, pg_store->is_connected()
                ? "PostgreSQL: connected to " + db_cfg.host + ":" + db_cfg.port + "/" + db_cfg.dbname
                : "PostgreSQL: connection failed — CSV fallback only.");
        else
            logger->log(AsyncLogger::INFO, "PostgreSQL: disabled.");
    }

    // -------------------------------------------------------------------------
    // PHASE 2 [REGEX ENGINE]
    // -------------------------------------------------------------------------
    {
        std::string rules_path = conf.get("rules_file", "rules.conf");
        regex_engine = std::make_unique<RegexEngine>(rules_path);
        logger->log(AsyncLogger::INFO, "Regex engine: "
            + std::to_string(regex_engine->builtin_count()) + " built-in, "
            + std::to_string(regex_engine->user_rules_loaded()) + " user rules");
    }

    // -------------------------------------------------------------------------
    // PHASE 2 [ALERT ENGINE]
    // -------------------------------------------------------------------------
    {
        AlertConfig alert_cfg;
        alert_cfg.enabled        = conf.get_bool("alert_enabled", true);
        alert_cfg.alert_log_path = conf.get("alert_log", "alerts.log");
        alert_cfg.load_defaults();
        for (auto& thresh : alert_cfg.thresholds) {
            std::string key = "alert_threshold_" + thresh.category;
            if (conf.data.count(key)) {
                std::istringstream iss(conf.get(key, ""));
                std::string tok; std::vector<int> vals;
                while (std::getline(iss, tok, ',')) { try { vals.push_back(std::stoi(tok)); } catch (...) {} }
                if (vals.size() >= 1) thresh.count = vals[0];
                if (vals.size() >= 2) thresh.window_sec = vals[1];
                if (vals.size() >= 3) thresh.cooldown_sec = vals[2];
            }
        }
        alert_engine = std::make_unique<AlertEngine>(alert_cfg);
        if (alert_cfg.enabled)
            logger->log(AsyncLogger::INFO, "Alert engine: " + alert_cfg.alert_log_path);
    }

    // -------------------------------------------------------------------------
    // PHASE 4 [TRAFFIC CLASSIFIER]: Initialize exploit detection engine
    // -------------------------------------------------------------------------
    {
        ClassifierConfig cls_cfg;
        cls_cfg.enabled = conf.get_bool("classifier_enabled", true);

        // Configurable threshold overrides from server.conf
        cls_cfg.ddos_inbound_z         = std::stod(conf.get("cls_ddos_inbound_z", "3.0"));
        cls_cfg.ddos_inbound_abs_bytes = std::stod(conf.get("cls_ddos_inbound_abs_bytes", "100000000"));
        cls_cfg.portscan_conn_refused_min = conf.get_int("cls_portscan_refused_min", 10);
        cls_cfg.brute_standard_min     = conf.get_int("cls_brute_min_failures", 5);
        cls_cfg.exfil_outbound_z       = std::stod(conf.get("cls_exfil_outbound_z", "3.0"));
        cls_cfg.exfil_outbound_abs_bytes = std::stod(conf.get("cls_exfil_outbound_abs_bytes", "50000000"));
        cls_cfg.c2_interval_jitter_max = std::stod(conf.get("cls_c2_jitter_max", "0.15"));

        BaselineTracker::Config bl_cfg;
        bl_cfg.alpha  = std::stod(conf.get("cls_baseline_alpha", "0.05"));
        bl_cfg.warmup = conf.get_int("cls_baseline_warmup", 20);
        bl_cfg.z_high   = std::stod(conf.get("cls_z_high", "3.0"));
        bl_cfg.z_medium = std::stod(conf.get("cls_z_medium", "2.5"));
        bl_cfg.z_low    = std::stod(conf.get("cls_z_low", "2.0"));

        classifier = std::make_unique<TrafficClassifier>(cls_cfg, bl_cfg);

        if (cls_cfg.enabled) {
            logger->log(AsyncLogger::INFO,
                "Traffic classifier: ENABLED | 6 attack categories | MITRE ATT&CK tagging"
                " | baseline alpha=" + conf.get("cls_baseline_alpha", "0.05")
                + " warmup=" + std::to_string(bl_cfg.warmup) + " samples");
        } else {
            logger->log(AsyncLogger::INFO, "Traffic classifier: disabled.");
        }
    }

    // -------------------------------------------------------------------------
    // PHASE 5 [THREAT INTEL]: Initialize IoC feed engine
    // -------------------------------------------------------------------------
    {
        ThreatIntelEngine::Config ti_cfg;
        ti_cfg.enabled            = conf.get_bool("threat_intel_enabled", true);
        ti_cfg.feeds_dir          = conf.get("feeds_dir", "feeds");
        ti_cfg.reload_interval_s  = conf.get_int("feeds_reload_interval_s", 300);

        threat_intel = std::make_unique<ThreatIntelEngine>(ti_cfg);

        if (ti_cfg.enabled) {
            logger->log(AsyncLogger::INFO,
                "Threat Intel: ENABLED | " + std::to_string(threat_intel->feed_count()) + " feeds loaded"
                " | " + std::to_string(threat_intel->total_iocs()) + " IoCs"
                " (" + std::to_string(threat_intel->ip_count()) + " IPs, "
                + std::to_string(threat_intel->domain_count()) + " domains, "
                + std::to_string(threat_intel->hash_count()) + " hashes)"
                " | reload every " + std::to_string(ti_cfg.reload_interval_s) + "s"
                " | dir=" + ti_cfg.feeds_dir);
        } else {
            logger->log(AsyncLogger::INFO, "Threat Intel: disabled.");
        }
    }

    // -------------------------------------------------------------------------
    // 2. Security (Phase 3)
    // -------------------------------------------------------------------------
    init_openssl();
    SSL_CTX* ctx = create_server_context(conf);

    // -------------------------------------------------------------------------
    // 3. Network Setup
    // -------------------------------------------------------------------------
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) { logger->log(AsyncLogger::ERROR_LOG, "Socket creation failed."); return 1; }
    int optval = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&optval, sizeof(optval));

#ifdef _WIN32
    DWORD timeout = 1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
#else
    struct timeval ltv;
    ltv.tv_sec = 1; ltv.tv_usec = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&ltv, sizeof(ltv));
#endif

    sockaddr_in a = { AF_INET, htons(static_cast<uint16_t>(port)) };
    a.sin_addr.s_addr = INADDR_ANY;
    if (bind(s, (sockaddr*)&a, sizeof(a)) < 0) {
        logger->log(AsyncLogger::ERROR_LOG, "Bind failed. Port " + std::to_string(port) + " in use.");
        return 1;
    }
    listen(s, 10);
    logger->log(AsyncLogger::INFO, "Secure mTLS Server started on Port " + std::to_string(port));

    // -------------------------------------------------------------------------
    // DYNAMIC THREAD POOL
    // -------------------------------------------------------------------------
    DynamicThreadPool::Config pool_cfg;
    pool_cfg.min_threads          = conf.get_size("pool_min", 2);
    pool_cfg.max_threads          = conf.get_size("pool_max", 32);
    pool_cfg.idle_timeout_seconds = conf.get_int("pool_idle_timeout_s", 30);
    logger->log(AsyncLogger::INFO, "Thread pool: min=" + std::to_string(pool_cfg.min_threads)
                 + " max=" + std::to_string(pool_cfg.max_threads));

    // -------------------------------------------------------------------------
    // 4. Execution Loop
    // -------------------------------------------------------------------------
    {
        DynamicThreadPool pool(pool_cfg);

        std::thread diagnostics([&pool]() {
            while (g_running) {
                std::this_thread::sleep_for(std::chrono::seconds(30));
                if (!g_running) break;

                // Phase 5: Check for feed file updates
                if (threat_intel) {
                    if (threat_intel->check_and_reload()) {
                        logger->log(AsyncLogger::INFO,
                            "Threat Intel: feeds reloaded — " + std::to_string(threat_intel->total_iocs()) + " IoCs");
                    }
                }

                std::stringstream ss;
                ss << "Pool: active=" << pool.active_count()
                   << " total=" << pool.total_count()
                   << " pending=" << pool.pending_count();
                if (alert_engine) ss << " | Alerts: " << alert_engine->total_alerts_fired();
                if (classifier)  ss << " | Threats: " << g_total_threats.load()
                                    << " (devices baselined: " << classifier->baselined_devices() << ")";
                if (threat_intel) ss << " | IoC: " << threat_intel->total_iocs()
                                     << " loaded, " << threat_intel->total_matches.load() << " hits";
                if (pg_store) ss << " | DB: " << (pg_store->is_connected() ? "up" : "down");
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

        logger->log(AsyncLogger::INFO, "Shutdown signal received.");
        g_running = false;
        if (diagnostics.joinable()) diagnostics.join();
    }

    // -------------------------------------------------------------------------
    // 5. Cleanup
    // -------------------------------------------------------------------------
    logger->log(AsyncLogger::INFO, "=== Server exiting gracefully ===");
    threat_intel.reset();
    classifier.reset();
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
    return 0;
}
