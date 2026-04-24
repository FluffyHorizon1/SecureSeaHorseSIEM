#define _CRT_SECURE_NO_WARNINGS
#define NOMINMAX

// =============================================================================
// SecureSeaHorse SIEM -- Server v3.0.0 (v5.0 integration build)
// =============================================================================
// This file merges the Phase 1-15 server (v3.1.4) with the Phase 16-25
// subsystems delivered in the v5.0 package. Every new subsystem is gated by
// its own *_enabled config flag so existing deployments upgrade cleanly.
//
// Divergences from docs/SERVER_INTEGRATION_SNIPPETS.md have been adapted to
// the real header APIs in src/server/. See DIVERGENCE_LOG.md shipped with
// this build for a point-by-point audit trail.
// =============================================================================

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libpq.lib")
typedef int socklen_t;
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#define INVALID_SOCKET -1
#define closesocket close
using SOCKET = int;
#endif

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
#include <filesystem>

#include <openssl/ssl.h>
#include <openssl/err.h>

// --- Phase 1-15 headers (unchanged from v3.1.4) ---
#include "server_protocol.h"
#include "crypto_utils.h"
#include "regex_engine.h"
#include "alert_engine.h"
#include "db_layer.h"
#include "traffic_classifier.h"
#include "threat_intel.h"
#include "fim_common.h"
#include "fim_monitor.h"
#include "rest_server.h"
#include "dashboard_html.h"
#include "incident_response.h"
#include "fleet_manager.h"
#include "network_inspector.h"
#include "process_monitor.h"
#include "connection_inventory.h"
#include "session_tracker.h"
#include "software_inventory.h"
#include "correlation_engine.h"

// --- Phases 16-25 headers (v5.0) ---
#include "sigma_engine.h"       // Phase 16
#include "report_generator.h"   // Phase 18
#include "usb_monitor.h"        // Phase 19 (shared struct + deserializer)
#include "rbac.h"               // Phase 20
#include "soar_connector.h"     // Phase 21 (patched: internal HttpResponse renamed to SoarHttpResponse)
#include "syslog_io.h"          // Phase 22
#include "hunt_query.h"         // Phase 23
#include "ml_anomaly.h"         // Phase 24

// =============================================================================
// GLOBAL CONTROL
// =============================================================================
std::atomic<bool> g_running(true);

void handle_signal(int sig) {
    (void)sig;
    g_running = false;
}

// =============================================================================
// GLOBAL SERVICES (Phase 1-15)
// =============================================================================
static std::unique_ptr<AsyncLogger>        logger;
static std::unique_ptr<PgStore>            pg_store;
static std::unique_ptr<RegexEngine>        regex_engine;
static std::unique_ptr<AlertEngine>        alert_engine;
static std::unique_ptr<TrafficClassifier>  classifier;
static std::unique_ptr<ThreatIntelEngine>  threat_intel;
static std::unique_ptr<FimMonitor>         fim_monitor;
static std::unique_ptr<RestServer>         rest_server;
static std::unique_ptr<IncidentResponseEngine> ir_engine;
static std::unique_ptr<FleetManager>       fleet_mgr;
static std::unique_ptr<NetworkInspector>   net_inspector;
static std::unique_ptr<CorrelationEngine>  correlator;
static std::chrono::steady_clock::time_point server_start_time;

// =============================================================================
// GLOBAL SERVICES (Phases 16-25)
// =============================================================================
static std::unique_ptr<SigmaEngine>       sigma;       // Phase 16
static std::unique_ptr<ReportGenerator>   reporter;    // Phase 18
static std::unique_ptr<RbacManager>       rbac;        // Phase 20
static std::unique_ptr<SoarConnector>     soar;        // Phase 21
static std::unique_ptr<SyslogListener>    syslog_in;   // Phase 22 listener
static std::unique_ptr<SyslogForwarder>   syslog_out;  // Phase 22 forwarder
static std::unique_ptr<MlAnomalyDetector> ml;          // Phase 24
static std::atomic<size_t> g_ml_findings{0};
static std::atomic<bool>   g_hunt_enabled{false};      // Phase 23 (gate via compile_hunt free fn)

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
// PHASE 19: USB change stringifier (helper; usb_monitor.h does not ship one)
// =============================================================================
inline std::string usb_change_str(UsbChangeType t) {
    switch (t) {
        case UsbChangeType::USB_INSERTED:     return "inserted";
        case UsbChangeType::USB_REMOVED:      return "removed";
        case UsbChangeType::USB_UNAUTHORIZED: return "unauthorized";
    }
    return "unknown";
}

// =============================================================================
// TINY JSON FIELD EXTRACTOR
// =============================================================================
// Minimal string-value extractor for the new REST endpoints. We only need to
// read single scalar strings out of flat request bodies ("username",
// "password", "token", "query", "framework", "action", "target"), so a full
// JSON parser is overkill and would drag in a new dependency.
// =============================================================================
static std::string json_field(const std::string& body, const std::string& key) {
    std::string needle = "\"" + key + "\"";
    size_t k = body.find(needle);
    if (k == std::string::npos) return "";
    size_t colon = body.find(':', k + needle.size());
    if (colon == std::string::npos) return "";
    size_t i = colon + 1;
    while (i < body.size() && (body[i] == ' ' || body[i] == '\t' || body[i] == '\n' || body[i] == '\r')) i++;
    if (i >= body.size() || body[i] != '"') return "";
    i++;
    std::string out;
    while (i < body.size() && body[i] != '"') {
        if (body[i] == '\\' && i + 1 < body.size()) {
            char n = body[i + 1];
            if      (n == '"')  out += '"';
            else if (n == '\\') out += '\\';
            else if (n == '/')  out += '/';
            else if (n == 'n')  out += '\n';
            else if (n == 't')  out += '\t';
            else if (n == 'r')  out += '\r';
            else                out += n;
            i += 2;
        } else {
            out += body[i++];
        }
    }
    return out;
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
// OPENSSL HELPERS -- Phase 3
// =============================================================================
void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

SSL_CTX* create_server_context(const AppConfig& conf) {
    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) { logger->log(AsyncLogger::ERROR_LOG, "Unable to create SSL context"); exit(EXIT_FAILURE); }

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3
                          | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1
                          | SSL_OP_NO_COMPRESSION
                          | SSL_OP_CIPHER_SERVER_PREFERENCE
                          | SSL_OP_NO_RENEGOTIATION);
    SSL_CTX_set_cipher_list(ctx,
        "ECDHE-ECDSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:"
        "ECDHE-RSA-CHACHA20-POLY1305:"
        "ECDHE-ECDSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-AES128-GCM-SHA256");

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

    std::string crl_path = conf.get("crl_path", "");
    if (!crl_path.empty()) {
        if (load_crl(ctx, crl_path)) logger->log(AsyncLogger::INFO, "CRL loaded: " + crl_path);
        else logger->log(AsyncLogger::WARN, "CRL load failed: " + crl_path);
    }

    if (conf.get_bool("ocsp_stapling", false)) {
        enable_ocsp_stapling_server(ctx);
        logger->log(AsyncLogger::INFO, "OCSP stapling: server support enabled.");
    }

    return ctx;
}

// =============================================================================
// PROCESSING LOGIC -- Phase 2 + 3 + 4 + 5 + 8 + 9 + 10 + 15 (+ 16, 21, 24)
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

        std::string raw_log(current.raw_log_chunk,
            strnlen(current.raw_log_chunk, sizeof(current.raw_log_chunk)));

        std::vector<SecurityEvent> sec_events;
        int new_fails = 0;
        if (regex_engine) {
            sec_events = regex_engine->analyze(raw_log);
            new_fails  = regex_engine->count_by_category(sec_events, "auth_failure");
        }
        state->failed_login_count += new_fails;

        if (pg_store) {
            for (const auto& ev : sec_events) {
                pg_store->insert_security_event(
                    current.device_id, current.timestamp_ms,
                    current.machine_ip,
                    ev.rule_name, ev.severity,
                    ev.category, ev.matched_text);
            }
        }

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

        // Snapshot deltas we'll need for ML BEFORE overwriting state->last_report
        uint64_t net_in_delta  = (current.net_bytes_in  >= last.net_bytes_in)
                               ?  current.net_bytes_in  - last.net_bytes_in  : 0;
        uint64_t net_out_delta = (current.net_bytes_out >= last.net_bytes_out)
                               ?  current.net_bytes_out - last.net_bytes_out : 0;
        int64_t  interval_ms   = current.timestamp_ms - last.timestamp_ms;

        state->last_report = current;

        if (pg_store) {
            pg_store->insert_telemetry(
                current.device_id, current.timestamp_ms,
                current.machine_name, current.machine_ip, current.os_user,
                static_cast<double>(cpu_usage),
                current.ram_total_bytes, current.ram_avail_bytes,
                current.disk_total_bytes, current.disk_free_bytes,
                current.net_bytes_in, current.net_bytes_out);
        }

        if (csv_writer)
            csv_writer->write(current.timestamp_ms, current.device_id, cpu_usage, new_fails);

        double ram_pct = (current.ram_total_bytes > 0)
            ? 100.0 * (1.0 - (double)current.ram_avail_bytes / (double)current.ram_total_bytes)
            : 0.0;

        // =================================================================
        // PHASE 4 [TRAFFIC CLASSIFIER]
        // =================================================================
        if (classifier) {
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

            for (const auto& t : threats) {
                g_total_threats++;

                if (pg_store) {
                    pg_store->insert_threat_detection(
                        t.device_id, t.timestamp_ms, t.machine_ip.c_str(),
                        t.category, t.sub_type, t.severity, t.confidence,
                        t.mitre_id, t.mitre_name, t.mitre_tactic,
                        t.description, t.evidence);
                }

                std::stringstream ss;
                ss << "\033[1;33m[THREAT]\033[0m "
                   << "device=" << t.device_id
                   << " ip=" << t.machine_ip
                   << " | " << t.category << "/" << t.sub_type
                   << " | " << t.severity
                   << " conf=" << std::fixed << std::setprecision(2) << t.confidence
                   << " | MITRE " << t.mitre_id << " (" << t.mitre_tactic << ")"
                   << " | " << t.description;

                if (t.severity == "critical") {
                    logger->log(AsyncLogger::ERROR_LOG, ss.str());
                } else if (t.severity == "high") {
                    logger->log(AsyncLogger::WARN, ss.str());
                } else {
                    logger->log(AsyncLogger::INFO, ss.str());
                }

                if (ir_engine) {
                    Incident inc;
                    inc.device_id = t.device_id; inc.timestamp_ms = t.timestamp_ms;
                    inc.machine_ip = t.machine_ip; inc.source = "traffic_classifier";
                    inc.category = t.category; inc.severity = t.severity;
                    inc.mitre_id = t.mitre_id; inc.description = t.description;
                    ir_engine->report_incident(inc);
                }
                if (fleet_mgr) fleet_mgr->increment_threats(t.device_id);
                if (correlator) {
                    CorrEvent ce;
                    ce.device_id = t.device_id; ce.timestamp_ms = t.timestamp_ms;
                    ce.source = "traffic"; ce.category = t.category;
                    ce.severity = t.severity; ce.machine_ip = t.machine_ip;
                    ce.detail = t.description;
                    correlator->ingest(ce);
                }

                // =========================================================
                // PHASE 21 [SOAR]: Forward every high+ threat to SOAR
                // =========================================================
                if (soar && (t.severity == "high" || t.severity == "critical")) {
                    SoarOutbound out;
                    out.timestamp_ms = t.timestamp_ms;
                    out.device_id    = t.device_id;
                    out.severity     = t.severity;
                    out.type         = "alert";
                    out.title        = t.category + "/" + t.sub_type;
                    out.mitre_id     = t.mitre_id;
                    out.source       = "traffic_classifier";
                    out.description  = t.description;
                    out.fields["category"]    = t.category;
                    out.fields["sub_type"]    = t.sub_type;
                    out.fields["machine_ip"]  = t.machine_ip;
                    soar->push(out);
                }
            }
        }

        // =================================================================
        // PHASE 5 [THREAT INTEL]
        // =================================================================
        if (threat_intel) {
            std::vector<IoCMatch> ioc_matches = threat_intel->match(
                current.machine_ip,
                current.machine_name,
                current.os_user,
                raw_log);

            for (const auto& m : ioc_matches) {
                threat_intel->total_matches++;

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

                if (ir_engine) {
                    Incident inc;
                    inc.device_id = current.device_id; inc.timestamp_ms = current.timestamp_ms;
                    inc.machine_ip = current.machine_ip; inc.source = "threat_intel";
                    inc.category = "ioc_match"; inc.severity = m.ioc.severity;
                    inc.mitre_id = m.ioc.mitre_id; inc.description = m.ioc.description;
                    inc.ioc_value = m.ioc.value;
                    ir_engine->report_incident(inc);
                }
                if (fleet_mgr) fleet_mgr->increment_ioc_hits(current.device_id);

                // Phase 21: forward critical IoC hits to SOAR too
                if (soar && (m.ioc.severity == "high" || m.ioc.severity == "critical")) {
                    SoarOutbound out;
                    out.timestamp_ms = current.timestamp_ms;
                    out.device_id    = current.device_id;
                    out.severity     = m.ioc.severity;
                    out.type         = "observable";
                    out.title        = "IoC hit: " + ioc_type_str(m.ioc.type);
                    out.mitre_id     = m.ioc.mitre_id;
                    out.source       = "threat_intel";
                    out.description  = m.ioc.description;
                    out.fields["ioc_type"]    = ioc_type_str(m.ioc.type);
                    out.fields["ioc_value"]   = m.ioc.value;
                    out.fields["feed"]        = m.ioc.feed_source;
                    out.fields["machine_ip"]  = current.machine_ip;
                    soar->push(out);
                }
            }
        }

        // =================================================================
        // PHASE 9 [FLEET MANAGER]
        // =================================================================
        if (fleet_mgr) {
            fleet_mgr->update_telemetry(current.device_id,
                current.machine_name, current.machine_ip,
                "", current.timestamp_ms);
        }

        // =================================================================
        // PHASE 10 [NETWORK INSPECTOR]
        // =================================================================
        if (net_inspector && !raw_log.empty()) {
            auto net_findings = net_inspector->inspect(raw_log, current.device_id, current.machine_ip);
            auto conn_findings = net_inspector->check_connections(current.device_id, current.machine_ip);
            net_findings.insert(net_findings.end(), conn_findings.begin(), conn_findings.end());

            for (const auto& nf : net_findings) {
                if (pg_store) {
                    pg_store->insert_threat_detection(
                        nf.device_id, nf.timestamp_ms, nf.machine_ip.c_str(),
                        nf.category, nf.indicator, nf.severity, nf.confidence,
                        nf.mitre_id, "", "", nf.description, nf.raw_evidence);
                }
                g_total_threats++;

                if (fleet_mgr) fleet_mgr->increment_threats(nf.device_id);

                logger->log(nf.severity == "high" || nf.severity == "critical"
                    ? AsyncLogger::WARN : AsyncLogger::INFO,
                    "[NET] " + nf.category + " | dev=" + std::to_string(nf.device_id)
                    + " | " + nf.severity + " | " + nf.description);

                if (ir_engine) {
                    Incident inc;
                    inc.device_id = nf.device_id;
                    inc.timestamp_ms = nf.timestamp_ms;
                    inc.machine_ip = nf.machine_ip;
                    inc.source = "network_inspector";
                    inc.category = nf.category;
                    inc.severity = nf.severity;
                    inc.mitre_id = nf.mitre_id;
                    inc.description = nf.description;
                    inc.ioc_value = nf.indicator;
                    ir_engine->report_incident(inc);
                }
            }

            net_inspector->update_connections(current.device_id,
                0, 0, 0, current.timestamp_ms);
        }

        // =================================================================
        // PHASE 16 [SIGMA RULE ENGINE]
        // =================================================================
        // Real SigmaEngine::evaluate() is void and routes hits via a callback
        // installed at init-time. Populate the event's `fields` map with the
        // full telemetry snapshot so Sigma rules can match on resource
        // metrics and network deltas in addition to the log message.
        if (sigma) {
            double disk_free_pct = (current.disk_total_bytes > 0)
                ? 100.0 * static_cast<double>(current.disk_free_bytes)
                        / static_cast<double>(current.disk_total_bytes)
                : 0.0;

            SigmaEvent ev;
            ev.source       = "telemetry";
            ev.category     = "log";
            ev.device_id    = current.device_id;
            ev.timestamp_ms = current.timestamp_ms;
            // Identity / log content
            ev.fields["Message"]        = raw_log;
            ev.fields["User"]           = current.os_user;
            ev.fields["Computer"]       = current.machine_name;
            ev.fields["SourceIp"]       = current.machine_ip;
            // Resource metrics
            ev.fields["CpuPct"]         = std::to_string(static_cast<int>(cpu_usage));
            ev.fields["RamPct"]         = std::to_string(static_cast<int>(ram_pct));
            ev.fields["DiskFreePct"]    = std::to_string(static_cast<int>(disk_free_pct));
            ev.fields["RamTotalBytes"]  = std::to_string(current.ram_total_bytes);
            ev.fields["RamAvailBytes"]  = std::to_string(current.ram_avail_bytes);
            ev.fields["DiskTotalBytes"] = std::to_string(current.disk_total_bytes);
            ev.fields["DiskFreeBytes"]  = std::to_string(current.disk_free_bytes);
            // Network (cumulative counters plus per-interval deltas)
            ev.fields["NetBytesIn"]     = std::to_string(current.net_bytes_in);
            ev.fields["NetBytesOut"]    = std::to_string(current.net_bytes_out);
            ev.fields["NetDeltaIn"]     = std::to_string(net_in_delta);
            ev.fields["NetDeltaOut"]    = std::to_string(net_out_delta);
            // Auth / event telemetry
            ev.fields["AuthFailures"]   = std::to_string(new_fails);
            ev.fields["EventCount"]     = std::to_string(sec_events.size());
            ev.fields["IntervalMs"]     = std::to_string(interval_ms);
            sigma->evaluate(ev);
        }

        // =================================================================
        // PHASE 24 [ML ANOMALY DETECTION]
        // =================================================================
        if (ml) {
            AnomalyFeatures feat;
            feat.cpu_pct        = static_cast<double>(cpu_usage);
            feat.ram_pct        = ram_pct;
            feat.net_in_rate    = static_cast<double>(net_in_delta);
            feat.net_out_rate   = static_cast<double>(net_out_delta);
            feat.event_rate     = static_cast<double>(sec_events.size());
            feat.auth_fail_rate = static_cast<double>(new_fails);
            feat.interval_ms    = static_cast<double>(interval_ms);

            auto findings = ml->observe(current.device_id, current.timestamp_ms,
                                        current.machine_ip, feat);
            for (const auto& f : findings) {
                g_ml_findings++;
                if (pg_store) {
                    pg_store->insert_threat_detection(
                        f.device_id, f.timestamp_ms, f.machine_ip.c_str(),
                        "ml_anomaly", f.detector, f.severity, f.confidence,
                        f.mitre_id, "", f.mitre_tactic, f.description, f.evidence);
                }
                logger->log(AsyncLogger::WARN,
                    "[ML] " + f.detector + " | dev=" + std::to_string(f.device_id)
                    + " | score=" + std::to_string(f.score) + " | " + f.description);

                if (ir_engine && (f.severity == "high" || f.severity == "critical")) {
                    Incident inc;
                    inc.device_id = f.device_id; inc.timestamp_ms = f.timestamp_ms;
                    inc.machine_ip = f.machine_ip; inc.source = "ml_anomaly";
                    inc.category = f.detector; inc.severity = f.severity;
                    inc.mitre_id = f.mitre_id; inc.description = f.description;
                    ir_engine->report_incident(inc);
                }

                if (soar && (f.severity == "high" || f.severity == "critical")) {
                    SoarOutbound out;
                    out.timestamp_ms = f.timestamp_ms;
                    out.device_id    = f.device_id;
                    out.severity     = f.severity;
                    out.type         = "alert";
                    out.title        = "ML anomaly: " + f.detector;
                    out.mitre_id     = f.mitre_id;
                    out.source       = "ml_anomaly";
                    out.description  = f.description;
                    out.fields["detector"]   = f.detector;
                    out.fields["score"]      = std::to_string(f.score);
                    out.fields["machine_ip"] = f.machine_ip;
                    soar->push(out);
                }
            }
        }

        // =================================================================
        // PHASE 8 [INCIDENT RESPONSE]: Route alert events
        // =================================================================
        if (ir_engine && alert_engine) {
            for (const auto& ev : sec_events) {
                if (ev.severity == "high" || ev.severity == "critical") {
                    Incident inc;
                    inc.device_id = current.device_id;
                    inc.timestamp_ms = current.timestamp_ms;
                    inc.machine_ip = current.machine_ip;
                    inc.source = "alert_engine";
                    inc.category = ev.rule_name;
                    inc.severity = ev.severity;
                    inc.description = ev.matched_text;
                    ir_engine->report_incident(inc);
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
// PHASE 6: PROCESS FIM REPORT
// =============================================================================
void process_fim_report(const char* payload_data, uint32_t payload_len,
                         const std::string& client_ip)
{
    if (!fim_monitor) return;

    std::string data(payload_data, payload_len);
    FimReport report;
    if (!FimReport::deserialize(data, report)) {
        logger->log(AsyncLogger::WARN, "FIM: Failed to deserialize report from " + client_ip);
        return;
    }

    logger->log(AsyncLogger::INFO, "FIM: Report from device " + std::to_string(report.device_id)
        + " -- " + std::to_string(report.entries.size()) + " files");

    std::vector<FimAlert> alerts = fim_monitor->process(report, client_ip);

    for (const auto& a : alerts) {
        if (pg_store) {
            pg_store->insert_fim_event(
                a.device_id, a.timestamp_ms, a.machine_ip.c_str(),
                fim_change_str(a.change_type), a.path,
                a.old_hash, a.new_hash,
                a.old_size, a.new_size,
                a.severity, a.mitre_id, a.description);
        }

        std::stringstream ss;
        ss << "\033[1;35m[FIM]\033[0m "
           << "device=" << a.device_id
           << " | " << fim_change_str(a.change_type)
           << " | " << a.severity
           << " | " << a.path;
        if (!a.mitre_id.empty()) ss << " | MITRE " << a.mitre_id;
        if (a.change_type == FimChangeType::FIM_MODIFIED)
            ss << " | hash=" << a.old_hash.substr(0, 12) << "->" << a.new_hash.substr(0, 12);

        if (a.severity == "critical") {
            logger->log(AsyncLogger::ERROR_LOG, ss.str());
        } else if (a.severity == "high") {
            logger->log(AsyncLogger::WARN, ss.str());
        } else {
            logger->log(AsyncLogger::INFO, ss.str());
        }

        if (ir_engine) {
            Incident inc;
            inc.device_id = a.device_id; inc.timestamp_ms = a.timestamp_ms;
            inc.machine_ip = a.machine_ip; inc.source = "fim";
            inc.category = "fim_" + fim_change_str(a.change_type);
            inc.severity = a.severity; inc.mitre_id = a.mitre_id;
            inc.description = a.description; inc.file_path = a.path;
            ir_engine->report_incident(inc);
        }
        if (fleet_mgr) fleet_mgr->increment_fim_changes(a.device_id);

        if (soar && (a.severity == "high" || a.severity == "critical")) {
            SoarOutbound out;
            out.timestamp_ms = a.timestamp_ms;
            out.device_id    = a.device_id;
            out.severity     = a.severity;
            out.type         = "incident";
            out.title        = "FIM " + fim_change_str(a.change_type) + ": " + a.path;
            out.mitre_id     = a.mitre_id;
            out.source       = "fim";
            out.description  = a.description;
            out.fields["path"]       = a.path;
            out.fields["change"]     = fim_change_str(a.change_type);
            out.fields["machine_ip"] = a.machine_ip;
            soar->push(out);
        }
    }

    if (fleet_mgr) fleet_mgr->update_fim(report.device_id);
}

// =============================================================================
// PHASE 11: PROCESS PROCESS REPORT
// =============================================================================
void process_process_report(const char* data, uint32_t len, const std::string& client_ip) {
    std::string payload(data, len);
    ProcessReport report = deserialize_process_report(payload);
    if (report.device_id == 0) return;

    logger->log(AsyncLogger::INFO,
        "[PROC] device=" + std::to_string(report.device_id) + " processes=" + std::to_string(report.processes.size())
        + " changes=" + std::to_string(report.changes.size()));

    for (const auto& c : report.changes) {
        if (c.type == ProcessChangeType::PROC_SUSPICIOUS) {
            logger->log(AsyncLogger::WARN,
                "[PROC] SUSPICIOUS: device=" + std::to_string(report.device_id)
                + " pid=" + std::to_string(c.process.pid)
                + " name=" + c.process.name + " | " + c.reason);

            if (correlator) {
                CorrEvent ce;
                ce.device_id = report.device_id; ce.timestamp_ms = report.timestamp_ms;
                ce.source = "process"; ce.category = "suspicious";
                ce.severity = "high"; ce.machine_ip = client_ip;
                ce.indicator = c.process.name; ce.detail = c.reason;
                correlator->ingest(ce);
            }

            if (ir_engine) {
                Incident inc;
                inc.device_id = report.device_id; inc.timestamp_ms = report.timestamp_ms;
                inc.machine_ip = client_ip; inc.source = "process_monitor";
                inc.category = "suspicious_process"; inc.severity = "high";
                inc.description = c.reason + ": " + c.process.name;
                ir_engine->report_incident(inc);
            }

            // Phase 16: route to Sigma (process_creation category)
            if (sigma) {
                SigmaEvent ev;
                ev.source       = "process";
                ev.category     = "process_creation";
                ev.device_id    = report.device_id;
                ev.timestamp_ms = report.timestamp_ms;
                ev.fields["Image"]       = c.process.path;
                ev.fields["CommandLine"] = c.process.cmdline;
                ev.fields["ProcessName"] = c.process.name;
                ev.fields["User"]        = c.process.user;
                sigma->evaluate(ev);
            }
        }
    }
    if (fleet_mgr) fleet_mgr->update_telemetry(report.device_id, "", client_ip, "", report.timestamp_ms);
}

// =============================================================================
// PHASE 12: PROCESS CONNECTION REPORT
// =============================================================================
void process_connection_report(const char* data, uint32_t len, const std::string& client_ip) {
    std::string payload(data, len);
    ConnectionReport report = deserialize_connection_report(payload);
    if (report.device_id == 0) return;

    logger->log(AsyncLogger::INFO,
        "[CONN] device=" + std::to_string(report.device_id) + " connections=" + std::to_string(report.connections.size())
        + " changes=" + std::to_string(report.changes.size()));

    for (const auto& ch : report.changes) {
        if (ch.type == ConnChangeType::CONN_SUSPICIOUS) {
            logger->log(AsyncLogger::WARN,
                "[CONN] SUSPICIOUS: device=" + std::to_string(report.device_id)
                + " remote=" + ch.conn.remote_addr + ":" + std::to_string(ch.conn.remote_port)
                + " | " + ch.reason);

            if (correlator) {
                CorrEvent ce;
                ce.device_id = report.device_id; ce.timestamp_ms = report.timestamp_ms;
                ce.source = "connection"; ce.category = "suspicious_connection";
                ce.severity = "medium"; ce.machine_ip = client_ip;
                ce.indicator = ch.conn.remote_addr; ce.detail = ch.reason;
                correlator->ingest(ce);
            }
        }
    }
}

// =============================================================================
// PHASE 13: PROCESS SESSION REPORT
// =============================================================================
void process_session_report(const char* data, uint32_t len, const std::string& client_ip) {
    std::string payload(data, len);
    SessionReport report = deserialize_session_report(payload);
    if (report.device_id == 0) return;

    logger->log(AsyncLogger::INFO,
        "[SESS] device=" + std::to_string(report.device_id) + " sessions=" + std::to_string(report.active_sessions.size())
        + " auth_events=" + std::to_string(report.auth_events.size())
        + " failed=" + std::to_string(report.failed_logins));

    for (const auto& a : report.auth_events) {
        if (a.type == AuthEventType::AUTH_LOGIN_FAILED) {
            if (correlator) {
                CorrEvent ce;
                ce.device_id = report.device_id; ce.timestamp_ms = a.timestamp_ms;
                ce.source = "session"; ce.category = "login_failed";
                ce.severity = "medium"; ce.machine_ip = client_ip;
                ce.target_user = a.username; ce.indicator = a.source_ip;
                ce.detail = a.detail;
                correlator->ingest(ce);
            }
        } else if (a.type == AuthEventType::AUTH_PRIVILEGE_ESCALATION) {
            logger->log(AsyncLogger::WARN,
                "[SESS] PRIV_ESC: device=" + std::to_string(report.device_id)
                + " user=" + a.username + " | " + a.detail);
            if (correlator) {
                CorrEvent ce;
                ce.device_id = report.device_id; ce.timestamp_ms = a.timestamp_ms;
                ce.source = "session"; ce.category = "priv_escalation";
                ce.severity = "high"; ce.machine_ip = client_ip;
                ce.target_user = a.username; ce.detail = a.detail;
                correlator->ingest(ce);
            }
        }
    }
    if (fleet_mgr) fleet_mgr->increment_alerts(report.device_id, report.failed_logins);
}

// =============================================================================
// PHASE 14: PROCESS SOFTWARE REPORT
// =============================================================================
void process_software_report(const char* data, uint32_t len, const std::string& client_ip) {
    std::string payload(data, len);
    SoftwareReport report = deserialize_software_report(payload);
    if (report.device_id == 0) return;

    logger->log(AsyncLogger::INFO,
        "[SW] device=" + std::to_string(report.device_id) + " software=" + std::to_string(report.software.size())
        + " changes=" + std::to_string(report.changes.size()));

    for (const auto& c : report.changes) {
        std::string type_str = "installed";
        if (c.type == SoftwareChangeType::SW_REMOVED) type_str = "removed";
        else if (c.type == SoftwareChangeType::SW_UPDATED) type_str = "updated";

        logger->log(AsyncLogger::INFO,
            "[SW] " + type_str + ": " + c.software.name + " " + c.software.version
            + (c.old_version.empty() ? "" : " (was " + c.old_version + ")")
            + " on device " + std::to_string(report.device_id));
    }
    (void)client_ip;
}

// =============================================================================
// PHASE 19: PROCESS USB REPORT  (NEW)
// =============================================================================
void process_usb_report(const char* data, uint32_t len, const std::string& client_ip) {
    std::string payload(data, len);
    UsbReport report = deserialize_usb_report(payload);
    if (report.device_id == 0) return;

    logger->log(AsyncLogger::INFO,
        "[USB] device=" + std::to_string(report.device_id)
        + " present=" + std::to_string(report.devices.size())
        + " changes=" + std::to_string(report.changes.size()));

    for (const auto& ch : report.changes) {
        // Real enum values: USB_INSERTED / USB_REMOVED / USB_UNAUTHORIZED
        std::string sev = "low";
        if (ch.type == UsbChangeType::USB_UNAUTHORIZED) sev = "high";
        else if (ch.type == UsbChangeType::USB_INSERTED && ch.device.device_class == "storage") sev = "medium";

        logger->log(sev == "high" ? AsyncLogger::WARN : AsyncLogger::INFO,
            "[USB] " + usb_change_str(ch.type)
            + " | dev=" + std::to_string(report.device_id)
            + " | " + ch.device.vendor_id + ":" + ch.device.product_id
            + " " + ch.device.product_name);

        if (correlator) {
            CorrEvent ce;
            ce.device_id = report.device_id; ce.timestamp_ms = report.timestamp_ms;
            ce.source = "usb"; ce.category = usb_change_str(ch.type);
            ce.severity = sev; ce.machine_ip = client_ip;
            ce.indicator = ch.device.vendor_id + ":" + ch.device.product_id;
            correlator->ingest(ce);
        }
        if (ir_engine && ch.type == UsbChangeType::USB_UNAUTHORIZED) {
            Incident inc;
            inc.device_id = report.device_id; inc.timestamp_ms = report.timestamp_ms;
            inc.machine_ip = client_ip; inc.source = "usb_monitor";
            inc.category = "usb_unauthorized"; inc.severity = "high";
            inc.description = "Unauthorised USB device: "
                + ch.device.vendor_id + ":" + ch.device.product_id
                + (ch.device.product_name.empty() ? "" : " (" + ch.device.product_name + ")");
            ir_engine->report_incident(inc);
        }
        if (soar && ch.type == UsbChangeType::USB_UNAUTHORIZED) {
            SoarOutbound out;
            out.timestamp_ms = report.timestamp_ms;
            out.device_id    = report.device_id;
            out.severity     = "high";
            out.type         = "incident";
            out.title        = "Unauthorised USB device";
            out.source       = "usb_monitor";
            out.description  = ch.device.vendor_id + ":" + ch.device.product_id
                             + " on " + client_ip;
            out.fields["vid_pid"]     = ch.device.vendor_id + ":" + ch.device.product_id;
            out.fields["serial"]      = ch.device.serial;
            out.fields["device_class"]= ch.device.device_class;
            out.fields["machine_ip"]  = client_ip;
            soar->push(out);
        }
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
// CLIENT HANDLER
// =============================================================================
void handle_client_ssl(SSL* ssl, SOCKET sock) {
    if (SSL_accept(ssl) <= 0) {
        logger->log(AsyncLogger::WARN, "TLS handshake failed (Mutual Auth required).");
        SSL_free(ssl);
        closesocket(sock);
        return;
    }

    logger->log(AsyncLogger::INFO, "TLS session established. Cipher: " + std::string(SSL_get_cipher(ssl)));

    std::string peer_ip = "unknown";
    {
        struct sockaddr_in peer_addr;
        socklen_t peer_len = sizeof(peer_addr);
        if (getpeername(sock, (struct sockaddr*)&peer_addr, &peer_len) == 0) {
            char ip_buf[INET_ADDRSTRLEN] = {0};
            inet_ntop(AF_INET, &peer_addr.sin_addr, ip_buf, sizeof(ip_buf));
            peer_ip = ip_buf;
        }
    }

    uint8_t hmac_key[HMAC_KEY_LEN] = {0};
    bool hmac_ready = false;
    if (g_hmac_enabled) {
        if (derive_hmac_key(ssl, hmac_key)) {
            hmac_ready = true;
            logger->log(AsyncLogger::DEBUG, "HMAC session key derived.");
        } else {
            logger->log(AsyncLogger::WARN, "HMAC derivation failed -- v1 fallback.");
        }
    }

#ifdef _WIN32
    DWORD read_timeout = g_connection_timeout * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&read_timeout, sizeof(read_timeout));
#else
    struct timeval tv;
    tv.tv_sec = g_connection_timeout; tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
#endif

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
                case MSG_FIM_REPORT: {
                    if (plen > 0) process_fim_report(payload.data(), plen, peer_ip);
                    break;
                }
                case MSG_PROCESS_REPORT: {
                    if (plen > 0) process_process_report(payload.data(), plen, peer_ip);
                    break;
                }
                case MSG_CONN_REPORT: {
                    if (plen > 0) process_connection_report(payload.data(), plen, peer_ip);
                    break;
                }
                case MSG_SESSION_REPORT: {
                    if (plen > 0) process_session_report(payload.data(), plen, peer_ip);
                    break;
                }
                case MSG_SOFTWARE_REPORT: {
                    if (plen > 0) process_software_report(payload.data(), plen, peer_ip);
                    break;
                }
                case MSG_USB_REPORT: {   // Phase 19 (v5.0)
                    if (plen > 0) process_usb_report(payload.data(), plen, peer_ip);
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
// MAIN
// =============================================================================
int main(int argc, char* argv[]) {
    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    CliArgs cli = parse_server_cli(argc, argv);
    if (cli.show_help) { print_server_usage(argv[0]); return 0; }
    if (cli.show_version) { std::cout << "SecureSeaHorse Server v3.0.0 (v5.0 / Phase 25)\n"; return 0; }

#ifdef _WIN32
    WSADATA w;
    if (WSAStartup(MAKEWORD(2, 2), &w) != 0) return 1;
#endif

    AppConfig conf = load_config(cli.config_path);
    cli.apply_overrides(conf);
    int port = conf.get_int("port", 65432);

    g_hmac_enabled       = conf.get_bool("hmac_enabled", true);
    g_connection_timeout = conf.get_int("connection_timeout_s", 120);

    {
        std::string log_path = conf.get("log_file", "server.log");
        size_t max_log_size  = conf.get_size("log_max_bytes", 10 * 1024 * 1024);
        int max_log_files    = conf.get_int("log_max_files", 5);
        logger = std::make_unique<AsyncLogger>(log_path, max_log_size, max_log_files, true);
    }

    logger->log(AsyncLogger::INFO, "=== SecureSeaHorse Server v3.0.0 (v5.0 build -- Phases 1-25) starting ===");
    logger->log(AsyncLogger::INFO, "Config loaded from: " + cli.config_path);

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
                : "PostgreSQL: connection failed -- CSV fallback only.");
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
    // PHASE 4 [TRAFFIC CLASSIFIER]
    // -------------------------------------------------------------------------
    {
        ClassifierConfig cls_cfg;
        cls_cfg.enabled = conf.get_bool("classifier_enabled", true);
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
                "Traffic classifier: ENABLED | 6 attack categories | MITRE ATT&CK tagging");
        } else {
            logger->log(AsyncLogger::INFO, "Traffic classifier: disabled.");
        }
    }

    // -------------------------------------------------------------------------
    // PHASE 5 [THREAT INTEL]
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
                " | " + std::to_string(threat_intel->total_iocs()) + " IoCs");
        } else {
            logger->log(AsyncLogger::INFO, "Threat Intel: disabled.");
        }
    }

    // -------------------------------------------------------------------------
    // PHASE 6 [FIM MONITOR]
    // -------------------------------------------------------------------------
    {
        FimMonitorConfig fim_cfg;
        fim_cfg.enabled = conf.get_bool("fim_enabled", true);
        fim_cfg.default_severity = conf.get("fim_default_severity", "medium");

        std::string crit_paths = conf.get("fim_critical_paths", "");
        if (!crit_paths.empty()) {
            std::istringstream iss(crit_paths);
            std::string path;
            while (std::getline(iss, path, ',')) {
                path.erase(0, path.find_first_not_of(" \t"));
                path.erase(path.find_last_not_of(" \t") + 1);
                if (!path.empty()) fim_cfg.critical_paths.push_back(path);
            }
        }

        std::string high_paths = conf.get("fim_high_paths", "");
        if (!high_paths.empty()) {
            std::istringstream iss(high_paths);
            std::string path;
            while (std::getline(iss, path, ',')) {
                path.erase(0, path.find_first_not_of(" \t"));
                path.erase(path.find_last_not_of(" \t") + 1);
                if (!path.empty()) fim_cfg.high_paths.push_back(path);
            }
        }

        fim_monitor = std::make_unique<FimMonitor>(fim_cfg);

        if (fim_cfg.enabled) {
            logger->log(AsyncLogger::INFO,
                "FIM Monitor: ENABLED | severity_default=" + fim_cfg.default_severity);
        } else {
            logger->log(AsyncLogger::INFO, "FIM Monitor: disabled.");
        }
    }

    // -------------------------------------------------------------------------
    // PHASE 8 [INCIDENT RESPONSE]
    // -------------------------------------------------------------------------
    {
        bool ir_enabled = conf.get_bool("ir_enabled", true);
        if (ir_enabled) {
            ir_engine = std::make_unique<IncidentResponseEngine>(
                [](int level, const std::string& msg) {
                    if (logger) logger->log(static_cast<AsyncLogger::Level>(level), msg);
                });
            ir_engine->set_webhook_url(conf.get("ir_webhook_url", ""));
            ir_engine->set_script_dir(conf.get("ir_script_dir", "scripts"));
            ir_engine->start();
            logger->log(AsyncLogger::INFO,
                "Incident Response: ENABLED | " + std::to_string(ir_engine->playbook_count()) + " playbooks loaded");
        } else {
            logger->log(AsyncLogger::INFO, "Incident Response: disabled.");
        }
    }

    // -------------------------------------------------------------------------
    // PHASE 9 [FLEET MANAGER]
    // -------------------------------------------------------------------------
    {
        FleetConfig fleet_cfg;
        fleet_cfg.enabled = conf.get_bool("fleet_enabled", true);
        fleet_cfg.stale_threshold_s = conf.get_int("fleet_stale_s", 300);
        fleet_cfg.offline_threshold_s = conf.get_int("fleet_offline_s", 900);

        if (fleet_cfg.enabled) {
            fleet_mgr = std::make_unique<FleetManager>(fleet_cfg);
            logger->log(AsyncLogger::INFO, "Fleet Manager: ENABLED");
        } else {
            logger->log(AsyncLogger::INFO, "Fleet Manager: disabled.");
        }
    }

    // -------------------------------------------------------------------------
    // PHASE 10 [NETWORK INSPECTOR]
    // -------------------------------------------------------------------------
    {
        NetworkInspector::InspectorConfig ni_cfg;
        ni_cfg.dns_enabled = conf.get_bool("inspect_dns", true);
        ni_cfg.protocol_enabled = conf.get_bool("inspect_protocol", true);
        ni_cfg.connection_enabled = conf.get_bool("inspect_connections", true);
        ni_cfg.entropy_enabled = conf.get_bool("inspect_entropy", true);

        bool ni_enabled = conf.get_bool("inspector_enabled", true);
        if (ni_enabled) {
            net_inspector = std::make_unique<NetworkInspector>(ni_cfg);
            logger->log(AsyncLogger::INFO, "Network Inspector: ENABLED");
        } else {
            logger->log(AsyncLogger::INFO, "Network Inspector: disabled.");
        }
    }

    // -------------------------------------------------------------------------
    // PHASE 15 [CORRELATION ENGINE]
    // -------------------------------------------------------------------------
    {
        bool corr_enabled = conf.get_bool("correlation_enabled", true);
        if (corr_enabled) {
            correlator = std::make_unique<CorrelationEngine>(
                [](const CorrelatedIncident& inc) {
                    if (logger) {
                        logger->log(AsyncLogger::WARN,
                            "[CORR] INCIDENT #" + std::to_string(inc.incident_id)
                            + " | " + inc.rule_name + " | " + inc.severity
                            + " | devices=" + std::to_string(inc.device_ids.size())
                            + " | " + inc.description);
                    }
                    if (ir_engine) {
                        Incident ir_inc;
                        ir_inc.device_id = inc.device_ids.empty() ? 0 : inc.device_ids[0];
                        ir_inc.timestamp_ms = inc.first_seen_ms;
                        ir_inc.source = "correlation";
                        ir_inc.category = inc.rule_name;
                        ir_inc.severity = inc.severity;
                        ir_inc.mitre_id = inc.mitre_technique;
                        ir_inc.description = inc.description;
                        ir_engine->report_incident(ir_inc);
                    }
                });
            logger->log(AsyncLogger::INFO,
                "Correlation Engine: ENABLED | " + std::to_string(correlator->rule_count()) + " rules loaded");
        } else {
            logger->log(AsyncLogger::INFO, "Correlation Engine: disabled.");
        }
    }

    // =========================================================================
    // PHASE 16 [SIGMA RULE ENGINE]                                     [v5.0]
    // =========================================================================
    // Adapted from snippets: SigmaEngine takes nested `Config`, evaluate() is
    // void and routes hits through a callback we install here.
    if (conf.get_bool("sigma_enabled", true)) {
        SigmaEngine::Config sc;
        sc.enabled           = true;
        sc.rules_dir         = conf.get("sigma_rules_dir", "config/sigma_rules");
        sc.reload_interval_s = conf.get_int("sigma_reload_s", 300);
        sigma = std::make_unique<SigmaEngine>(sc, [](const SigmaHit& h) {
            g_total_threats++;
            if (pg_store) {
                // SigmaHit has rule_id / rule_title / severity / mitre_id / description /
                // matched_field / matched_value -- no confidence/mitre_name/mitre_tactic.
                std::string evidence = h.matched_field + "=" + h.matched_value;
                pg_store->insert_threat_detection(
                    h.device_id, h.timestamp_ms, h.machine_ip.c_str(),
                    "sigma", h.rule_title, h.severity, 1.0,
                    h.mitre_id, "", "",
                    h.description, evidence);
            }
            if (logger) {
                logger->log(AsyncLogger::WARN,
                    "[SIGMA] " + h.rule_title
                    + " (" + h.rule_id + ")"
                    + " | dev=" + std::to_string(h.device_id)
                    + " | " + h.severity
                    + " | " + h.description);
            }
            if (correlator) {
                CorrEvent ce;
                ce.device_id = h.device_id; ce.timestamp_ms = h.timestamp_ms;
                ce.source = "sigma"; ce.category = h.rule_title;
                ce.severity = h.severity; ce.machine_ip = h.machine_ip;
                ce.detail = h.description;
                correlator->ingest(ce);
            }
            if (ir_engine) {
                Incident inc;
                inc.device_id = h.device_id; inc.timestamp_ms = h.timestamp_ms;
                inc.machine_ip = h.machine_ip; inc.source = "sigma";
                inc.category = h.rule_title; inc.severity = h.severity;
                inc.mitre_id = h.mitre_id; inc.description = h.description;
                ir_engine->report_incident(inc);
            }
            if (soar && (h.severity == "high" || h.severity == "critical")) {
                SoarOutbound out;
                out.timestamp_ms = h.timestamp_ms;
                out.device_id    = h.device_id;
                out.severity     = h.severity;
                out.type         = "alert";
                out.title        = "Sigma: " + h.rule_title;
                out.mitre_id     = h.mitre_id;
                out.source       = "sigma";
                out.description  = h.description;
                out.fields["rule_id"]    = h.rule_id;
                out.fields["machine_ip"] = h.machine_ip;
                soar->push(out);
            }
        });
        logger->log(AsyncLogger::INFO,
            "Sigma: ENABLED | " + std::to_string(sigma->rule_count()) + " rules loaded"
            " | dir=" + sc.rules_dir);
    } else {
        logger->log(AsyncLogger::INFO, "Sigma: disabled.");
    }

    // =========================================================================
    // PHASE 18 [REPORT GENERATOR]                                      [v5.0]
    // =========================================================================
    if (conf.get_bool("reports_enabled", true)) {
        ReportGenerator::Config rc;
        rc.enabled           = true;
        rc.output_dir        = conf.get("reports_dir", "reports");
        rc.organization_name = conf.get("reports_org_name", "SecureSeaHorse Deployment");
        reporter = std::make_unique<ReportGenerator>(rc);
        logger->log(AsyncLogger::INFO,
            "Reports: ENABLED | output_dir=" + rc.output_dir);
    } else {
        logger->log(AsyncLogger::INFO, "Reports: disabled.");
    }

    // =========================================================================
    // PHASE 20 [RBAC]                                                  [v5.0]
    // =========================================================================
    // Real RbacManager::Config field names: secret / users_file / tenants_file
    // / audit_log / token_lifetime_s (not the snippet's hmac_secret etc.)
    if (conf.get_bool("rbac_enabled", false)) {
        RbacManager::Config rc;
        rc.enabled          = true;
        rc.secret           = conf.get("rbac_secret", "");
        rc.users_file       = conf.get("rbac_users_db", "rbac/users.db");
        rc.tenants_file     = conf.get("rbac_tenants_db", "rbac/tenants.db");
        rc.audit_log        = conf.get("rbac_audit_log", "rbac/audit.log");
        rc.token_lifetime_s = conf.get_int("rbac_token_ttl_s", 28800);
        if (rc.secret.empty() || rc.secret.find("changeme") != std::string::npos
                              || rc.secret.size() < 32) {
            logger->log(AsyncLogger::ERROR_LOG,
                "RBAC: rbac_secret is unset, default, or too short (<32 bytes) -- "
                "refusing to start. Set a long random value in server.conf.");
            return 1;
        }
        rbac = std::make_unique<RbacManager>(rc);
        logger->log(AsyncLogger::INFO,
            "RBAC: ENABLED | users=" + std::to_string(rbac->user_count())
            + " tenants=" + std::to_string(rbac->tenant_count())
            + " token_ttl=" + std::to_string(rc.token_lifetime_s) + "s");
    } else {
        logger->log(AsyncLogger::INFO, "RBAC: disabled.");
    }

    // =========================================================================
    // PHASE 21 [SOAR]                                                  [v5.0]
    // =========================================================================
    // Real SoarConnector::Config uses `backend` (enum) + `base_url` and exposes
    // push() / sent() / receive(). `handle_inbound(HttpRequest)` does not exist.
    if (conf.get_bool("soar_enabled", false)) {
        SoarConnector::Config sc;
        sc.enabled       = true;
        std::string b    = conf.get("soar_backend", "generic_webhook");
        if      (b == "splunk_soar")  sc.backend = SoarBackend::SPLUNK_SOAR;
        else if (b == "cortex_xsoar") sc.backend = SoarBackend::CORTEX_XSOAR;
        else if (b == "the_hive")     sc.backend = SoarBackend::THE_HIVE;
        else                          sc.backend = SoarBackend::GENERIC_WEBHOOK;
        sc.base_url          = conf.get("soar_url", "");
        sc.auth_header       = conf.get("soar_auth_header", "");
        sc.container_label   = conf.get("soar_container_label", "");
        sc.xsoar_integration = conf.get("soar_xsoar_integration", "");
        sc.worker_interval_s = conf.get_int("soar_worker_interval_s", 2);
        soar = std::make_unique<SoarConnector>(sc);
        soar->set_inbound_handler([](const SoarInbound& in) {
            if (logger) logger->log(AsyncLogger::INFO,
                "[SOAR] inbound action=" + in.action + " target=" + in.target
                + " reason=" + in.reason);
            if (!ir_engine) return;
            Incident inc;
            inc.source = "soar";
            inc.category = "soar_action";
            inc.severity = "high";
            inc.description = in.action + " -> " + in.target + " (" + in.reason + ")";
            ir_engine->report_incident(inc);
        });
        soar->start();
        logger->log(AsyncLogger::INFO,
            "SOAR: ENABLED | backend=" + backend_name(sc.backend)
            + " | url=" + sc.base_url);
    } else {
        logger->log(AsyncLogger::INFO, "SOAR: disabled.");
    }

    // =========================================================================
    // PHASE 22 [SYSLOG I/O]                                            [v5.0]
    // =========================================================================
    // Real SyslogListener::Config has udp_port/tcp_port ints + bind_address.
    // Handler is a constructor arg, not a Config field.
    {
        std::string listen_udp = conf.get("syslog_listen_udp", "");  // "host:port" or empty
        std::string listen_tcp = conf.get("syslog_listen_tcp", "");
        if (!listen_udp.empty() || !listen_tcp.empty()) {
            SyslogListener::Config lc;
            lc.enabled = true;

            auto split_hostport = [](const std::string& s,
                                     std::string& host_out, int& port_out) {
                auto colon = s.find_last_of(':');
                if (colon == std::string::npos) {
                    host_out = "0.0.0.0";
                    try { port_out = std::stoi(s); } catch (...) { port_out = 0; }
                } else {
                    host_out = s.substr(0, colon);
                    if (host_out.empty()) host_out = "0.0.0.0";
                    try { port_out = std::stoi(s.substr(colon + 1)); } catch (...) { port_out = 0; }
                }
            };

            std::string bind_addr = "0.0.0.0";
            lc.udp_port = 0;
            lc.tcp_port = 0;
            if (!listen_udp.empty()) split_hostport(listen_udp, bind_addr, lc.udp_port);
            if (!listen_tcp.empty()) {
                std::string tcp_host; int tcp_port;
                split_hostport(listen_tcp, tcp_host, tcp_port);
                bind_addr = tcp_host;   // TCP wins if both specified; they normally match
                lc.tcp_port = tcp_port;
            }
            lc.bind_address = bind_addr;

            auto handler = [](const SyslogEvent& ev) {
                if (regex_engine) {
                    auto sec_events = regex_engine->analyze(ev.message);
                    for (const auto& se : sec_events) {
                        if (pg_store) pg_store->insert_security_event(
                            0, ev.received_ms, ev.hostname.c_str(),
                            se.rule_name, se.severity, se.category, se.matched_text);
                    }
                }
                if (sigma) {
                    SigmaEvent sev;
                    sev.source       = "syslog";
                    sev.category     = ev.app_name;
                    sev.device_id    = 0;
                    sev.timestamp_ms = ev.received_ms;
                    sev.fields["Message"]  = ev.message;
                    sev.fields["Computer"] = ev.hostname;
                    sev.fields["SourceIp"] = ev.source_ip;
                    sev.fields["Service"]  = ev.app_name;
                    sigma->evaluate(sev);
                }
            };

            syslog_in = std::make_unique<SyslogListener>(lc, handler);
            syslog_in->start();
            logger->log(AsyncLogger::INFO,
                "Syslog listener: ENABLED | udp=" + std::to_string(lc.udp_port)
                + " tcp=" + std::to_string(lc.tcp_port)
                + " bind=" + lc.bind_address);
        }

        if (conf.get_bool("syslog_forward_enabled", false)) {
            SyslogForwarder::Config fc;
            fc.enabled = true;
            std::string dest  = conf.get("syslog_forward_dest", "");
            std::string proto = conf.get("syslog_forward_proto", "udp");
            std::string fmt   = conf.get("syslog_forward_format", "cef");

            auto colon = dest.find_last_of(':');
            if (colon != std::string::npos) {
                fc.host = dest.substr(0, colon);
                try { fc.port = std::stoi(dest.substr(colon + 1)); } catch (...) { fc.port = 514; }
            } else {
                fc.host = dest.empty() ? "127.0.0.1" : dest;
                fc.port = 514;
            }
            fc.use_tcp = (proto == "tcp");
            if      (fmt == "leef")    fc.format = SyslogFormat::LEEF;
            else if (fmt == "rfc5424") fc.format = SyslogFormat::RFC5424;
            else                       fc.format = SyslogFormat::CEF;
            syslog_out = std::make_unique<SyslogForwarder>(fc);
            logger->log(AsyncLogger::INFO,
                "Syslog forwarder: ENABLED | " + fc.host + ":" + std::to_string(fc.port)
                + " [" + fmt + "/" + proto + "]");
        }
    }

    // =========================================================================
    // PHASE 23 [HUNT DSL]                                              [v5.0]
    // =========================================================================
    // The real hunt_query.h exposes compile_hunt() as a free function, not a
    // HuntQueryEngine class. We gate the endpoint via g_hunt_enabled and call
    // compile_hunt() inline in the /api/hunt handler.
    if (pg_store && pg_store->is_connected()) {
        g_hunt_enabled = true;
        logger->log(AsyncLogger::INFO,
            "Hunt DSL: ENABLED (compile + execute via pg_store->query_json; "
            "falls back to SQL preview if execution returns empty)");
    }

    // =========================================================================
    // PHASE 24 [ML ANOMALY]                                            [v5.0]
    // =========================================================================
    if (conf.get_bool("ml_enabled", true)) {
        MlAnomalyDetector::Config mc;
        mc.enabled             = true;
        mc.window_size         = conf.get_size("ml_window_size", 2048);
        mc.warmup_samples      = conf.get_int("ml_warmup_samples", 128);
        mc.retrain_interval_s  = conf.get_int("ml_retrain_interval_s", 300);
        mc.score_threshold     = std::stod(conf.get("ml_score_threshold", "0.65"));
        mc.critical_threshold  = std::stod(conf.get("ml_critical_threshold", "0.85"));
        mc.forest_config.num_trees    = conf.get_int("ml_forest_trees", 64);
        mc.forest_config.subsample    = conf.get_int("ml_forest_subsample", 256);
        mc.beacon_config.max_jitter   = std::stod(conf.get("ml_beacon_max_jitter", "0.15"));
        mc.beacon_config.min_autocorr = std::stod(conf.get("ml_beacon_min_autocorr", "0.35"));
        mc.beacon_config.min_samples  = conf.get_int("ml_beacon_min_samples", 12);
        mc.beacon_config.window_size  = conf.get_size("ml_beacon_window", 64);
        ml = std::make_unique<MlAnomalyDetector>(mc);
        logger->log(AsyncLogger::INFO,
            "ML Anomaly: ENABLED | trees=" + std::to_string(mc.forest_config.num_trees)
            + " warmup=" + std::to_string(mc.warmup_samples)
            + " threshold=" + std::to_string(mc.score_threshold));
    } else {
        logger->log(AsyncLogger::INFO, "ML Anomaly: disabled.");
    }

    // -------------------------------------------------------------------------
    // Security (Phase 3)
    // -------------------------------------------------------------------------
    init_openssl();
    SSL_CTX* ctx = create_server_context(conf);

    // -------------------------------------------------------------------------
    // Network Setup
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

    server_start_time = std::chrono::steady_clock::now();

    // -------------------------------------------------------------------------
    // PHASE 7 [REST API]
    // -------------------------------------------------------------------------
    {
        RestConfig rest_cfg;
        rest_cfg.enabled      = conf.get_bool("rest_enabled", true);
        rest_cfg.port         = conf.get_int("rest_port", 8080);
        rest_cfg.bind_address = conf.get("rest_bind", "0.0.0.0");
        rest_cfg.api_token    = conf.get("rest_api_token", "");

        if (rest_cfg.enabled) {
            rest_server = std::make_unique<RestServer>(rest_cfg);

            rest_server->get("/", [](const HttpRequest&) {
                return HttpResponse::html(get_dashboard_html());
            }, false);

            // --- Stats endpoint ---
            rest_server->get("/api/stats", [](const HttpRequest&) {
                auto uptime_s = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::steady_clock::now() - server_start_time).count();

                JsonBuilder j;
                j.begin_object();
                j.kv_int("uptime_hours", uptime_s / 3600);
                j.kv_int("uptime_seconds", uptime_s);
                if (pg_store) {
                    j.kv_int("devices_online", pg_store->count_online_devices());
                    j.kv_int("total_threats", pg_store->count_table("threat_detections"));
                    j.kv_int("total_events", pg_store->count_table("security_events"));
                    j.kv_int("total_ioc_hits", pg_store->count_table("ioc_matches"));
                    j.kv_int("total_fim_changes", pg_store->count_table("fim_events"));
                } else {
                    j.kv_int("devices_online", 0);
                    j.kv_int("total_threats", static_cast<int64_t>(g_total_threats.load()));
                    j.kv_int("total_events", 0);
                    j.kv_int("total_ioc_hits", 0);
                    j.kv_int("total_fim_changes", 0);
                }
                if (threat_intel) {
                    j.kv_int("iocs_loaded", static_cast<int64_t>(threat_intel->total_iocs()));
                    j.kv_int("feeds_loaded", static_cast<int64_t>(threat_intel->feed_count()));
                }
                if (fim_monitor) {
                    j.kv_int("fim_baselined_devices", static_cast<int64_t>(fim_monitor->baselined_devices()));
                }
                if (rest_server) {
                    j.kv_int("api_requests", static_cast<int64_t>(rest_server->total_requests()));
                }
                if (ir_engine) {
                    j.kv_int("ir_incidents", static_cast<int64_t>(ir_engine->total_incidents()));
                    j.kv_int("ir_actions_executed", static_cast<int64_t>(ir_engine->total_actions_executed()));
                    j.kv_int("ir_blocked_ips", static_cast<int64_t>(ir_engine->blocked_count()));
                    j.kv_int("ir_quarantined", static_cast<int64_t>(ir_engine->quarantined_count()));
                }
                if (fleet_mgr) {
                    auto fs = fleet_mgr->get_summary();
                    j.kv_int("fleet_total", static_cast<int64_t>(fs.total));
                    j.kv_int("fleet_online", static_cast<int64_t>(fs.online));
                    j.kv_int("fleet_stale", static_cast<int64_t>(fs.stale));
                    j.kv_int("fleet_offline", static_cast<int64_t>(fs.offline));
                    j.kv_int("fleet_quarantined", static_cast<int64_t>(fs.quarantined));
                }
                if (net_inspector) {
                    j.kv_int("net_findings", static_cast<int64_t>(net_inspector->total_findings()));
                    j.kv_int("net_inspections", static_cast<int64_t>(net_inspector->total_inspections()));
                }
                if (correlator) {
                    j.kv_int("corr_incidents", static_cast<int64_t>(correlator->total_incidents()));
                    j.kv_int("corr_active", static_cast<int64_t>(correlator->active_incidents()));
                    j.kv_int("corr_rules", static_cast<int64_t>(correlator->rule_count()));
                }
                // --- v5.0 counters ---
                if (sigma) {
                    j.kv_int("sigma_rules", static_cast<int64_t>(sigma->rule_count()));
                    j.kv_int("sigma_hits",  static_cast<int64_t>(sigma->total_hits()));
                }
                if (rbac) {
                    j.kv_int("rbac_users",   static_cast<int64_t>(rbac->user_count()));
                    j.kv_int("rbac_tenants", static_cast<int64_t>(rbac->tenant_count()));
                }
                if (soar) {
                    j.kv_int("soar_sent",   static_cast<int64_t>(soar->sent()));
                    j.kv_int("soar_failed", static_cast<int64_t>(soar->failed()));
                }
                if (syslog_in) {
                    j.kv_int("syslog_received",
                        static_cast<int64_t>(syslog_in->total_received()));
                }
                if (ml) {
                    j.kv_int("ml_findings", static_cast<int64_t>(ml->total_findings()));
                    j.kv_int("ml_observed", static_cast<int64_t>(ml->total_observed()));
                    j.kv_int("ml_trained",  ml->is_trained() ? 1 : 0);
                }
                j.end_object();
                return HttpResponse::json(j.str());
            });

            auto clamp_limit = [](int v) {
                if (v < 1) return 1;
                if (v > 1000) return 1000;
                return v;
            };

            rest_server->get("/api/threats", [clamp_limit](const HttpRequest& req) {
                int limit = clamp_limit(req.get_param_int("limit", 50));
                int dev   = req.get_param_int("device_id", -1);
                if (pg_store) return HttpResponse::json(pg_store->query_threats(limit, dev));
                return HttpResponse::json("[]");
            });

            rest_server->get("/api/ioc", [clamp_limit](const HttpRequest& req) {
                int limit = clamp_limit(req.get_param_int("limit", 50));
                int dev   = req.get_param_int("device_id", -1);
                if (pg_store) return HttpResponse::json(pg_store->query_ioc_matches(limit, dev));
                return HttpResponse::json("[]");
            });

            rest_server->get("/api/fim", [clamp_limit](const HttpRequest& req) {
                int limit = clamp_limit(req.get_param_int("limit", 50));
                int dev   = req.get_param_int("device_id", -1);
                if (pg_store) return HttpResponse::json(pg_store->query_fim_events(limit, dev));
                return HttpResponse::json("[]");
            });

            rest_server->get("/api/events", [clamp_limit](const HttpRequest& req) {
                int limit = clamp_limit(req.get_param_int("limit", 50));
                int dev   = req.get_param_int("device_id", -1);
                if (pg_store) return HttpResponse::json(pg_store->query_security_events(limit, dev));
                return HttpResponse::json("[]");
            });

            rest_server->get("/api/devices", [](const HttpRequest& req) {
                if (!fleet_mgr) return HttpResponse::json("[]");
                int dev = req.get_param_int("device_id", -1);
                if (dev >= 0) return HttpResponse::json("[" + fleet_mgr->device_to_json(dev) + "]");
                return HttpResponse::json(fleet_mgr->to_json());
            });

            rest_server->get("/api/ir/actions", [](const HttpRequest&) {
                if (!ir_engine) return HttpResponse::json("[]");
                auto actions = ir_engine->get_recent_actions(100);
                std::string json = "[";
                for (size_t i = 0; i < actions.size(); i++) {
                    if (i > 0) json += ",";
                    const auto& a = actions[i];
                    json += "{\"timestamp_ms\":" + std::to_string(a.timestamp_ms)
                        + ",\"device_id\":" + std::to_string(a.device_id)
                        + ",\"source\":\"" + a.incident_source + "\""
                        + ",\"category\":\"" + a.incident_category + "\""
                        + ",\"severity\":\"" + a.severity + "\""
                        + ",\"action\":\"" + action_type_str(a.action_type) + "\""
                        + ",\"target\":\"" + HttpResponse::json_escape(a.target) + "\""
                        + ",\"success\":" + (a.success ? "true" : "false")
                        + ",\"detail\":\"" + HttpResponse::json_escape(a.detail) + "\"}";
                }
                json += "]";
                return HttpResponse::json(json);
            });

            rest_server->get("/api/ir/blocklist", [](const HttpRequest&) {
                if (!ir_engine) return HttpResponse::json("[]");
                auto blocks = ir_engine->get_blocklist();
                std::string json = "[";
                for (size_t i = 0; i < blocks.size(); i++) {
                    if (i > 0) json += ",";
                    const auto& b = blocks[i];
                    json += "{\"ip\":\"" + b.ip + "\""
                        + ",\"blocked_at_ms\":" + std::to_string(b.blocked_at_ms)
                        + ",\"expires_at_ms\":" + std::to_string(b.expires_at_ms)
                        + ",\"reason\":\"" + HttpResponse::json_escape(b.reason) + "\""
                        + ",\"device_id\":" + std::to_string(b.device_id) + "}";
                }
                json += "]";
                return HttpResponse::json(json);
            });

            rest_server->get("/api/ir/quarantined", [](const HttpRequest&) {
                if (!ir_engine) return HttpResponse::json("[]");
                auto q = ir_engine->get_quarantined();
                std::string json = "[";
                bool first = true;
                for (int32_t dev : q) {
                    if (!first) json += ",";
                    first = false;
                    json += std::to_string(dev);
                }
                json += "]";
                return HttpResponse::json(json);
            });

            rest_server->get("/api/correlations", [clamp_limit](const HttpRequest& req) {
                if (!correlator) return HttpResponse::json("[]");
                int limit = clamp_limit(req.get_param_int("limit", 50));
                return HttpResponse::json(correlator->incidents_to_json(limit));
            });

            // =================================================================
            // v5.0 routes
            // =================================================================

            // --- Phase 20: Authentication ---
            rest_server->post("/api/auth/login", [](const HttpRequest& req) {
                if (!rbac) return HttpResponse::error(503, "RBAC disabled");
                std::string username = json_field(req.body, "username");
                std::string password = json_field(req.body, "password");
                if (username.empty() || password.empty())
                    return HttpResponse::error(400, "username+password required");
                auto res = rbac->login(username, password, "rest_api");
                if (!res.success) return HttpResponse::error(401, "invalid credentials");
                std::string body = std::string("{\"token\":\"") + res.jwt
                    + "\",\"role\":\""   + role_to_str(res.role)
                    + "\",\"tenant\":\"" + res.tenant_id + "\"}";
                return HttpResponse::json(body);
            }, false);

            rest_server->post("/api/auth/me", [](const HttpRequest& req) {
                if (!rbac) return HttpResponse::error(503, "RBAC disabled");
                std::string token = json_field(req.body, "token");
                if (token.empty()) return HttpResponse::error(400, "token required");
                auto claims = rbac->verify_jwt(token);
                if (!claims.valid) return HttpResponse::error(401, "Invalid token");
                std::string body = std::string("{\"username\":\"") + claims.username
                    + "\",\"role\":\""   + role_to_str(claims.role)
                    + "\",\"tenant\":\"" + claims.tenant_id
                    + "\",\"exp_ms\":"   + std::to_string(claims.exp_ms) + "}";
                return HttpResponse::json(body);
            }, false);

            // --- Phase 18: Compliance report generation ---
            rest_server->post("/api/reports/generate", [](const HttpRequest& req) {
                if (!reporter) return HttpResponse::error(503, "Reporting disabled");
                std::string fw = json_field(req.body, "framework");
                if (fw.empty()) fw = "generic";

                ReportInputs in;
                in.framework = fw;
                int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
                in.period_end_ms   = now_ms;
                in.period_start_ms = now_ms - 30LL * 24 * 3600 * 1000;
                in.report_period   = "Monthly";

                if (pg_store) {
                    in.threats_total    = pg_store->count_table("threat_detections");
                    in.ioc_hits_total   = pg_store->count_table("ioc_matches");
                    in.fim_events_total = pg_store->count_table("fim_events");
                }
                if (fleet_mgr) {
                    auto fs = fleet_mgr->get_summary();
                    in.devices_total       = fs.total;
                    in.devices_online      = fs.online;
                    in.devices_offline     = fs.offline;
                    in.devices_quarantined = fs.quarantined;
                }
                if (ir_engine) {
                    in.ir_incidents        = ir_engine->total_incidents();
                    in.ir_actions_executed = ir_engine->total_actions_executed();
                    in.ir_blocked_ips      = ir_engine->blocked_count();
                    in.ir_quarantines      = ir_engine->quarantined_count();
                }
                if (correlator) in.correlated_incidents = correlator->total_incidents();

                Report r = reporter->render(in);
                std::string saved = reporter->save(r);
                std::string fn;
                try { fn = std::filesystem::path(saved).filename().string(); } catch (...) { fn = saved; }
                std::string body = std::string("{\"path\":\"") + HttpResponse::json_escape(saved)
                    + "\",\"framework\":\"" + r.framework
                    + "\",\"generated_ms\":" + std::to_string(r.generated_ms)
                    + ",\"url\":\"/reports/" + HttpResponse::json_escape(fn) + "\"}";
                return HttpResponse::json(body);
            });

            // --- Phase 21: SOAR inbound callback ---
            // Real SoarConnector has receive(SoarInbound), not handle_inbound(req).
            // We parse a flat JSON body into SoarInbound and call receive().
            rest_server->post("/api/soar/callback", [](const HttpRequest& req) {
                if (!soar) return HttpResponse::error(503, "SOAR disabled");
                SoarInbound in;
                in.action     = json_field(req.body, "action");
                in.target     = json_field(req.body, "target");
                in.reason     = json_field(req.body, "reason");
                in.request_id = json_field(req.body, "request_id");
                if (in.action.empty())
                    return HttpResponse::error(400, "action required");
                soar->receive(in);
                return HttpResponse::json("{\"ok\":true}");
            }, false);

            // --- Phase 23: Hunt query ---
            // Compiles the DSL to SQL, then executes via pg_store->query_json()
            // (libpq-style: sql, n_params, params[], limit). If the database is
            // offline or the execution returns an empty result, we fall back
            // to returning the compiled SQL preview so the operator still gets
            // something actionable and can see what was compiled.
            rest_server->post("/api/hunt", [clamp_limit](const HttpRequest& req) {
                if (!g_hunt_enabled.load()) return HttpResponse::error(503, "Hunt DSL disabled (db offline)");
                std::string q = json_field(req.body, "query");
                if (q.empty()) return HttpResponse::error(400, "query required");
                int limit = clamp_limit(req.get_param_int("limit", 100));

                HuntResult r = compile_hunt(q);
                if (!r.ok) return HttpResponse::error(400, r.error.c_str());

                // Attempt real execution via pg_store->query_json(...).
                if (pg_store && pg_store->is_connected()) {
                    std::vector<const char*> params_cstr;
                    params_cstr.reserve(r.compiled.params.size());
                    for (const auto& p : r.compiled.params) params_cstr.push_back(p.c_str());

                    std::string exec_json = pg_store->query_json(
                        r.compiled.sql.c_str(),
                        static_cast<int>(r.compiled.params.size()),
                        params_cstr.empty() ? nullptr : params_cstr.data(),
                        limit);
                    if (!exec_json.empty()) return HttpResponse::json(exec_json);
                    // else fall through to preview-only response
                }

                // Fallback: return compiled SQL + params as a preview.
                std::string params_json = "[";
                for (size_t i = 0; i < r.compiled.params.size(); i++) {
                    if (i > 0) params_json += ",";
                    params_json += "\"" + HttpResponse::json_escape(r.compiled.params[i]) + "\"";
                }
                params_json += "]";
                std::string body = std::string("{\"ok\":true,\"executed\":false,\"sql\":\"")
                    + HttpResponse::json_escape(r.compiled.sql)
                    + "\",\"params\":" + params_json + "}";
                return HttpResponse::json(body);
            });

            // --- Phase 24: ML anomalies ---
            // Primary path: filtered SELECT via pg_store->query_json() so the
            // server returns ml_anomaly threats only. Fallback: query_threats()
            // (returns all recent threats; the UI filters category client-side).
            rest_server->get("/api/anomalies", [clamp_limit](const HttpRequest& req) {
                int limit = clamp_limit(req.get_param_int("limit", 50));
                int dev   = req.get_param_int("device_id", -1);
                if (!pg_store) return HttpResponse::json("[]");

                if (pg_store->is_connected()) {
                    std::string sql =
                        "SELECT device_id, timestamp_ms, machine_ip, "
                        "sub_type AS detector, confidence AS score, "
                        "severity, mitre_id, description, evidence "
                        "FROM threat_detections "
                        "WHERE category = 'ml_anomaly'";
                    std::string dev_str;
                    const char* params[1] = { nullptr };
                    int n_params = 0;
                    if (dev >= 0) {
                        sql += " AND device_id = $1";
                        dev_str = std::to_string(dev);
                        params[0] = dev_str.c_str();
                        n_params = 1;
                    }
                    sql += " ORDER BY received_at DESC";

                    std::string exec_json = pg_store->query_json(
                        sql.c_str(), n_params,
                        n_params > 0 ? params : nullptr,
                        limit);
                    if (!exec_json.empty()) return HttpResponse::json(exec_json);
                }

                // Fallback: full recent threats (UI filters by category).
                return HttpResponse::json(pg_store->query_threats(limit, dev));
            });

            if (rest_server->start()) {
                logger->log(AsyncLogger::INFO,
                    "REST API: ENABLED on port " + std::to_string(rest_cfg.port)
                    + " | auth=" + (rest_cfg.api_token.empty() ? "none" : "token")
                    + " | dashboard at http://localhost:" + std::to_string(rest_cfg.port) + "/");
            } else {
                logger->log(AsyncLogger::ERROR_LOG,
                    "REST API: FAILED to start on port " + std::to_string(rest_cfg.port));
            }
        } else {
            logger->log(AsyncLogger::INFO, "REST API: disabled.");
        }
    }

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
    // Execution Loop
    // -------------------------------------------------------------------------
    {
        DynamicThreadPool pool(pool_cfg);

        std::thread diagnostics([&pool]() {
            while (g_running) {
                std::this_thread::sleep_for(std::chrono::seconds(30));
                if (!g_running) break;

                if (threat_intel && threat_intel->check_and_reload()) {
                    logger->log(AsyncLogger::INFO,
                        "Threat Intel: feeds reloaded -- " + std::to_string(threat_intel->total_iocs()) + " IoCs");
                }
                if (sigma && sigma->check_and_reload()) {
                    logger->log(AsyncLogger::INFO,
                        "Sigma: rules reloaded -- " + std::to_string(sigma->rule_count()) + " rules");
                }

                std::stringstream ss;
                ss << "Pool: active=" << pool.active_count()
                   << " total=" << pool.total_count()
                   << " pending=" << pool.pending_count();
                if (alert_engine) ss << " | Alerts: " << alert_engine->total_alerts_fired();
                if (classifier)   ss << " | Threats: " << g_total_threats.load();
                if (threat_intel) ss << " | IoC: " << threat_intel->total_iocs()
                                     << " loaded, " << threat_intel->total_matches.load() << " hits";
                if (fim_monitor)  ss << " | FIM: " << fim_monitor->baselined_devices()
                                     << " devices, " << fim_monitor->total_changes() << " changes";
                if (rest_server)  ss << " | API: " << rest_server->total_requests() << " requests";
                if (ir_engine)    ss << " | IR: " << ir_engine->total_incidents() << " incidents, "
                                     << ir_engine->blocked_count() << " blocked";
                if (fleet_mgr) {
                    fleet_mgr->refresh_health();
                    auto fs = fleet_mgr->get_summary();
                    ss << " | Fleet: " << fs.online << "/" << fs.total << " online";
                }
                if (net_inspector) ss << " | NetInsp: " << net_inspector->total_findings() << " findings";
                if (correlator)    ss << " | Corr: " << correlator->active_incidents() << " active, "
                                      << correlator->total_incidents() << " total";
                if (sigma)         ss << " | Sigma: " << sigma->total_hits() << " hits";
                if (soar)          ss << " | SOAR: " << soar->sent() << " sent, " << soar->failed() << " failed";
                if (syslog_in)     ss << " | Syslog: " << syslog_in->total_received() << " received";
                if (ml)            ss << " | ML: " << ml->total_findings() << " findings ("
                                      << (ml->is_trained() ? "trained" : "warmup") << ")";
                if (pg_store)      ss << " | DB: " << (pg_store->is_connected() ? "up" : "down");
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
    // Cleanup
    // -------------------------------------------------------------------------
    logger->log(AsyncLogger::INFO, "=== Server exiting gracefully ===");
    if (rest_server) rest_server->stop();
    if (ir_engine)   ir_engine->stop();
    if (syslog_in)   syslog_in->stop();
    if (soar)        soar->stop();
    rest_server.reset();
    ir_engine.reset();
    fleet_mgr.reset();
    net_inspector.reset();
    correlator.reset();
    fim_monitor.reset();
    threat_intel.reset();
    classifier.reset();
    alert_engine.reset();
    // --- v5.0 cleanup ---
    ml.reset();
    syslog_out.reset();
    syslog_in.reset();
    soar.reset();
    rbac.reset();
    reporter.reset();
    sigma.reset();
    // ---
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
