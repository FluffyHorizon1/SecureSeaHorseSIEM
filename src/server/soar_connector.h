#ifndef SOAR_CONNECTOR_H
#define SOAR_CONNECTOR_H

#ifndef NOMINMAX
#define NOMINMAX
#endif

// =============================================================================
// SecureSeaHorse SIEM -- Phase 21: SOAR Integration
// =============================================================================
// Bidirectional integration with Security Orchestration, Automation and
// Response platforms. SecureSeaHorse pushes incidents/alerts out as events,
// and accepts action requests coming back in (block IP, quarantine device,
// etc.) via a signed webhook callback.
//
// Backends implemented:
//   - Splunk SOAR (formerly Phantom)     /rest/container + /rest/artifact
//   - Cortex XSOAR (Palo Alto)           /incident + /investigation
//   - TheHive                            /api/v1/case + /api/v1/alert
//   - Generic webhook (JSON POST)        any URL
//
// The HTTP itself is pluggable -- we expose a simple `HttpPoster` interface
// so the project can keep relying on OpenSSL for TLS without forcing a curl
// dependency. A minimal BIO-based implementation is included.
// =============================================================================

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <queue>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <openssl/bio.h>
#include <openssl/ssl.h>

// =============================================================================
// OUTBOUND EVENT (SIEM -> SOAR)
// =============================================================================
struct SoarOutbound {
    std::string type;           // "incident", "alert", "observable"
    std::string severity;
    std::string title;
    std::string description;
    std::string mitre_id;
    std::string source;         // "correlation","ir","threat_intel"...
    int32_t     device_id = 0;
    int64_t     timestamp_ms = 0;
    std::map<std::string, std::string> fields;  // Arbitrary KV
};

// =============================================================================
// INBOUND ACTION (SOAR -> SIEM)
// =============================================================================
struct SoarInbound {
    std::string action;          // "block_ip","quarantine","disable_user","close_incident"
    std::string target;
    std::string reason;
    std::string request_id;
    std::map<std::string, std::string> params;
};

// =============================================================================
// HTTP POSTER ABSTRACTION
// =============================================================================
struct SoarHttpResponse {
    int         status = 0;
    std::string body;
    std::string error;
};

class HttpPoster {
public:
    virtual ~HttpPoster() = default;
    virtual SoarHttpResponse post(const std::string& url,
                              const std::string& json_body,
                              const std::vector<std::string>& headers) = 0;
};

// =============================================================================
// MINIMAL BUILT-IN POSTER (plain-text HTTP / TLS via OpenSSL BIO)
// =============================================================================
// This is intentionally basic: parses scheme://host[:port]/path, does one
// request/response cycle. Good enough for webhook-style POSTs. For heavier
// integrations plug in a curl-based HttpPoster instead.
// =============================================================================
class BasicHttpPoster : public HttpPoster {
public:
    SoarHttpResponse post(const std::string& url,
                      const std::string& body,
                      const std::vector<std::string>& headers) override
    {
        SoarHttpResponse r;
        std::string scheme, host, path;
        int port = 0;
        if (!parse_url(url, scheme, host, port, path)) {
            r.error = "bad URL";
            return r;
        }
        bool use_tls = (scheme == "https");
        if (port == 0) port = use_tls ? 443 : 80;

        SSL_CTX* ctx = nullptr;
        BIO* bio = nullptr;
        if (use_tls) {
            ctx = SSL_CTX_new(TLS_client_method());
            SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
            SSL_CTX_set_default_verify_paths(ctx);
            bio = BIO_new_ssl_connect(ctx);
            SSL* ssl = nullptr;
            BIO_get_ssl(bio, &ssl);
            SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
            std::string host_port = host + ":" + std::to_string(port);
            BIO_set_conn_hostname(bio, host_port.c_str());
        } else {
            bio = BIO_new_connect((host + ":" + std::to_string(port)).c_str());
        }

        if (!bio || BIO_do_connect(bio) <= 0) {
            r.error = "connect failed";
            if (bio) BIO_free_all(bio);
            if (ctx) SSL_CTX_free(ctx);
            return r;
        }

        std::ostringstream req;
        req << "POST " << path << " HTTP/1.1\r\n"
            << "Host: " << host << "\r\n"
            << "Content-Type: application/json\r\n"
            << "Content-Length: " << body.size() << "\r\n"
            << "Connection: close\r\n";
        for (const auto& h : headers) req << h << "\r\n";
        req << "\r\n" << body;
        std::string rq = req.str();

        int written = BIO_write(bio, rq.data(), static_cast<int>(rq.size()));
        if (written < static_cast<int>(rq.size())) {
            r.error = "short write";
        } else {
            char buf[4096];
            std::string resp;
            while (true) {
                int n = BIO_read(bio, buf, sizeof(buf));
                if (n <= 0) break;
                resp.append(buf, n);
            }
            // Very lenient parse: first line for status, blank line separator
            auto first_space = resp.find(' ');
            if (first_space != std::string::npos) {
                auto second_space = resp.find(' ', first_space + 1);
                if (second_space != std::string::npos) {
                    try { r.status = std::stoi(resp.substr(first_space + 1, second_space - first_space - 1)); }
                    catch (...) { r.status = 0; }
                }
            }
            auto sep = resp.find("\r\n\r\n");
            r.body = (sep == std::string::npos) ? resp : resp.substr(sep + 4);
        }

        BIO_free_all(bio);
        if (ctx) SSL_CTX_free(ctx);
        return r;
    }

private:
    static bool parse_url(const std::string& url, std::string& scheme,
                          std::string& host, int& port, std::string& path) {
        auto scheme_end = url.find("://");
        if (scheme_end == std::string::npos) return false;
        scheme = url.substr(0, scheme_end);
        auto rest = url.substr(scheme_end + 3);
        auto slash = rest.find('/');
        std::string host_part = (slash == std::string::npos) ? rest : rest.substr(0, slash);
        path = (slash == std::string::npos) ? "/" : rest.substr(slash);
        auto colon = host_part.find(':');
        if (colon != std::string::npos) {
            host = host_part.substr(0, colon);
            try { port = std::stoi(host_part.substr(colon + 1)); } catch (...) { port = 0; }
        } else {
            host = host_part;
            port = 0;
        }
        return !host.empty();
    }
};

// =============================================================================
// BACKEND TYPES
// =============================================================================
enum class SoarBackend { GENERIC_WEBHOOK, SPLUNK_SOAR, CORTEX_XSOAR, THE_HIVE };

inline std::string backend_name(SoarBackend b) {
    switch (b) {
        case SoarBackend::SPLUNK_SOAR:    return "splunk_soar";
        case SoarBackend::CORTEX_XSOAR:   return "cortex_xsoar";
        case SoarBackend::THE_HIVE:       return "the_hive";
        default: return "generic_webhook";
    }
}

// =============================================================================
// SOAR CONNECTOR
// =============================================================================
class SoarConnector {
public:
    struct Config {
        bool enabled = false;
        SoarBackend backend = SoarBackend::GENERIC_WEBHOOK;
        std::string base_url;
        std::string auth_header;         // e.g. "Authorization: Bearer ..."
        std::string container_label;     // Splunk SOAR label
        std::string xsoar_integration;   // Cortex XSOAR integration ID
        int worker_interval_s = 2;
        size_t max_queue = 10000;
    };

    using InboundHandler = std::function<void(const SoarInbound&)>;

    explicit SoarConnector(const Config& cfg,
                           std::shared_ptr<HttpPoster> poster = nullptr)
        : config_(cfg), poster_(std::move(poster))
    {
        if (!poster_) poster_ = std::make_shared<BasicHttpPoster>();
    }

    ~SoarConnector() { stop(); }

    void set_inbound_handler(InboundHandler h) { inbound_cb_ = std::move(h); }

    void start() {
        if (!config_.enabled || running_) return;
        running_ = true;
        worker_ = std::thread([this]() { loop(); });
    }

    void stop() {
        running_ = false;
        cv_.notify_all();
        if (worker_.joinable()) worker_.join();
    }

    // Outbound: queue an event for async delivery
    bool push(const SoarOutbound& e) {
        if (!config_.enabled) return false;
        std::lock_guard<std::mutex> lock(mutex_);
        if (queue_.size() >= config_.max_queue) {
            dropped_++;
            return false;
        }
        queue_.push(e);
        cv_.notify_one();
        return true;
    }

    // Inbound: called by the REST server when SOAR posts to /api/soar/callback.
    // Assumes the caller has already validated any signing header.
    void receive(const SoarInbound& action) {
        received_++;
        if (inbound_cb_) inbound_cb_(action);
    }

    // Stats
    size_t sent() const      { return sent_.load(); }
    size_t failed() const    { return failed_.load(); }
    size_t dropped() const   { return dropped_.load(); }
    size_t received() const  { return received_.load(); }
    size_t queue_size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }

private:
    Config config_;
    std::shared_ptr<HttpPoster> poster_;
    InboundHandler inbound_cb_;
    std::thread worker_;
    std::atomic<bool> running_{false};
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::queue<SoarOutbound> queue_;
    std::atomic<size_t> sent_{0}, failed_{0}, dropped_{0}, received_{0};

    void loop() {
        while (running_) {
            SoarOutbound e;
            {
                std::unique_lock<std::mutex> lock(mutex_);
                cv_.wait_for(lock, std::chrono::seconds(config_.worker_interval_s),
                             [this]() { return !queue_.empty() || !running_; });
                if (queue_.empty()) continue;
                e = std::move(queue_.front());
                queue_.pop();
            }
            deliver(e);
        }
    }

    void deliver(const SoarOutbound& e) {
        std::string url = config_.base_url;
        std::string body;
        switch (config_.backend) {
            case SoarBackend::SPLUNK_SOAR:
                url += "/rest/container";
                body = to_splunk_soar(e);
                break;
            case SoarBackend::CORTEX_XSOAR:
                url += "/incident";
                body = to_xsoar(e);
                break;
            case SoarBackend::THE_HIVE:
                url += "/api/v1/alert";
                body = to_thehive(e);
                break;
            default:
                body = to_generic(e);
                break;
        }
        std::vector<std::string> hdr;
        if (!config_.auth_header.empty()) hdr.push_back(config_.auth_header);

        auto r = poster_->post(url, body, hdr);
        if (r.status >= 200 && r.status < 300) sent_++;
        else failed_++;
    }

    static std::string json_escape(const std::string& s) {
        std::string o; o.reserve(s.size() + 8);
        for (char c : s) {
            switch (c) {
                case '"': o += "\\\""; break;
                case '\\': o += "\\\\"; break;
                case '\n': o += "\\n"; break;
                case '\r': o += "\\r"; break;
                default:
                    if (static_cast<unsigned char>(c) < 0x20) {
                        char buf[8];
                        snprintf(buf, sizeof(buf), "\\u%04x", c);
                        o += buf;
                    } else o += c;
            }
        }
        return o;
    }

    static std::string field_block(const SoarOutbound& e) {
        std::string s;
        for (const auto& kv : e.fields) {
            if (!s.empty()) s += ",";
            s += "\"" + json_escape(kv.first) + "\":\"" + json_escape(kv.second) + "\"";
        }
        return s;
    }

    static std::string to_generic(const SoarOutbound& e) {
        std::ostringstream j;
        j << "{\"type\":\"" << json_escape(e.type) << "\","
          << "\"severity\":\"" << json_escape(e.severity) << "\","
          << "\"title\":\"" << json_escape(e.title) << "\","
          << "\"description\":\"" << json_escape(e.description) << "\","
          << "\"mitre_id\":\"" << json_escape(e.mitre_id) << "\","
          << "\"source\":\"" << json_escape(e.source) << "\","
          << "\"device_id\":" << e.device_id << ","
          << "\"timestamp_ms\":" << e.timestamp_ms;
        auto f = field_block(e);
        if (!f.empty()) j << ",\"fields\":{" << f << "}";
        j << "}";
        return j.str();
    }

    static std::string to_splunk_soar(const SoarOutbound& e) {
        std::ostringstream j;
        j << "{\"name\":\"" << json_escape(e.title) << "\","
          << "\"label\":\"events\","
          << "\"severity\":\"" << json_escape(e.severity) << "\","
          << "\"description\":\"" << json_escape(e.description) << "\","
          << "\"source_data_identifier\":\"ss-" << e.timestamp_ms << "-" << e.device_id << "\","
          << "\"sensitivity\":\"amber\"}";
        return j.str();
    }

    static std::string to_xsoar(const SoarOutbound& e) {
        std::ostringstream j;
        j << "{\"name\":\"" << json_escape(e.title) << "\","
          << "\"type\":\"SecureSeaHorse\","
          << "\"severity\":" << xsoar_sev(e.severity) << ","
          << "\"details\":\"" << json_escape(e.description) << "\","
          << "\"labels\":[{\"type\":\"mitre\",\"value\":\"" << json_escape(e.mitre_id) << "\"},"
          << "{\"type\":\"device\",\"value\":\"" << e.device_id << "\"}]}";
        return j.str();
    }

    static int xsoar_sev(const std::string& s) {
        if (s == "critical") return 4; if (s == "high") return 3;
        if (s == "medium") return 2;   if (s == "low") return 1;
        return 0;
    }

    static std::string to_thehive(const SoarOutbound& e) {
        std::ostringstream j;
        j << "{\"title\":\"" << json_escape(e.title) << "\","
          << "\"description\":\"" << json_escape(e.description) << "\","
          << "\"type\":\"external\","
          << "\"source\":\"SecureSeaHorse\","
          << "\"sourceRef\":\"ss-" << e.timestamp_ms << "-" << e.device_id << "\","
          << "\"severity\":" << xsoar_sev(e.severity) << ","
          << "\"tlp\":2,"
          << "\"tags\":[\"" << json_escape(e.mitre_id) << "\",\"seahorse\"]}";
        return j.str();
    }
};

#endif
