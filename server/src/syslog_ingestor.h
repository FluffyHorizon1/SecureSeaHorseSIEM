// =============================================================================
// syslog_ingestor.h -- Phase 22 (v4.5.0)
// -----------------------------------------------------------------------------
// Passive RFC 5424 / RFC 3164 syslog receiver + CEF/LEEF forwarder.
// Lets SeaHorse ingest telemetry from appliances that can't run the C++
// agent (firewalls, switches, AV suites) and forward its own events to an
// upstream SIEM (Splunk, QRadar, Sentinel) using the same wire format those
// products already understand.
//
// Supports UDP 514 and TCP 6514 (TLS). Both listeners feed the same parser
// and hand off events to the regex + sigma engines exactly like agent-sourced
// telemetry — they become first-class security_events.
// =============================================================================
#pragma once

#include <atomic>
#include <cctype>
#include <cstdint>
#include <functional>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace seahorse::syslog {

enum class Transport { Udp, Tcp, TcpTls };
enum class OutputFormat { Cef, Leef, Rfc5424 };

struct SyslogEvent {
    int         facility = 0;
    int         severity = 0;          // 0=emerg .. 7=debug
    std::string timestamp;             // ISO-8601
    std::string hostname;
    std::string appname;
    std::string procid;
    std::string msgid;
    std::string message;               // the free-text payload
    std::string raw;                   // untouched, for audit
};

using SyslogSink = std::function<void(const SyslogEvent&)>;

class SyslogIngestor {
public:
    struct ListenerConfig {
        Transport   transport = Transport::Udp;
        int         port = 514;
        std::string bind = "0.0.0.0";
        std::string tls_cert_path;      // TcpTls only
        std::string tls_key_path;
        int         max_message_bytes = 64 * 1024;
    };

    explicit SyslogIngestor(SyslogSink sink) : sink_(std::move(sink)) {}

    bool add_listener(const ListenerConfig& cfg);
    void start();
    void stop();

    // Parser — exposed for unit tests and for replay from the DB.
    static SyslogEvent parse(const std::string& raw);

private:
    SyslogSink                  sink_;
    std::vector<ListenerConfig> listeners_;
    std::vector<std::thread>    threads_;
    std::atomic<bool>           running_{false};
    std::mutex                  listeners_mu_;
};

class SyslogForwarder {
public:
    struct UpstreamConfig {
        std::string host;
        int         port = 6514;
        Transport   transport = Transport::TcpTls;
        OutputFormat format = OutputFormat::Cef;
        std::string tls_ca_path;
        std::string vendor_tag = "SecureSeaHorse";
        std::string product_tag = "SIEM";
        std::string product_version = "5.0.0";
    };

    void configure(const UpstreamConfig& cfg);
    void send(const SyslogEvent& e);
    void start();
    void stop();

    // Serialize a SyslogEvent to the configured format. Pure function so it
    // can be unit-tested without opening a socket.
    static std::string to_cef(const SyslogEvent& e,
                              const UpstreamConfig& cfg);
    static std::string to_leef(const SyslogEvent& e,
                               const UpstreamConfig& cfg);

private:
    UpstreamConfig cfg_{};
};


// -----------------------------------------------------------------------------
// RFC 5424 / RFC 3164 parser and CEF/LEEF serializers (header-only).
// Live UDP/TCP listeners are not implemented here: add_listener stores the
// config, start()/stop() only flip the running flag, and send() is a no-op.
// Unit tests cover parse() / to_cef() / to_leef().
// -----------------------------------------------------------------------------

namespace detail_syslog {

inline constexpr size_t kMaxMessage = 64 * 1024;
inline constexpr size_t kMaxHost    = 255;
inline constexpr size_t kMaxApp     = 48;
inline constexpr size_t kMaxProc    = 128;
inline constexpr size_t kMaxMsgid   = 32;
inline constexpr size_t kMaxTs      = 64;

inline void cap(std::string& s, size_t n) {
    if (s.size() > n) s.resize(n);
}

inline bool is_digit(char c) {
    return std::isdigit(static_cast<unsigned char>(c));
}

inline bool parse_pri(const std::string& raw, size_t& i, int& fac, int& sev) {
    if (i >= raw.size() || raw[i] != '<') return false;
    size_t j = i + 1;
    int pri = 0;
    int digits = 0;
    while (j < raw.size() && is_digit(raw[j])) {
        pri = pri * 10 + (raw[j] - '0');
        ++digits;
        ++j;
        if (digits > 3) return false;
    }
    if (digits == 0 || j >= raw.size() || raw[j] != '>') return false;
    if (pri > 191) return false;
    fac = pri / 8;
    sev = pri % 8;
    i = j + 1;
    return true;
}

inline bool looks_rfc5424(const std::string& raw, size_t i) {
    if (i >= raw.size() || !is_digit(raw[i])) return false;
    size_t j = i;
    while (j < raw.size() && is_digit(raw[j])) ++j;
    return j < raw.size() && raw[j] == ' ';
}

inline bool starts_rfc3164_ts(const std::string& raw, size_t i) {
    static const char* months[] = {
        "Jan","Feb","Mar","Apr","May","Jun",
        "Jul","Aug","Sep","Oct","Nov","Dec"
    };
    if (i + 15 > raw.size()) return false;
    std::string mon = raw.substr(i, 3);
    bool ok = false;
    for (auto* m : months) if (mon == m) { ok = true; break; }
    if (!ok) return false;
    return raw[i + 3] == ' ';
}

inline bool next_token(const std::string& raw, size_t& i, std::string& out, size_t maxn) {
    if (i >= raw.size()) return false;
    size_t j = i;
    while (j < raw.size() && raw[j] != ' ') ++j;
    out = raw.substr(i, j - i);
    cap(out, maxn);
    i = j;
    if (i < raw.size() && raw[i] == ' ') ++i;
    if (out == "-") out.clear();
    return true;
}

inline std::string escape_cef(const std::string& s) {
    std::string o;
    o.reserve(s.size());
    for (char c : s) {
        if (c == '\n' || c == '\r') { o.push_back(' '); continue; }
        if (c == '\\' || c == '|' || c == '=') o.push_back('\\');
        o.push_back(c);
    }
    return o;
}

inline std::string escape_leef(const std::string& s, char delim) {
    std::string o;
    o.reserve(s.size());
    for (char c : s) {
        if (c == '\n' || c == '\r') { o.push_back(' '); continue; }
        if (c == '\\' || c == delim) o.push_back('\\');
        o.push_back(c);
    }
    return o;
}

inline int cef_severity(int syslog_sev) {
    static const int map[8] = {10, 8, 6, 5, 4, 3, 1, 0}; // emerg .. debug
    if (syslog_sev < 0 || syslog_sev > 7) return 0;
    return map[syslog_sev];
}

} // namespace detail_syslog

inline SyslogEvent SyslogIngestor::parse(const std::string& raw_in) {
    SyslogEvent ev;
    std::string raw = raw_in;
    if (raw.size() > detail_syslog::kMaxMessage)
        raw.resize(detail_syslog::kMaxMessage);
    ev.raw = raw;
    if (raw.empty()) return ev;

    size_t i = 0;
    int fac = 0, sev = 0;
    if (detail_syslog::parse_pri(raw, i, fac, sev)) {
        ev.facility = fac;
        ev.severity = sev;
    }

    while (i < raw.size() && raw[i] == ' ') ++i;
    if (i >= raw.size()) return ev;

    if (detail_syslog::looks_rfc5424(raw, i)) {
        std::string ver;
        detail_syslog::next_token(raw, i, ver, 8);
        detail_syslog::next_token(raw, i, ev.timestamp, detail_syslog::kMaxTs);
        detail_syslog::next_token(raw, i, ev.hostname, detail_syslog::kMaxHost);
        detail_syslog::next_token(raw, i, ev.appname, detail_syslog::kMaxApp);
        detail_syslog::next_token(raw, i, ev.procid, detail_syslog::kMaxProc);
        detail_syslog::next_token(raw, i, ev.msgid, detail_syslog::kMaxMsgid);
        if (i < raw.size() && raw[i] == '-') {
            ++i;
            if (i < raw.size() && raw[i] == ' ') ++i;
        } else if (i < raw.size() && raw[i] == '[') {
            while (i < raw.size() && raw[i] == '[') {
                bool in_quote = false;
                bool closed = false;
                ++i;
                while (i < raw.size()) {
                    char c = raw[i++];
                    if (c == '\\' && i < raw.size()) { ++i; continue; }
                    if (c == '"') { in_quote = !in_quote; continue; }
                    if (c == ']' && !in_quote) { closed = true; break; }
                }
                if (!closed) break;
                while (i < raw.size() && raw[i] == ' ') ++i;
            }
            if (i < raw.size() && raw[i] == ' ') ++i;
        }
        if (i < raw.size()) ev.message = raw.substr(i);
        return ev;
    }

    if (detail_syslog::starts_rfc3164_ts(raw, i)) {
        ev.timestamp = raw.substr(i, 15);
        detail_syslog::cap(ev.timestamp, detail_syslog::kMaxTs);
        i += 15;
        if (i < raw.size() && raw[i] == ' ') ++i;
        detail_syslog::next_token(raw, i, ev.hostname, detail_syslog::kMaxHost);
        if (i < raw.size()) {
            size_t colon = raw.find(':', i);
            if (colon != std::string::npos) {
                std::string tag = raw.substr(i, colon - i);
                auto br = tag.find('[');
                if (br != std::string::npos && !tag.empty() && tag.back() == ']') {
                    ev.appname = tag.substr(0, br);
                    ev.procid  = tag.substr(br + 1, tag.size() - br - 2);
                } else {
                    ev.appname = tag;
                }
                detail_syslog::cap(ev.appname, detail_syslog::kMaxApp);
                detail_syslog::cap(ev.procid, detail_syslog::kMaxProc);
                i = colon + 1;
                if (i < raw.size() && raw[i] == ' ') ++i;
                if (i < raw.size()) ev.message = raw.substr(i);
            } else {
                ev.message = raw.substr(i);
            }
        }
        return ev;
    }

    ev.message = raw.substr(i);
    return ev;
}

inline bool SyslogIngestor::add_listener(const ListenerConfig& cfg) {
    std::lock_guard<std::mutex> lock(listeners_mu_);
    listeners_.push_back(cfg);
    return true;
}

inline void SyslogIngestor::start() { running_ = true; }
inline void SyslogIngestor::stop()  { running_ = false; }

inline void SyslogForwarder::configure(const UpstreamConfig& cfg) { cfg_ = cfg; }

inline void SyslogForwarder::send(const SyslogEvent&) {}
inline void SyslogForwarder::start() {}
inline void SyslogForwarder::stop() {}

inline std::string SyslogForwarder::to_cef(const SyslogEvent& e,
                                           const UpstreamConfig& cfg) {
    std::string event_id = e.msgid.empty() ? "0" : e.msgid;
    std::string name = !e.msgid.empty() ? e.msgid
                     : (!e.appname.empty() ? e.appname : "syslog");
    std::ostringstream oss;
    oss << "CEF:0|"
        << detail_syslog::escape_cef(cfg.vendor_tag) << "|"
        << detail_syslog::escape_cef(cfg.product_tag) << "|"
        << detail_syslog::escape_cef(cfg.product_version) << "|"
        << detail_syslog::escape_cef(event_id) << "|"
        << detail_syslog::escape_cef(name) << "|"
        << detail_syslog::cef_severity(e.severity) << "|";
    bool first = true;
    auto ext = [&](const char* k, const std::string& v) {
        if (v.empty()) return;
        if (!first) oss << " ";
        first = false;
        oss << k << "=" << detail_syslog::escape_cef(v);
    };
    ext("msg", e.message);
    ext("dhost", e.hostname);
    ext("dproc", e.appname);
    ext("rt", e.timestamp);
    if (!first) oss << " ";
    oss << "syslogFacility=" << e.facility
        << " syslogSeverity=" << e.severity;
    return oss.str();
}

inline std::string SyslogForwarder::to_leef(const SyslogEvent& e,
                                            const UpstreamConfig& cfg) {
    const char delim = '\t';
    std::string event_id = e.msgid.empty() ? "0" : e.msgid;
    std::ostringstream oss;
    oss << "LEEF:2.0|"
        << cfg.vendor_tag << "|"
        << cfg.product_tag << "|"
        << cfg.product_version << "|"
        << event_id << "|";
    bool first = true;
    auto ext = [&](const char* k, const std::string& v) {
        if (v.empty()) return;
        if (!first) oss << delim;
        first = false;
        oss << k << "=" << detail_syslog::escape_leef(v, delim);
    };
    ext("msg", e.message);
    ext("dhost", e.hostname);
    ext("dproc", e.appname);
    ext("devTime", e.timestamp);
    if (!first) oss << delim;
    oss << "syslogFacility=" << e.facility
        << delim << "syslogSeverity=" << e.severity;
    return oss.str();
}

} // namespace seahorse::syslog
