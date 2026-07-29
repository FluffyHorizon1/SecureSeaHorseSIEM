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
#include <cstdint>
#include <functional>
#include <mutex>
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
};

} // namespace seahorse::syslog
