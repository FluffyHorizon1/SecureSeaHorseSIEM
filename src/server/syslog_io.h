#ifndef SYSLOG_IO_H
#define SYSLOG_IO_H

#ifndef NOMINMAX
#define NOMINMAX
#endif

// =============================================================================
// SecureSeaHorse SIEM -- Phase 22: Syslog Ingestion & Forwarding
// =============================================================================
// Two related subsystems:
//
//   1. Syslog Listener  -- accepts RFC 5424 (structured) and RFC 3164 (BSD)
//      messages on UDP or TCP, normalises them into SecurityEvents the
//      regex/alert/correlation pipeline already understands. This makes
//      SecureSeaHorse usable as a drop-in SIEM for hosts that cannot run
//      the native agent (switches, routers, appliances).
//
//   2. Syslog Forwarder -- exports every detection/incident to an external
//      SIEM/SOC in CEF (ArcSight) or LEEF (QRadar) format, via UDP or TCP.
//
// No external dependencies beyond the existing socket layer.
// =============================================================================

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <functional>
#include <mutex>
#include <queue>
#include <regex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
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

// =============================================================================
// NORMALIZED SYSLOG EVENT
// =============================================================================
struct SyslogEvent {
    int64_t     received_ms = 0;
    int         facility = 1;        // 0..23
    int         severity = 6;        // 0..7 (0=emerg, 7=debug)
    std::string hostname;
    std::string app_name;
    std::string proc_id;
    std::string msg_id;
    std::string source_ip;           // Sender IP (socket-level)
    std::string message;             // MSG body (no header)
    std::string raw;                 // Original line

    std::string level_name() const {
        static const char* names[] = {"emerg","alert","crit","err","warning","notice","info","debug"};
        int s = (severity < 0 || severity > 7) ? 6 : severity;
        return names[s];
    }
};

// =============================================================================
// SYSLOG PARSER (supports both RFC 5424 and RFC 3164)
// =============================================================================
class SyslogParser {
public:
    static SyslogEvent parse(const std::string& raw, const std::string& src_ip) {
        SyslogEvent e;
        e.raw = raw;
        e.source_ip = src_ip;
        e.received_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        // Priority: <N>
        size_t pos = 0;
        if (!raw.empty() && raw[0] == '<') {
            auto gt = raw.find('>', 1);
            if (gt != std::string::npos) {
                try {
                    int pri = std::stoi(raw.substr(1, gt - 1));
                    e.facility = pri / 8;
                    e.severity = pri % 8;
                } catch (...) {}
                pos = gt + 1;
            }
        }
        std::string rest = raw.substr(pos);

        // RFC 5424: starts with "1 " then timestamp
        if (rest.size() > 2 && rest[0] == '1' && rest[1] == ' ') {
            parse_5424(rest.substr(2), e);
        } else {
            parse_3164(rest, e);
        }
        return e;
    }

private:
    static void parse_5424(const std::string& s, SyslogEvent& e) {
        // FORMAT: TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
        std::istringstream iss(s);
        std::string ts, host, app, proc, mid;
        iss >> ts >> host >> app >> proc >> mid;
        e.hostname = host; e.app_name = app;
        e.proc_id = proc;  e.msg_id = mid;
        // Skip structured-data: either "-" or "[...]...[...]"
        std::string rest;
        std::getline(iss, rest);
        // Trim leading space
        size_t p = 0;
        while (p < rest.size() && rest[p] == ' ') p++;
        rest = rest.substr(p);
        if (!rest.empty()) {
            if (rest[0] == '-') {
                // No structured data
                if (rest.size() > 2) e.message = rest.substr(2);
            } else if (rest[0] == '[') {
                // Skip bracketed sections
                size_t depth = 0, i = 0;
                for (; i < rest.size(); i++) {
                    if (rest[i] == '[') depth++;
                    else if (rest[i] == ']') {
                        if (depth > 0) depth--;
                        if (depth == 0 && i + 1 < rest.size() && rest[i + 1] != '[') { i++; break; }
                    }
                }
                while (i < rest.size() && rest[i] == ' ') i++;
                if (i < rest.size()) e.message = rest.substr(i);
            } else {
                e.message = rest;
            }
        }
    }

    static void parse_3164(const std::string& s, SyslogEvent& e) {
        // FORMAT: "MMM DD hh:mm:ss HOSTNAME TAG: MSG"
        // We don't strictly require the timestamp; if we can't parse, dump the
        // whole line into message.
        static const std::regex rx(
            R"(^[A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+(\S+)\s+([^\s:\[]+)(?:\[[^\]]*\])?:?\s+(.*)$)"
        );
        std::smatch m;
        if (std::regex_match(s, m, rx)) {
            e.hostname = m[1]; e.app_name = m[2]; e.message = m[3];
        } else {
            e.message = s;
        }
    }
};

// =============================================================================
// SYSLOG LISTENER (UDP + TCP)
// =============================================================================
class SyslogListener {
public:
    using Handler = std::function<void(const SyslogEvent&)>;

    struct Config {
        bool enabled = false;
        int  udp_port = 514;
        int  tcp_port = 0;                   // 0 = disabled
        std::string bind_address = "0.0.0.0";
        size_t max_line = 8192;
    };

    SyslogListener(const Config& cfg, Handler h)
        : config_(cfg), handler_(std::move(h)) {}

    ~SyslogListener() { stop(); }

    bool start() {
        if (!config_.enabled || running_) return false;
        running_ = true;
        if (config_.udp_port > 0) udp_thread_ = std::thread([this]() { udp_loop(); });
        if (config_.tcp_port > 0) tcp_thread_ = std::thread([this]() { tcp_loop(); });
        return true;
    }

    void stop() {
        running_ = false;
        if (udp_sock_ != INVALID_SOCKET) { closesocket(udp_sock_); udp_sock_ = INVALID_SOCKET; }
        if (tcp_sock_ != INVALID_SOCKET) { closesocket(tcp_sock_); tcp_sock_ = INVALID_SOCKET; }
        if (udp_thread_.joinable()) udp_thread_.join();
        if (tcp_thread_.joinable()) tcp_thread_.join();
    }

    size_t total_received() const { return total_received_.load(); }

private:
    Config config_;
    Handler handler_;
    std::atomic<bool> running_{false};
    std::atomic<SOCKET> udp_sock_{INVALID_SOCKET};
    std::atomic<SOCKET> tcp_sock_{INVALID_SOCKET};
    std::thread udp_thread_, tcp_thread_;
    std::atomic<size_t> total_received_{0};

    void udp_loop() {
        SOCKET s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s == INVALID_SOCKET) return;
        sockaddr_in addr{}; addr.sin_family = AF_INET;
        addr.sin_port = htons(static_cast<uint16_t>(config_.udp_port));
        inet_pton(AF_INET, config_.bind_address.c_str(), &addr.sin_addr);
        int opt = 1;
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
        if (bind(s, (sockaddr*)&addr, sizeof(addr)) < 0) { closesocket(s); return; }
        udp_sock_ = s;

        std::vector<char> buf(config_.max_line);
        while (running_) {
            sockaddr_in src{}; socklen_t sl = sizeof(src);
            int n = recvfrom(s, buf.data(), static_cast<int>(buf.size()) - 1, 0,
                             (sockaddr*)&src, &sl);
            if (n <= 0) continue;
            buf[n] = 0;
            char ip[INET_ADDRSTRLEN] = {};
            inet_ntop(AF_INET, &src.sin_addr, ip, sizeof(ip));
            total_received_++;
            if (handler_) {
                SyslogEvent ev = SyslogParser::parse(std::string(buf.data(), n), ip);
                handler_(ev);
            }
        }
    }

    void tcp_loop() {
        SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
        if (s == INVALID_SOCKET) return;
        sockaddr_in addr{}; addr.sin_family = AF_INET;
        addr.sin_port = htons(static_cast<uint16_t>(config_.tcp_port));
        inet_pton(AF_INET, config_.bind_address.c_str(), &addr.sin_addr);
        int opt = 1;
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
        if (bind(s, (sockaddr*)&addr, sizeof(addr)) < 0 || listen(s, 32) < 0) {
            closesocket(s); return;
        }
        tcp_sock_ = s;
#ifdef _WIN32
        DWORD t = 1000;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&t, sizeof(t));
#else
        timeval t; t.tv_sec = 1; t.tv_usec = 0;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&t, sizeof(t));
#endif
        while (running_) {
            sockaddr_in caddr{}; socklen_t cl = sizeof(caddr);
            SOCKET c = accept(s, (sockaddr*)&caddr, &cl);
            if (c == INVALID_SOCKET) continue;
            char ip[INET_ADDRSTRLEN] = {};
            inet_ntop(AF_INET, &caddr.sin_addr, ip, sizeof(ip));
            std::thread([this, c, ipstr = std::string(ip)]() { handle_tcp(c, ipstr); }).detach();
        }
    }

    void handle_tcp(SOCKET c, const std::string& ip) {
        std::vector<char> buf(4096);
        std::string accum;
        while (running_) {
            int n = recv(c, buf.data(), static_cast<int>(buf.size()), 0);
            if (n <= 0) break;
            accum.append(buf.data(), n);
            if (accum.size() > config_.max_line * 4) { accum.clear(); break; }
            size_t nl;
            while ((nl = accum.find('\n')) != std::string::npos) {
                std::string line = accum.substr(0, nl);
                accum.erase(0, nl + 1);
                if (!line.empty() && line.back() == '\r') line.pop_back();
                if (line.empty()) continue;
                total_received_++;
                if (handler_) handler_(SyslogParser::parse(line, ip));
            }
        }
        closesocket(c);
    }
};

// =============================================================================
// FORWARDER -- CEF / LEEF emission over UDP or TCP
// =============================================================================
enum class SyslogFormat { CEF, LEEF, RFC5424 };

class SyslogForwarder {
public:
    struct Config {
        bool enabled = false;
        std::string host = "127.0.0.1";
        int port = 514;
        bool use_tcp = false;
        SyslogFormat format = SyslogFormat::CEF;
        std::string vendor = "SecuredCyberSolutions";
        std::string product = "SecureSeaHorse";
        std::string version = "3.1.4";
    };

    struct Outbound {
        std::string category;       // "threat","ioc","fim","correlation","incident"
        std::string sub_type;
        std::string severity;       // "low".."critical"
        std::string mitre_id;
        std::string description;
        int32_t device_id = 0;
        std::string machine_ip;
        int64_t timestamp_ms = 0;
        std::map<std::string, std::string> extra;
    };

    explicit SyslogForwarder(const Config& cfg) : config_(cfg) {}

    bool send(const Outbound& o) {
        if (!config_.enabled) return false;
        std::string payload = format_message(o);

        SOCKET s = socket(AF_INET, config_.use_tcp ? SOCK_STREAM : SOCK_DGRAM, 0);
        if (s == INVALID_SOCKET) return false;
        sockaddr_in addr{}; addr.sin_family = AF_INET;
        addr.sin_port = htons(static_cast<uint16_t>(config_.port));
        inet_pton(AF_INET, config_.host.c_str(), &addr.sin_addr);

        if (config_.use_tcp) {
            if (connect(s, (sockaddr*)&addr, sizeof(addr)) < 0) { closesocket(s); return false; }
            payload += "\n";
            auto rc = ::send(s, payload.c_str(), static_cast<int>(payload.size()), 0);
            closesocket(s);
            if (rc < 0) { failed_++; return false; }
        } else {
            auto rc = sendto(s, payload.c_str(), static_cast<int>(payload.size()), 0,
                             (sockaddr*)&addr, sizeof(addr));
            closesocket(s);
            if (rc < 0) { failed_++; return false; }
        }
        sent_++;
        return true;
    }

    size_t sent() const   { return sent_.load(); }
    size_t failed() const { return failed_.load(); }

private:
    Config config_;
    std::atomic<size_t> sent_{0}, failed_{0};

    static int sev_number(const std::string& s) {
        if (s == "critical") return 10; if (s == "high") return 7;
        if (s == "medium") return 5;    if (s == "low") return 3;
        return 1;
    }

    std::string format_message(const Outbound& o) const {
        switch (config_.format) {
            case SyslogFormat::LEEF:   return build_leef(o);
            case SyslogFormat::RFC5424: return build_5424(o);
            default: return build_cef(o);
        }
    }

    // CEF: CEF:0|Vendor|Product|Version|Signature|Name|Severity|Extension
    std::string build_cef(const Outbound& o) const {
        auto esc = [](std::string s) {
            std::string r; r.reserve(s.size());
            for (char c : s) { if (c == '|' || c == '\\' || c == '=') r += '\\'; r += c; }
            return r;
        };
        std::ostringstream ext;
        ext << "deviceExternalId=" << o.device_id
            << " src=" << esc(o.machine_ip)
            << " rt=" << o.timestamp_ms
            << " mitre=" << esc(o.mitre_id)
            << " cat=" << esc(o.category);
        for (const auto& kv : o.extra) {
            ext << " " << kv.first << "=" << esc(kv.second);
        }
        std::ostringstream msg;
        msg << "CEF:0|" << config_.vendor << "|" << config_.product << "|"
            << config_.version << "|" << esc(o.sub_type) << "|"
            << esc(o.description) << "|" << sev_number(o.severity) << "|" << ext.str();
        return msg.str();
    }

    // LEEF: LEEF:Version|Vendor|Product|Version|EventID|Tab-separated KV
    std::string build_leef(const Outbound& o) const {
        std::ostringstream msg;
        msg << "LEEF:2.0|" << config_.vendor << "|" << config_.product << "|"
            << config_.version << "|" << o.sub_type << "|"
            << "cat=" << o.category
            << "\tseverity=" << o.severity
            << "\tdevTime=" << o.timestamp_ms
            << "\tmitre=" << o.mitre_id
            << "\tsrc=" << o.machine_ip
            << "\tdevId=" << o.device_id
            << "\tmsg=" << o.description;
        for (const auto& kv : o.extra) msg << "\t" << kv.first << "=" << kv.second;
        return msg.str();
    }

    std::string build_5424(const Outbound& o) const {
        // Priority: facility 16 (local0) + severity mapped
        int sev = (o.severity == "critical") ? 2 :
                  (o.severity == "high") ? 3 :
                  (o.severity == "medium") ? 4 : 5;
        int pri = 16 * 8 + sev;
        std::ostringstream m;
        m << "<" << pri << ">1 - " << config_.product << " " << o.category
          << " " << o.device_id << " " << o.sub_type
          << " [ss@32473 mitre=\"" << o.mitre_id << "\" severity=\""
          << o.severity << "\" ip=\"" << o.machine_ip << "\"] "
          << o.description;
        return m.str();
    }
};

#endif
