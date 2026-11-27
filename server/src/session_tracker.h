#ifndef SESSION_TRACKER_H
#define SESSION_TRACKER_H

#include "wire_parse.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif

// =============================================================================
// SecureSeaHorse SIEM -- Phase 13: User Session & Auth Tracker (Client-Side)
// =============================================================================
// Provides:
//   - Active user session enumeration
//   - Login/logout event detection
//   - Failed authentication tracking with source IP
//   - Privilege escalation detection (sudo/runas)
//   - Windows: Security EventLog 4624/4625/4648, WTS sessions
//   - Linux: utmp/wtmp, /var/log/auth.log, /var/log/secure
// =============================================================================

#include <string>
#include <vector>
#include <set>
#include <mutex>
#include <sstream>
#include <chrono>
#include <cstdint>
#include <algorithm>
#include <regex>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wtsapi32.h>
#pragma comment(lib, "wtsapi32.lib")
#else
#include <utmp.h>
#include <fstream>
#include <cstring>
#endif

// =============================================================================
// SESSION ENTRY
// =============================================================================
struct SessionEntry {
    std::string username;
    std::string session_type;    // "console","rdp","ssh","tty"
    std::string source_ip;       // Remote IP for RDP/SSH (empty for local)
    std::string terminal;        // "pts/0", "Console", "RDP-Tcp#5"
    int64_t     login_time_ms = 0;
    bool        is_active     = true;
    bool        is_elevated   = false;  // Admin/root session
};

// =============================================================================
// AUTH EVENT
// =============================================================================
enum class AuthEventType {
    AUTH_LOGIN_SUCCESS,
    AUTH_LOGIN_FAILED,
    AUTH_LOGOUT,
    AUTH_PRIVILEGE_ESCALATION,
    AUTH_ACCOUNT_LOCKOUT
};

struct AuthEvent {
    AuthEventType type        = AuthEventType::AUTH_LOGIN_SUCCESS;
    int64_t     timestamp_ms  = 0;
    std::string username;
    std::string source_ip;
    std::string session_type;   // "rdp","ssh","console","su","sudo"
    std::string detail;         // Failure reason, escalation target, etc.
};

inline std::string auth_event_str(AuthEventType t) {
    switch (t) {
        case AuthEventType::AUTH_LOGIN_SUCCESS:        return "login_success";
        case AuthEventType::AUTH_LOGIN_FAILED:         return "login_failed";
        case AuthEventType::AUTH_LOGOUT:               return "logout";
        case AuthEventType::AUTH_PRIVILEGE_ESCALATION: return "priv_escalation";
        case AuthEventType::AUTH_ACCOUNT_LOCKOUT:      return "account_lockout";
        default: return "unknown";
    }
}

// =============================================================================
// SESSION REPORT
// =============================================================================
struct SessionReport {
    int32_t     device_id     = 0;
    int64_t     timestamp_ms  = 0;
    std::vector<SessionEntry> active_sessions;
    std::vector<AuthEvent>    auth_events;
    uint32_t    failed_logins = 0;  // Count in this period
};

// =============================================================================
// SERIALIZATION
// =============================================================================
inline std::string serialize_session_report(const SessionReport& r) {
    std::ostringstream oss;
    oss << "SESS|" << r.device_id << "|" << r.timestamp_ms << "|"
        << r.active_sessions.size() << "|" << r.auth_events.size() << "|"
        << r.failed_logins << "\n";

    for (const auto& s : r.active_sessions) {
        oss << s.username << "|" << s.session_type << "|" << s.source_ip << "|"
            << s.terminal << "|" << s.login_time_ms << "|"
            << (s.is_active ? 1 : 0) << "|" << (s.is_elevated ? 1 : 0) << "\n";
    }

    oss << "SESS_AUTH\n";
    for (const auto& a : r.auth_events) {
        oss << auth_event_str(a.type) << "|" << a.timestamp_ms << "|"
            << a.username << "|" << a.source_ip << "|" << a.session_type << "|";
        std::string safe_detail = a.detail;
        for (char& c : safe_detail) { if (c == '|' || c == '\n') c = ' '; }
        oss << safe_detail << "\n";
    }
    oss << "SESS_END\n";
    return oss.str();
}

inline SessionReport deserialize_session_report(const std::string& data) {
    SessionReport r;
    std::istringstream iss(data);
    std::string line;

    if (!std::getline(iss, line) || line.substr(0, 5) != "SESS|") return r;
    {
        std::istringstream hdr(line.substr(5));
        std::string tok;
        if (std::getline(hdr, tok, '|')) r.device_id = seahorse::wire::to_i32(tok);
        if (std::getline(hdr, tok, '|')) r.timestamp_ms = seahorse::wire::to_i64(tok);
        uint32_t sess_count = 0, auth_count = 0;
        if (std::getline(hdr, tok, '|')) sess_count = seahorse::wire::to_u32(tok);
        if (std::getline(hdr, tok, '|')) auth_count = seahorse::wire::to_u32(tok);
        if (std::getline(hdr, tok, '|')) r.failed_logins = seahorse::wire::to_u32(tok);
        (void)auth_count;

        for (uint32_t i = 0; i < sess_count && std::getline(iss, line); i++) {
            if (line == "SESS_AUTH") break;
            SessionEntry s;
            std::istringstream row(line);
            std::string t;
            if (std::getline(row, t, '|')) s.username = t;
            if (std::getline(row, t, '|')) s.session_type = t;
            if (std::getline(row, t, '|')) s.source_ip = t;
            if (std::getline(row, t, '|')) s.terminal = t;
            if (std::getline(row, t, '|')) s.login_time_ms = seahorse::wire::to_i64(t);
            if (std::getline(row, t, '|')) s.is_active = (t == "1");
            if (std::getline(row, t, '|')) s.is_elevated = (t == "1");
            r.active_sessions.push_back(std::move(s));
        }
    }

    while (std::getline(iss, line)) {
        if (line == "SESS_END" || line == "SESS_AUTH") continue;
        AuthEvent a;
        std::istringstream row(line);
        std::string t;
        if (std::getline(row, t, '|')) {
            if (t == "login_success") a.type = AuthEventType::AUTH_LOGIN_SUCCESS;
            else if (t == "login_failed") a.type = AuthEventType::AUTH_LOGIN_FAILED;
            else if (t == "logout") a.type = AuthEventType::AUTH_LOGOUT;
            else if (t == "priv_escalation") a.type = AuthEventType::AUTH_PRIVILEGE_ESCALATION;
            else if (t == "account_lockout") a.type = AuthEventType::AUTH_ACCOUNT_LOCKOUT;
        }
        if (std::getline(row, t, '|')) a.timestamp_ms = seahorse::wire::to_i64(t);
        if (std::getline(row, t, '|')) a.username = t;
        if (std::getline(row, t, '|')) a.source_ip = t;
        if (std::getline(row, t, '|')) a.session_type = t;
        if (std::getline(row, t, '|')) a.detail = t;
        r.auth_events.push_back(std::move(a));
    }
    return r;
}

// =============================================================================
// SESSION SCANNER
// =============================================================================
struct SessionScannerConfig {
    bool enabled           = true;
    int  scan_interval_s   = 60;
    bool track_auth_events = true;
    int  max_auth_events   = 500;   // Per scan period
};

class SessionScanner {
public:
    explicit SessionScanner(const SessionScannerConfig& cfg = {})
        : config_(cfg) {}

    // Enumerate current active sessions
    std::vector<SessionEntry> scan_sessions() {
        std::vector<SessionEntry> sessions;
#ifdef _WIN32
        scan_windows_sessions(sessions);
#else
        scan_linux_sessions(sessions);
#endif
        return sessions;
    }

    // Collect auth events since last call
    std::vector<AuthEvent> collect_auth_events() {
        std::lock_guard<std::mutex> lock(mutex_);
        auto events = std::move(pending_events_);
        pending_events_.clear();
        return events;
    }

    // Parse log lines for auth events (called from main log processing)
    void parse_log_for_auth(const std::string& log_text, int64_t timestamp_ms) {
        if (!config_.track_auth_events) return;
        std::lock_guard<std::mutex> lock(mutex_);
        std::string text = log_text;
        if (text.size() > 65536) text.resize(65536);

#ifdef _WIN32
        parse_windows_auth(text, timestamp_ms);
#else
        parse_linux_auth(text, timestamp_ms);
#endif
        cap_pending();
    }

    // OS-independent text parsers. The server must parse Windows Event XML
    // even when it itself is running on Linux (and vice versa). Tests call
    // these directly. parse_log_for_auth still dispatches by host OS for
    // any existing in-process callers.
    void parse_windows_auth_text(const std::string& log_text, int64_t timestamp_ms) {
        if (!config_.track_auth_events) return;
        std::lock_guard<std::mutex> lock(mutex_);
        parse_windows_auth(log_text, timestamp_ms);
        cap_pending();
    }
    void parse_linux_auth_text(const std::string& log_text, int64_t timestamp_ms) {
        if (!config_.track_auth_events) return;
        std::lock_guard<std::mutex> lock(mutex_);
        parse_linux_auth(log_text, timestamp_ms);
        cap_pending();
    }
    // Source tag from MSG_LOG_BATCH: "windows-*" -> Windows parser, else Linux.
    void parse_auth_record(const std::string& source, const std::string& log_text,
                           int64_t timestamp_ms) {
        if (source.rfind("windows", 0) == 0)
            parse_windows_auth_text(log_text, timestamp_ms);
        else
            parse_linux_auth_text(log_text, timestamp_ms);
    }

    size_t pending_count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return pending_events_.size();
    }

private:
    SessionScannerConfig config_;
    mutable std::mutex mutex_;
    std::vector<AuthEvent> pending_events_;

    void cap_pending() {
        if (pending_events_.size() > static_cast<size_t>(config_.max_auth_events))
            pending_events_.erase(pending_events_.begin(),
                pending_events_.begin() + static_cast<long>(pending_events_.size() - config_.max_auth_events));
    }

#ifdef _WIN32
    void scan_windows_sessions(std::vector<SessionEntry>& sessions) {
        WTS_SESSION_INFOW* pSessions = nullptr;
        DWORD count = 0;
        if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessions, &count))
            return;

        for (DWORD i = 0; i < count; i++) {
            if (pSessions[i].State != WTSActive && pSessions[i].State != WTSDisconnected)
                continue;

            SessionEntry s;

            // Session type
            char narrow_name[256] = {};
            WideCharToMultiByte(CP_UTF8, 0, pSessions[i].pWinStationName, -1, narrow_name, sizeof(narrow_name), NULL, NULL);
            s.terminal = narrow_name;

            if (s.terminal == "Console") s.session_type = "console";
            else if (s.terminal.find("RDP") != std::string::npos) s.session_type = "rdp";
            else s.session_type = "other";

            s.is_active = (pSessions[i].State == WTSActive);

            // Username
            LPWSTR pUser = nullptr;
            DWORD userLen = 0;
            if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE,
                    pSessions[i].SessionId, WTSUserName, &pUser, &userLen) && pUser) {
                char nu[256] = {};
                WideCharToMultiByte(CP_UTF8, 0, pUser, -1, nu, sizeof(nu), NULL, NULL);
                s.username = nu;
                WTSFreeMemory(pUser);
            }

            // Client IP (for RDP)
            LPWSTR pAddr = nullptr;
            DWORD addrLen = 0;
            if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE,
                    pSessions[i].SessionId, WTSClientAddress, &pAddr, &addrLen) && pAddr) {
                // WTS_CLIENT_ADDRESS struct
                WTS_CLIENT_ADDRESS* addr = reinterpret_cast<WTS_CLIENT_ADDRESS*>(pAddr);
                if (addr->AddressFamily == AF_INET && addrLen >= sizeof(WTS_CLIENT_ADDRESS)) {
                    char ip[46] = {};
                    snprintf(ip, sizeof(ip), "%d.%d.%d.%d",
                        addr->Address[2], addr->Address[3],
                        addr->Address[4], addr->Address[5]);
                    if (std::string(ip) != "0.0.0.0") s.source_ip = ip;
                }
                WTSFreeMemory(pAddr);
            }

            if (!s.username.empty())
                sessions.push_back(std::move(s));
        }
        WTSFreeMemory(pSessions);
    }

#else
    void scan_linux_sessions(std::vector<SessionEntry>& sessions) {
        // Read from utmp
        setutent();
        struct utmp* entry;
        while ((entry = getutent()) != nullptr) {
            if (entry->ut_type != USER_PROCESS) continue;
            SessionEntry s;
            s.username = entry->ut_user;
            s.terminal = entry->ut_line;
            s.login_time_ms = static_cast<int64_t>(entry->ut_tv.tv_sec) * 1000;
            s.is_active = true;

            // Determine session type
            if (std::string(entry->ut_line).find("pts/") == 0) {
                s.session_type = "ssh";
                s.source_ip = entry->ut_host;
            } else if (std::string(entry->ut_line).find("tty") == 0) {
                s.session_type = "tty";
            } else {
                s.session_type = "other";
            }

            // Root check
            s.is_elevated = (s.username == "root");

            sessions.push_back(std::move(s));
        }
        endutent();
    }
#endif

    // Text parsers are OS-independent and always compiled so a Linux server
    // can parse forwarded Windows Event XML, and unit tests can cover both.
    void parse_windows_auth(const std::string& log_in, int64_t ts) {
        // EvtRender XML is often 2-6 KiB; keep a cap against pathological input
        // and std::regex cost, but do not trim at 4 KiB or EventData (user/IP)
        // at the end of the document is lost.
        std::string log = log_in;
        if (log.size() > 65536) log.resize(65536);

        const auto flags = std::regex_constants::ECMAScript | std::regex_constants::icase;
        // Accept <EventID>4625</EventID> and <EventID Qualifiers="0">4625</EventID>
        // plus "Event ID: 4625" / "event_id=4625". Do not match a bare "4625"
        // or the word "failed" -- those were false-positive sources.
        static const std::regex ev_rx(
            R"(<EventID(?:\s[^>]*)?>\s*(4624|4625|4634|4648|4672|4740)\s*</EventID>|event\s*id\s*[=:]?\s*\b(4624|4625|4634|4648|4672|4740)\b)",
            flags);
        std::smatch m;
        if (!std::regex_search(log, m, ev_rx)) return;
        const std::string id = m[1].matched ? m[1].str() : m[2].str();

        auto xml_data = [&](const char* name) -> std::string {
            // Name is a compile-time constant (TargetUserName / IpAddress).
            std::string pat = std::string(R"(<Data Name=")") + name + R"(">([^<]*)</Data>)";
            std::regex rx(pat);
            std::smatch dm;
            if (std::regex_search(log, dm, rx)) return dm[1].str();
            return {};
        };
        std::string user = xml_data("TargetUserName");
        std::string ip   = xml_data("IpAddress");
        if (ip == "-" || ip == "::1" || ip == "127.0.0.1") {
            // keep loopback IPs (they are real), only drop the Windows placeholder
            if (ip == "-") ip.clear();
        }

        AuthEvent e;
        e.timestamp_ms = ts;
        e.session_type = "windows";
        e.username = user;
        e.source_ip = ip;

        if (id == "4625") {
            e.type = AuthEventType::AUTH_LOGIN_FAILED;
            e.detail = "Failed authentication (EventID 4625)";
        } else if (id == "4624") {
            e.type = AuthEventType::AUTH_LOGIN_SUCCESS;
            e.detail = "Successful logon (EventID 4624)";
        } else if (id == "4634") {
            e.type = AuthEventType::AUTH_LOGOUT;
            e.detail = "Logoff (EventID 4634)";
        } else if (id == "4648") {
            e.type = AuthEventType::AUTH_LOGIN_SUCCESS;
            e.detail = "Explicit credentials (EventID 4648)";
        } else if (id == "4672") {
            e.type = AuthEventType::AUTH_PRIVILEGE_ESCALATION;
            e.detail = "Special privileges assigned (EventID 4672)";
        } else if (id == "4740") {
            e.type = AuthEventType::AUTH_ACCOUNT_LOCKOUT;
            e.detail = "Account locked out (EventID 4740)";
        } else {
            return;
        }
        pending_events_.push_back(std::move(e));
    }

    void parse_linux_auth(const std::string& log_in, int64_t ts) {
        std::string log = log_in;
        if (log.size() > 65536) log.resize(65536);

        if (log.find("Failed password") != std::string::npos) {
            AuthEvent e;
            e.type = AuthEventType::AUTH_LOGIN_FAILED;
            e.timestamp_ms = ts;
            e.session_type = "ssh";
            static const std::regex fail_rx(
                R"(Failed password for (?:invalid user )?(\S+) from (\S+))",
                std::regex_constants::icase);
            std::smatch m;
            if (std::regex_search(log, m, fail_rx)) {
                e.username = m[1].str();
                e.source_ip = m[2].str();
            }
            e.detail = "SSH failed password";
            pending_events_.push_back(std::move(e));
        }

        // Only emit success on the sshd "Accepted <method> for ... from ..." shape.
        {
            static const std::regex acc_rx(
                R"(Accepted \S+ for (\S+) from (\S+))",
                std::regex_constants::icase);
            std::smatch m;
            if (std::regex_search(log, m, acc_rx)) {
                AuthEvent e;
                e.type = AuthEventType::AUTH_LOGIN_SUCCESS;
                e.timestamp_ms = ts;
                e.session_type = "ssh";
                e.username = m[1].str();
                e.source_ip = m[2].str();
                e.detail = "SSH login accepted";
                pending_events_.push_back(std::move(e));
            }
        }

        if (log.find("sudo") != std::string::npos && log.find("COMMAND") != std::string::npos) {
            AuthEvent e;
            e.type = AuthEventType::AUTH_PRIVILEGE_ESCALATION;
            e.timestamp_ms = ts;
            e.session_type = "sudo";
            // Capture the user after "sudo:", not the "sudo" token itself.
            static const std::regex sudo_rx(R"(sudo:\s+(\S+)\s*:.*COMMAND=(.+))");
            std::smatch m;
            if (std::regex_search(log, m, sudo_rx)) {
                e.username = m[1].str();
                e.detail = "sudo: " + m[2].str();
            } else {
                e.detail = "sudo COMMAND";
            }
            pending_events_.push_back(std::move(e));
        }

        if (log.find("su[") != std::string::npos || log.find("su:") != std::string::npos) {
            if (log.find("Successful") != std::string::npos || log.find("session opened") != std::string::npos) {
                AuthEvent e;
                e.type = AuthEventType::AUTH_PRIVILEGE_ESCALATION;
                e.timestamp_ms = ts;
                e.session_type = "su";
                e.detail = "su session opened";
                pending_events_.push_back(std::move(e));
            }
        }
    }
};

#endif
