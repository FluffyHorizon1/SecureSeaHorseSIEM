#ifndef CONNECTION_INVENTORY_H
#define CONNECTION_INVENTORY_H

#ifndef NOMINMAX
#define NOMINMAX
#endif

// =============================================================================
// SecureSeaHorse SIEM -- Phase 12: Network Connection Inventory (Client-Side)
// =============================================================================
// Provides:
//   - Active TCP/UDP connection enumeration (like netstat)
//   - Listening port inventory
//   - New/closed connection detection between scans
//   - Unusual port and outbound connection flagging
//   - Windows: GetTcpTable2/GetUdpTable / Linux: /proc/net/tcp, /proc/net/udp
// =============================================================================

#include <string>
#include <vector>
#include <map>
#include <set>
#include <mutex>
#include <sstream>
#include <algorithm>
#include <cstdint>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#else
#include <fstream>
#include <arpa/inet.h>
#endif

// =============================================================================
// CONNECTION ENTRY
// =============================================================================
struct ConnectionEntry {
    std::string protocol;       // "tcp", "udp"
    std::string local_addr;     // "192.168.1.5"
    uint16_t    local_port  = 0;
    std::string remote_addr;    // "93.184.216.34"
    uint16_t    remote_port = 0;
    std::string state;          // "ESTABLISHED","LISTEN","TIME_WAIT", etc.
    uint32_t    owning_pid  = 0;
    std::string process_name;   // Resolved process name (if available)
};

// =============================================================================
// CONNECTION CHANGE
// =============================================================================
enum class ConnChangeType { CONN_NEW, CONN_CLOSED, CONN_SUSPICIOUS };

struct ConnectionChange {
    ConnChangeType  type = ConnChangeType::CONN_NEW;
    ConnectionEntry conn;
    std::string     reason;
};

// =============================================================================
// CONNECTION REPORT
// =============================================================================
struct ConnectionReport {
    int32_t     device_id       = 0;
    int64_t     timestamp_ms    = 0;
    uint32_t    total_tcp       = 0;
    uint32_t    total_udp       = 0;
    uint32_t    listening_ports = 0;
    std::vector<ConnectionEntry>  connections;
    std::vector<ConnectionChange> changes;
};

// =============================================================================
// SERIALIZATION
// =============================================================================
inline std::string serialize_connection_report(const ConnectionReport& r) {
    std::ostringstream oss;
    oss << "CONN|" << r.device_id << "|" << r.timestamp_ms << "|"
        << r.connections.size() << "|" << r.changes.size() << "\n";

    for (const auto& c : r.connections) {
        oss << c.protocol << "|" << c.local_addr << "|" << c.local_port << "|"
            << c.remote_addr << "|" << c.remote_port << "|" << c.state << "|"
            << c.owning_pid << "|" << c.process_name << "\n";
    }

    oss << "CONN_CHANGES\n";
    for (const auto& ch : r.changes) {
        std::string type_str = "new";
        if (ch.type == ConnChangeType::CONN_CLOSED) type_str = "closed";
        else if (ch.type == ConnChangeType::CONN_SUSPICIOUS) type_str = "suspicious";
        oss << type_str << "|" << ch.conn.protocol << "|" << ch.conn.remote_addr << "|"
            << ch.conn.remote_port << "|" << ch.reason << "\n";
    }
    oss << "CONN_END\n";
    return oss.str();
}

inline ConnectionReport deserialize_connection_report(const std::string& data) {
    ConnectionReport r;
    std::istringstream iss(data);
    std::string line;

    if (!std::getline(iss, line) || line.substr(0, 5) != "CONN|") return r;
    {
        std::istringstream hdr(line.substr(5));
        std::string tok;
        if (std::getline(hdr, tok, '|')) r.device_id = std::stoi(tok);
        if (std::getline(hdr, tok, '|')) r.timestamp_ms = std::stoll(tok);
        uint32_t conn_count = 0, change_count = 0;
        if (std::getline(hdr, tok, '|')) conn_count = std::stoul(tok);
        if (std::getline(hdr, tok, '|')) change_count = std::stoul(tok);
        (void)change_count;

        for (uint32_t i = 0; i < conn_count && std::getline(iss, line); i++) {
            if (line == "CONN_CHANGES") break;
            ConnectionEntry c;
            std::istringstream row(line);
            std::string t;
            if (std::getline(row, t, '|')) c.protocol = t;
            if (std::getline(row, t, '|')) c.local_addr = t;
            if (std::getline(row, t, '|')) c.local_port = static_cast<uint16_t>(std::stoul(t));
            if (std::getline(row, t, '|')) c.remote_addr = t;
            if (std::getline(row, t, '|')) c.remote_port = static_cast<uint16_t>(std::stoul(t));
            if (std::getline(row, t, '|')) c.state = t;
            if (std::getline(row, t, '|')) c.owning_pid = std::stoul(t);
            if (std::getline(row, t, '|')) c.process_name = t;
            r.connections.push_back(std::move(c));
        }
    }

    // Read changes until CONN_END
    while (std::getline(iss, line)) {
        if (line == "CONN_END" || line == "CONN_CHANGES") continue;
        if (line.empty()) continue;
        ConnectionChange ch;
        std::istringstream row(line);
        std::string t;
        if (std::getline(row, t, '|')) {
            if (t == "closed") ch.type = ConnChangeType::CONN_CLOSED;
            else if (t == "suspicious") ch.type = ConnChangeType::CONN_SUSPICIOUS;
        }
        if (std::getline(row, t, '|')) ch.conn.protocol = t;
        if (std::getline(row, t, '|')) ch.conn.remote_addr = t;
        if (std::getline(row, t, '|')) ch.conn.remote_port = static_cast<uint16_t>(std::stoul(t));
        if (std::getline(row, t, '|')) ch.reason = t;
        r.changes.push_back(std::move(ch));
    }
    return r;
}

// =============================================================================
// CONNECTION SCANNER CONFIG
// =============================================================================
struct ConnectionScannerConfig {
    bool enabled = true;
    int  scan_interval_s = 60;
    bool flag_unusual_ports = true;
    std::set<uint16_t> known_ports = {
        20,21,22,23,25,53,80,110,143,443,445,993,995,
        3306,3389,5432,5900,8080,8443,8888
    };
    std::set<uint16_t> suspicious_remote_ports = {
        4444, 5555, 6666, 7777, 8888, 9999,  // Common reverse shells
        1337, 31337,                            // Leet ports
        6667, 6697,                             // IRC (C2)
        4443, 8443,                             // Alt HTTPS (C2)
    };
};

// =============================================================================
// CONNECTION SCANNER
// =============================================================================
class ConnectionScanner {
public:
    explicit ConnectionScanner(const ConnectionScannerConfig& cfg = {})
        : config_(cfg) {}

    std::vector<ConnectionEntry> scan() {
        std::vector<ConnectionEntry> conns;
#ifdef _WIN32
        scan_tcp_windows(conns);
        scan_udp_windows(conns);
#else
        scan_proc_net(conns, "/proc/net/tcp", "tcp");
        scan_proc_net(conns, "/proc/net/tcp6", "tcp6");
        scan_proc_net(conns, "/proc/net/udp", "udp");
#endif
        return conns;
    }

    std::vector<ConnectionChange> diff(const std::vector<ConnectionEntry>& current) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<ConnectionChange> changes;

        // Build key sets
        auto make_key = [](const ConnectionEntry& c) -> std::string {
            return c.protocol + ":" + c.local_addr + ":" + std::to_string(c.local_port)
                + "->" + c.remote_addr + ":" + std::to_string(c.remote_port);
        };

        std::set<std::string> current_keys;
        for (const auto& c : current) current_keys.insert(make_key(c));

        // New connections
        for (const auto& c : current) {
            std::string key = make_key(c);
            if (baseline_keys_.find(key) == baseline_keys_.end()) {
                ConnectionChange ch;
                ch.type = ConnChangeType::CONN_NEW;
                ch.conn = c;
                ch.reason = "New connection";
                changes.push_back(std::move(ch));
            }
        }

        // Closed connections
        for (const auto& key : baseline_keys_) {
            if (current_keys.find(key) == current_keys.end()) {
                ConnectionChange ch;
                ch.type = ConnChangeType::CONN_CLOSED;
                ch.reason = "Connection closed";
                changes.push_back(std::move(ch));
            }
        }

        // Suspicious connections
        if (config_.flag_unusual_ports) {
            for (const auto& c : current) {
                if (c.state != "LISTEN" && !c.remote_addr.empty() && c.remote_addr != "0.0.0.0" && c.remote_addr != "::") {
                    if (config_.suspicious_remote_ports.count(c.remote_port)) {
                        ConnectionChange ch;
                        ch.type = ConnChangeType::CONN_SUSPICIOUS;
                        ch.conn = c;
                        ch.reason = "Suspicious remote port: " + std::to_string(c.remote_port);
                        changes.push_back(std::move(ch));
                    }
                }
            }
        }

        return changes;
    }

    void update_baseline(const std::vector<ConnectionEntry>& conns) {
        std::lock_guard<std::mutex> lock(mutex_);
        baseline_keys_.clear();
        for (const auto& c : conns) {
            baseline_keys_.insert(c.protocol + ":" + c.local_addr + ":" + std::to_string(c.local_port)
                + "->" + c.remote_addr + ":" + std::to_string(c.remote_port));
        }
    }

private:
    ConnectionScannerConfig config_;
    mutable std::mutex mutex_;
    std::set<std::string> baseline_keys_;

#ifdef _WIN32
    void scan_tcp_windows(std::vector<ConnectionEntry>& conns) {
        ULONG size = 0;
        GetTcpTable2(NULL, &size, TRUE);
        if (size == 0) return;

        std::vector<uint8_t> buf(size);
        PMIB_TCPTABLE2 table = reinterpret_cast<PMIB_TCPTABLE2>(buf.data());
        if (GetTcpTable2(table, &size, TRUE) != NO_ERROR) return;

        for (DWORD i = 0; i < table->dwNumEntries; i++) {
            const auto& row = table->table[i];
            ConnectionEntry c;
            c.protocol = "tcp";

            char addr[46] = {};
            struct in_addr ia;
            ia.S_un.S_addr = row.dwLocalAddr;
            inet_ntop(AF_INET, &ia, addr, sizeof(addr));
            c.local_addr = addr;
            c.local_port = ntohs(static_cast<uint16_t>(row.dwLocalPort));

            ia.S_un.S_addr = row.dwRemoteAddr;
            inet_ntop(AF_INET, &ia, addr, sizeof(addr));
            c.remote_addr = addr;
            c.remote_port = ntohs(static_cast<uint16_t>(row.dwRemotePort));

            c.owning_pid = row.dwOwningPid;

            switch (row.dwState) {
                case MIB_TCP_STATE_LISTEN:  c.state = "LISTEN"; break;
                case MIB_TCP_STATE_ESTAB:   c.state = "ESTABLISHED"; break;
                case MIB_TCP_STATE_SYN_SENT: c.state = "SYN_SENT"; break;
                case MIB_TCP_STATE_CLOSE_WAIT: c.state = "CLOSE_WAIT"; break;
                case MIB_TCP_STATE_TIME_WAIT: c.state = "TIME_WAIT"; break;
                default: c.state = "OTHER"; break;
            }

            conns.push_back(std::move(c));
        }
    }

    void scan_udp_windows(std::vector<ConnectionEntry>& conns) {
        ULONG size = 0;
        GetUdpTable(NULL, &size, TRUE);
        if (size == 0) return;

        std::vector<uint8_t> buf(size);
        PMIB_UDPTABLE table = reinterpret_cast<PMIB_UDPTABLE>(buf.data());
        if (GetUdpTable(table, &size, TRUE) != NO_ERROR) return;

        for (DWORD i = 0; i < table->dwNumEntries; i++) {
            ConnectionEntry c;
            c.protocol = "udp";
            char addr[46] = {};
            struct in_addr ia;
            ia.S_un.S_addr = table->table[i].dwLocalAddr;
            inet_ntop(AF_INET, &ia, addr, sizeof(addr));
            c.local_addr = addr;
            c.local_port = ntohs(static_cast<uint16_t>(table->table[i].dwLocalPort));
            c.state = "LISTEN";
            conns.push_back(std::move(c));
        }
    }
#else
    void scan_proc_net(std::vector<ConnectionEntry>& conns, const char* path, const char* proto) {
        std::ifstream f(path);
        if (!f.is_open()) return;
        std::string line;
        std::getline(f, line); // Skip header

        while (std::getline(f, line)) {
            ConnectionEntry c;
            c.protocol = proto;

            // Parse hex addresses from /proc/net/tcp format
            std::istringstream iss(line);
            std::string slot, local, remote, st;
            iss >> slot >> local >> remote >> st;

            auto parse_addr = [](const std::string& hex_addr, std::string& ip, uint16_t& port) {
                auto colon = hex_addr.find(':');
                if (colon == std::string::npos) return;
                std::string hex_ip = hex_addr.substr(0, colon);
                std::string hex_port = hex_addr.substr(colon + 1);
                port = static_cast<uint16_t>(std::stoul(hex_port, nullptr, 16));
                if (hex_ip.size() == 8) {
                    uint32_t addr = std::stoul(hex_ip, nullptr, 16);
                    unsigned char* bytes = reinterpret_cast<unsigned char*>(&addr);
                    ip = std::to_string(bytes[0]) + "." + std::to_string(bytes[1])
                       + "." + std::to_string(bytes[2]) + "." + std::to_string(bytes[3]);
                }
            };

            parse_addr(local, c.local_addr, c.local_port);
            parse_addr(remote, c.remote_addr, c.remote_port);

            int state_num = std::stoi(st, nullptr, 16);
            switch (state_num) {
                case 1:  c.state = "ESTABLISHED"; break;
                case 2:  c.state = "SYN_SENT"; break;
                case 6:  c.state = "TIME_WAIT"; break;
                case 8:  c.state = "CLOSE_WAIT"; break;
                case 10: c.state = "LISTEN"; break;
                default: c.state = "OTHER"; break;
            }

            conns.push_back(std::move(c));
        }
    }
#endif
};

#endif
