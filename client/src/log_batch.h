#ifndef SEAHORSE_LOG_BATCH_H
#define SEAHORSE_LOG_BATCH_H

// =============================================================================
// SecureSeaHorse -- MSG_LOG_BATCH (0x0C) wire format
// =============================================================================
// Backward-compatible protocol extension:
//   * RawTelemetry.raw_log_chunk remains 512 bytes. Old servers and v1
//     clients are unchanged. The 512-byte field is still filled with a
//     truncated preview of the newest log data so existing regex rules fire.
//   * New agents (HMAC/v2 only) also send MSG_LOG_BATCH with a variable-
//     length, length-prefixed record payload (auth Event XML, auth.log /
//     secure / syslog lines). Payload is capped at 256 KiB.
//   * Servers that do not know 0x0C already read the payload and hit the
//     existing "Unknown v2 msg_type" default -- the stream stays in sync.
// =============================================================================

#include <cstdint>
#include <string>
#include <vector>
#include <sstream>
#include <cctype>

struct LogRecord {
    std::string source;       // "windows-security", "linux-auth", "linux-syslog"
    int64_t     timestamp_ms = 0;
    std::string text;         // One Event XML document, or one log line
};

struct LogBatch {
    int32_t device_id = 0;
    int64_t timestamp_ms = 0;
    std::vector<LogRecord> records;
};

// Sources the agent tags on each record. The server parser is selected by
// this tag, not by the server's host OS (a Linux server must parse Windows
// Event XML forwarded by a Windows agent).
inline constexpr const char* kAuthSourceWindowsSecurity = "windows-security";
inline constexpr const char* kAuthSourceLinuxAuth       = "linux-auth";
inline constexpr const char* kAuthSourceLinuxSyslog     = "linux-syslog";

// XPath used by the Windows agent (Security channel). Event IDs only --
// not Level<=3 -- so Information / Audit Success events such as 4624/4625
// are collected.
inline constexpr const char* kWindowsAuthXPath =
    "Event/System[EventID=4624 or EventID=4625 or EventID=4634 or "
    "EventID=4648 or EventID=4672 or EventID=4740]";

inline constexpr size_t kLogBatchMaxBytes   = 256 * 1024;
inline constexpr int    kLogBatchMaxRecords = 32;

inline std::string serialize_log_batch(const LogBatch& batch) {
    std::ostringstream os;
    os << "SSH-LOGBATCH/1\n"
       << "device_id=" << batch.device_id << "\n"
       << "timestamp_ms=" << batch.timestamp_ms << "\n"
       << "record_count=" << batch.records.size() << "\n"
       << "\n";
    for (const auto& r : batch.records) {
        os << "source=" << r.source << "\n"
           << "ts=" << r.timestamp_ms << "\n"
           << r.text.size() << "\n";
        os.write(r.text.data(), static_cast<std::streamsize>(r.text.size()));
        os.put('\n');  // framing newline, not part of `len`
    }
    return os.str();
}

namespace log_batch_detail {
inline bool read_line(const std::string& s, size_t& i, std::string& line) {
    if (i >= s.size()) return false;
    size_t start = i;
    while (i < s.size() && s[i] != '\n') ++i;
    line.assign(s, start, i - start);
    if (i < s.size() && s[i] == '\n') ++i;
    if (!line.empty() && line.back() == '\r') line.pop_back();
    return true;
}
} // namespace log_batch_detail

// Returns an empty batch (device_id == 0) on parse failure.
inline LogBatch deserialize_log_batch(const std::string& payload) {
    LogBatch batch;
    size_t i = 0;
    std::string line;
    if (!log_batch_detail::read_line(payload, i, line) || line != "SSH-LOGBATCH/1")
        return {};
    int declared = 0;
    while (log_batch_detail::read_line(payload, i, line)) {
        if (line.empty()) break;
        auto eq = line.find('=');
        if (eq == std::string::npos) return {};
        std::string k = line.substr(0, eq);
        std::string v = line.substr(eq + 1);
        if (k == "device_id") batch.device_id = static_cast<int32_t>(std::stoll(v));
        else if (k == "timestamp_ms") batch.timestamp_ms = std::stoll(v);
        else if (k == "record_count") declared = static_cast<int>(std::stoll(v));
    }
    if (declared < 0 || declared > 4096) return {};
    batch.records.reserve(static_cast<size_t>(declared));
    for (int n = 0; n < declared; ++n) {
        LogRecord rec;
        if (!log_batch_detail::read_line(payload, i, line)) return {};
        if (line.rfind("source=", 0) != 0) return {};
        rec.source = line.substr(7);
        if (!log_batch_detail::read_line(payload, i, line)) return {};
        if (line.rfind("ts=", 0) != 0) return {};
        rec.timestamp_ms = std::stoll(line.substr(3));
        if (!log_batch_detail::read_line(payload, i, line)) return {};
        // length
        size_t len = 0;
        for (char c : line) {
            if (!std::isdigit(static_cast<unsigned char>(c))) return {};
            len = len * 10 + static_cast<size_t>(c - '0');
            if (len > kLogBatchMaxBytes) return {};
        }
        if (i + len > payload.size()) return {};
        rec.text.assign(payload, i, len);
        i += len;
        // Consume the framing newline that follows every record body.
        if (i < payload.size() && payload[i] == '\n') ++i;
        else if (i < payload.size() && payload[i] == '\r') {
            ++i;
            if (i < payload.size() && payload[i] == '\n') ++i;
        }
        batch.records.push_back(std::move(rec));
    }
    return batch;
}

#endif
