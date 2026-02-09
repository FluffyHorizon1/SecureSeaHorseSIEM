#ifndef SERVER_PROTOCOL_H
#define SERVER_PROTOCOL_H

#define _CRT_SECURE_NO_WARNINGS 
#if defined(_MSC_VER) && !defined(_WIN32)
#define _WIN32
#endif

#include <cstdint>
#include <cstring>
#include <algorithm>
#include <string>  
#include <fstream> 
#include <map>     

// --- CONSTANTS ---
constexpr int DEFAULT_PORT = 65432;
constexpr int CLIENT_SLEEP_MS = 2000;
constexpr uint32_t PROTOCOL_MAGIC = 0xDEADBEEF;
constexpr const char* DEFAULT_CONFIG_PATH = "server.conf"; // Added proper file path constant

#pragma pack(push, 1)
// --- FRAMING HEADER ---
struct PacketHeader {
    uint32_t magic;
    uint16_t version;
    uint32_t payload_len;
    uint32_t checksum;
};

// --- PAYLOAD ---
struct RawTelemetry {
    uint16_t struct_version;
    int32_t device_id;
    int64_t timestamp_ms;

    char machine_name[64];
    char machine_ip[32];
    char os_user[32];

    uint64_t cpu_idle_ticks;
    uint64_t cpu_kernel_ticks;
    uint64_t cpu_user_ticks;

    uint64_t ram_total_bytes;
    uint64_t ram_avail_bytes;

    uint64_t disk_total_bytes;
    uint64_t disk_free_bytes;

    uint64_t net_bytes_in;
    uint64_t net_bytes_out;

    char raw_log_chunk[512];
    uint8_t extension_block[128];
};
#pragma pack(pop)

// --- HELPERS ---
inline uint32_t calculate_crc32(const uint8_t* data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ (0xEDB88320 & (-(int)(crc & 1)));
        }
    }
    return ~crc;
}

inline void safe_strncpy(char* dest, const char* src, size_t dest_size) {
    if (dest_size > 0) {
        strncpy(dest, src, dest_size - 1);
        dest[dest_size - 1] = '\0';
    }
}

inline uint64_t swap_uint64(uint64_t val) {
    val = ((val << 8) & 0xFF00FF00FF00FF00ULL) | ((val >> 8) & 0x00FF00FF00FF00FFULL);
    val = ((val << 16) & 0xFFFF0000FFFF0000ULL) | ((val >> 16) & 0x0000FFFF0000FFFFULL);
    return (val << 32) | (val >> 32);
}

inline bool is_little_endian() { int num = 1; return (*(char*)&num == 1); }
inline uint64_t htonll_custom(uint64_t val) { return is_little_endian() ? swap_uint64(val) : val; }
inline uint64_t ntohll_custom(uint64_t val) { return is_little_endian() ? swap_uint64(val) : val; }

// --- CONFIGURATION MANAGEMENT ---
struct AppConfig {
    std::map<std::string, std::string> data;

    std::string get(const std::string& key, const std::string& def) {
        return data.count(key) ? data.at(key) : def;
    }

    int get_int(const std::string& key, int def) {
        try {
            return data.count(key) ? std::stoi(data.at(key)) : def;
        }
        catch (...) {
            return def;
        }
    }
};

inline AppConfig load_config(const std::string& filename) {
    AppConfig config;
    std::ifstream file(filename);
    if (!file.is_open()) return config; // Return empty config if file is missing

    std::string line;
    while (std::getline(file, line)) {
        size_t comment = line.find('#');
        if (comment != std::string::npos) line = line.substr(0, comment);

        line.erase(0, line.find_first_not_of(" \t\r\n"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);

        if (line.empty()) continue;

        size_t sep = line.find('=');
        if (sep != std::string::npos) {
            std::string key = line.substr(0, sep);
            std::string val = line.substr(sep + 1);

            key.erase(key.find_last_not_of(" \t") + 1);
            val.erase(0, val.find_first_not_of(" \t"));

            config.data[key] = val;
        }
    }
    return config;
}

#endif