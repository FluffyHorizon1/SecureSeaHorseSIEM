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
#include <vector>
#include <queue>
#include <mutex>
#include <thread>
#include <condition_variable>
#include <atomic>
#include <chrono>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <functional>
#include <memory>

// =============================================================================
// CONSTANTS
// =============================================================================
constexpr int DEFAULT_PORT = 65432;
constexpr int CLIENT_SLEEP_MS = 2000;
constexpr uint32_t PROTOCOL_MAGIC = 0xDEADBEEF;
constexpr const char* DEFAULT_CONFIG_PATH = "server.conf";

// =============================================================================
// PROTOCOL STRUCTURES
// =============================================================================
#pragma pack(push, 1)
struct PacketHeader {
    uint32_t magic;
    uint16_t version;
    uint32_t payload_len;
    uint32_t checksum;
};

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

// =============================================================================
// CORE HELPERS
// =============================================================================
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

// =============================================================================
// CONFIGURATION MANAGEMENT
// =============================================================================
struct AppConfig {
    std::map<std::string, std::string> data;

    std::string get(const std::string& key, const std::string& def) const {
        return data.count(key) ? data.at(key) : def;
    }

    int get_int(const std::string& key, int def) const {
        try { return data.count(key) ? std::stoi(data.at(key)) : def; }
        catch (...) { return def; }
    }

    size_t get_size(const std::string& key, size_t def) const {
        try { return data.count(key) ? std::stoull(data.at(key)) : def; }
        catch (...) { return def; }
    }

    bool get_bool(const std::string& key, bool def) const {
        if (!data.count(key)) return def;
        std::string v = data.at(key);
        std::transform(v.begin(), v.end(), v.begin(), ::tolower);
        if (v == "true" || v == "1" || v == "yes") return true;
        if (v == "false" || v == "0" || v == "no") return false;
        return def;
    }

    void set(const std::string& key, const std::string& val) { data[key] = val; }
};

inline AppConfig load_config(const std::string& filename) {
    AppConfig config;
    std::ifstream file(filename);
    if (!file.is_open()) return config;
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

// =============================================================================
// PHASE 1: CLI ARGUMENT PARSING
// =============================================================================
struct CliArgs {
    std::string config_path;
    std::map<std::string, std::string> overrides;
    bool show_help = false;
    bool show_version = false;

    void apply_overrides(AppConfig& conf) const {
        for (const auto& [k, v] : overrides) conf.set(k, v);
    }
};

inline void print_server_usage(const char* prog) {
    std::cout << "Usage: " << prog << " [OPTIONS]\n"
        << "\nOptions:\n"
        << "  -c, --config <path>    Path to server.conf (default: ./server.conf)\n"
        << "  -s, --set <key=value>  Override a config value (repeatable)\n"
        << "  -h, --help             Show this help message\n"
        << "  -v, --version          Show version\n"
        << "\nPhase 1 — Thread Pool:\n"
        << "  pool_min / pool_max / pool_idle_timeout_s\n"
        << "\nPhase 2 — Data Intelligence:\n"
        << "  db_enabled / db_host / db_port / db_name / db_user / db_pass\n"
        << "  rules_file             Path to regex rules (default: rules.conf)\n"
        << "  alert_enabled / alert_log\n";
}

inline CliArgs parse_server_cli(int argc, char* argv[]) {
    CliArgs args;
    args.config_path = DEFAULT_CONFIG_PATH;
    for (int i = 1; i < argc; i++) {
        std::string arg(argv[i]);
        if (arg == "-h" || arg == "--help") { args.show_help = true; }
        else if (arg == "-v" || arg == "--version") { args.show_version = true; }
        else if ((arg == "-c" || arg == "--config") && i + 1 < argc) { args.config_path = argv[++i]; }
        else if ((arg == "-s" || arg == "--set") && i + 1 < argc) {
            std::string kv = argv[++i];
            size_t eq = kv.find('=');
            if (eq != std::string::npos) args.overrides[kv.substr(0, eq)] = kv.substr(eq + 1);
        }
        else { std::cerr << "Unknown argument: " << arg << "\n"; }
    }
    return args;
}

// =============================================================================
// PHASE 1: ASYNC LOGGER WITH LOG ROTATION
// =============================================================================
class AsyncLogger {
public:
    enum Level { INFO, WARN, ERROR_LOG, DEBUG };
private:
    struct LogEntry { Level level; std::string message; std::chrono::system_clock::time_point timestamp; };
    std::queue<LogEntry> queue_;
    std::mutex queue_mutex_;
    std::condition_variable cv_;
    std::atomic<bool> running_{ true };
    std::thread worker_;
    std::ofstream log_file_;
    std::string base_filename_;
    size_t max_file_size_, current_file_size_;
    int max_rotated_files_;
    bool echo_to_console_;

    static const char* level_str(Level l) {
        switch (l) { case WARN: return "[WARN] "; case ERROR_LOG: return "[ERROR] "; case DEBUG: return "[DEBUG] "; default: return "[INFO] "; }
    }
    std::string format_entry(const LogEntry& entry) {
        std::time_t t = std::chrono::system_clock::to_time_t(entry.timestamp);
        std::stringstream ss;
        ss << "[" << std::put_time(std::localtime(&t), "%Y-%m-%d %H:%M:%S") << "] " << level_str(entry.level) << entry.message;
        return ss.str();
    }
    void rotate_logs() {
        log_file_.close();
        std::remove((base_filename_ + "." + std::to_string(max_rotated_files_)).c_str());
        for (int i = max_rotated_files_ - 1; i >= 1; i--)
            std::rename((base_filename_ + "." + std::to_string(i)).c_str(), (base_filename_ + "." + std::to_string(i + 1)).c_str());
        std::rename(base_filename_.c_str(), (base_filename_ + ".1").c_str());
        log_file_.open(base_filename_, std::ios::app);
        current_file_size_ = 0;
    }
    void worker_loop() {
        while (true) {
            std::queue<LogEntry> batch;
            { std::unique_lock<std::mutex> lock(queue_mutex_); cv_.wait(lock, [this] { return !queue_.empty() || !running_; }); if (!running_ && queue_.empty()) return; std::swap(batch, queue_); }
            while (!batch.empty()) {
                std::string formatted = format_entry(batch.front()); batch.pop();
                if (echo_to_console_) std::cout << formatted << "\n";
                if (log_file_.is_open()) { log_file_ << formatted << "\n"; log_file_.flush(); current_file_size_ += formatted.size() + 1; if (current_file_size_ >= max_file_size_) rotate_logs(); }
            }
        }
    }
public:
    AsyncLogger(const std::string& filename = "", size_t max_file_size = 10 * 1024 * 1024, int max_files = 5, bool echo_console = true)
        : base_filename_(filename), max_file_size_(max_file_size), max_rotated_files_(max_files), current_file_size_(0), echo_to_console_(echo_console) {
        if (!filename.empty()) { log_file_.open(filename, std::ios::app); if (log_file_.is_open()) { log_file_.seekp(0, std::ios::end); current_file_size_ = static_cast<size_t>(log_file_.tellp()); } }
        worker_ = std::thread(&AsyncLogger::worker_loop, this);
    }
    ~AsyncLogger() { { std::lock_guard<std::mutex> lock(queue_mutex_); running_ = false; } cv_.notify_one(); if (worker_.joinable()) worker_.join(); }
    AsyncLogger(const AsyncLogger&) = delete;
    AsyncLogger& operator=(const AsyncLogger&) = delete;
    void log(Level level, const std::string& msg) { { std::lock_guard<std::mutex> lock(queue_mutex_); if (!running_) return; queue_.push({ level, msg, std::chrono::system_clock::now() }); } cv_.notify_one(); }
};

// =============================================================================
// PHASE 1: DYNAMIC THREAD POOL
// =============================================================================
class DynamicThreadPool {
public:
    struct Config { size_t min_threads = 2; size_t max_threads = 32; int idle_timeout_seconds = 30; };
private:
    Config config_;
    std::queue<std::function<void()>> tasks_;
    std::mutex queue_mutex_;
    std::condition_variable cv_;
    std::atomic<bool> stop_{ false };
    std::atomic<size_t> active_workers_{ 0 }, total_workers_{ 0 }, pending_tasks_{ 0 };
    std::vector<std::thread> workers_;
    std::mutex workers_mutex_;
    std::thread monitor_;

    void worker_func() {
        total_workers_++;
        while (true) {
            std::function<void()> task;
            {
                std::unique_lock<std::mutex> lock(queue_mutex_);
                bool got_work = cv_.wait_for(lock, std::chrono::seconds(config_.idle_timeout_seconds), [this] { return stop_ || !tasks_.empty(); });
                if (stop_ && tasks_.empty()) { total_workers_--; return; }
                if (!got_work) { if (total_workers_.load() > config_.min_threads) { total_workers_--; return; } continue; }
                if (tasks_.empty()) continue;
                task = std::move(tasks_.front()); tasks_.pop(); pending_tasks_--;
            }
            active_workers_++; task(); active_workers_--;
        }
    }
    void spawn_worker() { std::lock_guard<std::mutex> lock(workers_mutex_); workers_.emplace_back(&DynamicThreadPool::worker_func, this); }
    void monitor_func() {
        while (!stop_) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            size_t pending = pending_tasks_.load(), total = total_workers_.load(), active = active_workers_.load();
            if (pending > 0 && active >= total && total < config_.max_threads) {
                size_t to_spawn = std::min({ pending, config_.max_threads - total, (size_t)4 });
                for (size_t i = 0; i < to_spawn; i++) spawn_worker();
            }
        }
    }
public:
    explicit DynamicThreadPool(const Config& cfg = {}) : config_(cfg) {
        if (config_.min_threads == 0) config_.min_threads = 1;
        if (config_.max_threads < config_.min_threads) config_.max_threads = config_.min_threads;
        for (size_t i = 0; i < config_.min_threads; i++) spawn_worker();
        monitor_ = std::thread(&DynamicThreadPool::monitor_func, this);
    }
    ~DynamicThreadPool() {
        { std::lock_guard<std::mutex> lock(queue_mutex_); stop_ = true; } cv_.notify_all();
        if (monitor_.joinable()) monitor_.join();
        { std::lock_guard<std::mutex> lock(workers_mutex_); for (auto& w : workers_) if (w.joinable()) w.join(); }
    }
    DynamicThreadPool(const DynamicThreadPool&) = delete;
    DynamicThreadPool& operator=(const DynamicThreadPool&) = delete;
    template<class F> void enqueue(F&& f) { { std::lock_guard<std::mutex> lock(queue_mutex_); if (stop_) return; tasks_.emplace(std::forward<F>(f)); pending_tasks_++; } cv_.notify_one(); }
    size_t active_count() const { return active_workers_.load(); }
    size_t total_count() const { return total_workers_.load(); }
    size_t pending_count() const { return pending_tasks_.load(); }
};

#endif
