#define _CRT_SECURE_NO_WARNINGS 

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

// --- OPENSSL INCLUDES ---
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "server_protocol.h" 

#ifdef _WIN32
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")
typedef int socklen_t;
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#define INVALID_SOCKET -1
#define closesocket close
typedef int SOCKET;
#endif

// --- GLOBAL CONTROL ---
std::atomic<bool> g_running(true);

void handle_signal(int sig) {
    g_running = false;
}

// --- SIMPLE LOGGER ---
class SimpleLogger {
    std::mutex log_mutex;
    std::ofstream log_file;
public:
    enum Level { INFO, WARN, ERROR_LOG };
    SimpleLogger(const std::string& filename) {
        log_file.open(filename, std::ios::app);
    }
    void log(Level level, const std::string& msg) {
        std::lock_guard<std::mutex> lock(log_mutex);
        auto now = std::chrono::system_clock::now();
        std::time_t now_c = std::chrono::system_clock::to_time_t(now);
        const char* lvlStr = (level == WARN) ? "[WARN] " : (level == ERROR_LOG) ? "[ERROR] " : "[INFO] ";

        std::stringstream ss;
        ss << "[" << std::put_time(std::localtime(&now_c), "%T") << "] " << lvlStr << msg;
        std::cout << ss.str() << "\n";

        if (log_file.is_open()) {
            log_file << "[" << std::put_time(std::localtime(&now_c), "%F %T") << "] " << lvlStr << msg << "\n";
            log_file.flush();
        }
    }
};

SimpleLogger logger("server.log");

// --- PERSISTENT CSV WRITER ---
class CsvWriter {
    std::mutex csv_mutex;
    std::ofstream csv_file;
public:
    CsvWriter(const std::string& filename) {
        csv_file.open(filename, std::ios::app);
        if (!csv_file.is_open()) logger.log(SimpleLogger::ERROR_LOG, "Could not open CSV file!");
    }
    void write(int64_t ts, int dev_id, float cpu, int fails) {
        std::lock_guard<std::mutex> lock(csv_mutex);
        if (csv_file.is_open()) {
            csv_file << ts << "," << dev_id << "," << std::fixed << std::setprecision(1) << cpu << "," << fails << "\n";
            csv_file.flush();
        }
    }
};

CsvWriter csv_writer("s_log.csv");

// --- STATE MANAGEMENT ---
struct DeviceState {
    std::mutex device_mutex;
    RawTelemetry last_report = {};
    bool has_history = false;
    int failed_login_count = 0;
};

std::mutex registry_mutex;
std::map<int, std::shared_ptr<DeviceState>> device_registry;

// --- THREAD POOL ---
class ThreadPool {
    std::vector<std::thread> workers;
    std::queue<std::function<void()>> tasks;
    std::mutex queue_mutex;
    std::condition_variable condition;
    bool stop;
public:
    ThreadPool(size_t threads) : stop(false) {
        for (size_t i = 0; i < threads; ++i) {
            workers.emplace_back([this] {
                while (true) {
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lock(this->queue_mutex);
                        this->condition.wait(lock, [this] { return this->stop || !this->tasks.empty(); });
                        if (this->stop && this->tasks.empty()) return;
                        task = std::move(this->tasks.front());
                        this->tasks.pop();
                    }
                    task();
                }
                });
        }
    }
    template<class F>
    void enqueue(F&& f) {
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            tasks.emplace(std::forward<F>(f));
        }
        condition.notify_one();
    }
    ~ThreadPool() {
        { std::unique_lock<std::mutex> lock(queue_mutex); stop = true; }
        condition.notify_all();
        for (std::thread& worker : workers) worker.join();
    }
};

// --- LOG PARSING ---
int count_failed_logins(const std::string& raw_logs) {
    if (raw_logs.empty()) return 0;
    int count = 0;
    std::string s = raw_logs;
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    const char* sigs[] = { "failed password", "authentication failure", "audit failure", "4625" };
    for (const char* sig : sigs) {
        size_t pos = 0;
        while ((pos = s.find(sig, pos)) != std::string::npos) { count++; pos += strlen(sig); }
    }
    return count;
}

// --- NETWORK HELPER ---
bool recv_exact_ssl(SSL* ssl, char* buf, int len) {
    int total = 0;
    while (total < len) {
        int b = SSL_read(ssl, buf + total, len - total);
        if (b <= 0) return false;
        total += b;
    }
    return true;
}

// --- OPENSSL HELPERS ---
void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

SSL_CTX* create_server_context(const std::string& ca_path, const std::string& cert_path, const std::string& key_path) {
    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        logger.log(SimpleLogger::ERROR_LOG, "Unable to create SSL context");
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_certificate_file(ctx, cert_path.c_str(), SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, key_path.c_str(), SSL_FILETYPE_PEM) <= 0) {
        logger.log(SimpleLogger::ERROR_LOG, "Failed to load server certificate or key.");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_load_verify_locations(ctx, ca_path.c_str(), NULL) <= 0) {
        logger.log(SimpleLogger::ERROR_LOG, "Failed to load CA certificate.");
        exit(EXIT_FAILURE);
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    return ctx;
}

// --- PROCESSING LOGIC ---
void process_report(RawTelemetry& current) {
    current.device_id = ntohl(current.device_id);
    current.timestamp_ms = ntohll_custom(current.timestamp_ms);
    current.cpu_idle_ticks = ntohll_custom(current.cpu_idle_ticks);
    current.cpu_kernel_ticks = ntohll_custom(current.cpu_kernel_ticks);
    current.cpu_user_ticks = ntohll_custom(current.cpu_user_ticks);

    std::shared_ptr<DeviceState> state;
    {
        std::lock_guard<std::mutex> lock(registry_mutex);
        if (device_registry.find(current.device_id) == device_registry.end()) {
            device_registry[current.device_id] = std::make_shared<DeviceState>();
            logger.log(SimpleLogger::INFO, "New Device Registered: " + std::to_string(current.device_id));
        }
        state = device_registry[current.device_id];
    }

    {
        std::lock_guard<std::mutex> dev_lock(state->device_mutex);
        if (state->has_history && current.timestamp_ms <= state->last_report.timestamp_ms) return;

        int new_fails = count_failed_logins(current.raw_log_chunk);
        state->failed_login_count += new_fails;

        if (!state->has_history) {
            state->last_report = current;
            state->has_history = true;
            logger.log(SimpleLogger::INFO, "Device " + std::to_string(current.device_id) + " baseline established.");
            return;
        }

        const RawTelemetry& last = state->last_report;
        uint64_t prev_total = last.cpu_user_ticks + last.cpu_kernel_ticks + last.cpu_idle_ticks;
        uint64_t curr_total = current.cpu_user_ticks + current.cpu_kernel_ticks + current.cpu_idle_ticks;
        uint64_t total_delta = curr_total - prev_total;
        uint64_t idle_delta = current.cpu_idle_ticks - last.cpu_idle_ticks;

        float cpu_usage = (total_delta > 0) ? 100.0f * (1.0f - ((float)idle_delta / (float)total_delta)) : 0.0f;
        state->last_report = current;

        csv_writer.write(current.timestamp_ms, current.device_id, cpu_usage, new_fails);

        std::stringstream ss;
        ss << "Dev: " << current.device_id << " | CPU: " << std::fixed << std::setprecision(1) << cpu_usage
            << "% | Fails: " << new_fails << " | IP: " << current.machine_ip;
        logger.log(SimpleLogger::INFO, ss.str());
    }
}

// --- CLIENT HANDLER ---
void handle_client_ssl(SSL* ssl, SOCKET sock) {
    PacketHeader h;
    std::vector<char> rx_buffer;

    if (SSL_accept(ssl) <= 0) {
        logger.log(SimpleLogger::WARN, "TLS handshake failed (Mutual Auth required).");
    }
    else {
        logger.log(SimpleLogger::INFO, "TLS session established with verified client.");
        while (g_running) {
            if (!recv_exact_ssl(ssl, (char*)&h, sizeof(h))) break;

            uint32_t payload_len = ntohl(h.payload_len);
            uint32_t magic = ntohl(h.magic);

            if (magic != PROTOCOL_MAGIC || payload_len != sizeof(RawTelemetry)) {
                logger.log(SimpleLogger::WARN, "Invalid magic or payload size mismatch.");
                break;
            }

            rx_buffer.assign(payload_len, 0);
            if (!recv_exact_ssl(ssl, rx_buffer.data(), payload_len)) break;

            uint32_t received_checksum = ntohl(h.checksum);
            uint32_t computed_crc = calculate_crc32(reinterpret_cast<const uint8_t*>(rx_buffer.data()), payload_len);
            if (computed_crc != received_checksum) {
                logger.log(SimpleLogger::WARN, "CRC mismatch. Dropping packet.");
                continue;
            }

            RawTelemetry* r = reinterpret_cast<RawTelemetry*>(rx_buffer.data());
            process_report(*r);
        }
    }
    SSL_shutdown(ssl);
    SSL_free(ssl);
    closesocket(sock);
}

// --- MAIN ---
int main() {
    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

#ifdef _WIN32
    WSADATA w;
    if (WSAStartup(MAKEWORD(2, 2), &w) != 0) return 1;
#endif

    // 1. Load Configuration
    AppConfig conf = load_config("server.conf");
    int port = conf.get_int("port", 65432);

    // 2. Initialize Security
    init_openssl();
    SSL_CTX* ctx = create_server_context(
        conf.get("ca_path", "ca.crt"),
        conf.get("server_crt", "server.crt"),
        conf.get("server_key", "server.key")
    );

    // 3. Network Setup
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) {
        logger.log(SimpleLogger::ERROR_LOG, "Socket creation failed.");
        return 1;
    }

#ifdef _WIN32
    DWORD timeout = 1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
#else
    struct timeval tv;
    tv.tv_sec = 1; tv.tv_usec = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
#endif

    sockaddr_in a = { AF_INET, htons(port) };
    a.sin_addr.s_addr = INADDR_ANY;

    if (bind(s, (sockaddr*)&a, sizeof(a)) < 0) {
        logger.log(SimpleLogger::ERROR_LOG, "Bind failed. Port " + std::to_string(port) + " might be in use.");
        return 1;
    }

    listen(s, 10);
    logger.log(SimpleLogger::INFO, "Secure mTLS Server started on Port " + std::to_string(port));

    // 4. Execution Loop
    {
        ThreadPool pool(4);
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
        logger.log(SimpleLogger::INFO, "Shutdown signal received. Stopping thread pool...");
    }

    // 5. Cleanup
    logger.log(SimpleLogger::INFO, "Server exiting gracefully.");
    closesocket(s);
    SSL_CTX_free(ctx);

#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}