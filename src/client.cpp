#define _CRT_SECURE_NO_WARNINGS 

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <cstring>
#include <sstream>
#include <mutex>
#include <iomanip>
#include <algorithm>
#include <csignal>  
#include <atomic>   

// --- OPENSSL INCLUDES ---
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "client_protocol.h" 

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h> 
#include <winevt.h> 
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wevtapi.lib") 
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")
#ifndef EvtFormatMessageEventString
#define EvtFormatMessageEventString 1
#endif
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/sysinfo.h> 
#include <sys/statvfs.h>
#include <ifaddrs.h> 
#include <net/if.h>
#include <pwd.h>
#define INVALID_SOCKET -1
#define closesocket close
typedef int SOCKET;
#endif

// --- GLOBAL CONTROL ---
std::atomic<bool> g_running(true);

void handle_signal(int sig) {
    g_running = false;
}

// --- NETWORK ORDER HELPERS ---
inline uint64_t htonll_custom(uint64_t val) {
    static const int num = 42;
    if (*(const char*)&num == 42) { // Little Endian
        return (((uint64_t)htonl((uint32_t)val)) << 32) | htonl((uint32_t)(val >> 32));
    }
    return val;
}

// --- SIMPLE LOGGER ---
class SimpleLogger {
    std::mutex log_mutex;
    std::ofstream log_file;
    bool to_file;
public:
    enum Level { INFO, WARN, ERROR_LOG, DEBUG };
    SimpleLogger(const std::string& filename = "") {
        if (!filename.empty()) {
            log_file.open(filename, std::ios::app);
            to_file = log_file.is_open();
        }
        else { to_file = false; }
    }
    void log(Level level, const std::string& msg) {
        std::lock_guard<std::mutex> lock(log_mutex);
        auto now = std::chrono::system_clock::now();
        std::time_t now_c = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&now_c), "[%Y-%m-%d %H:%M:%S] ");
        const char* lvlStr = (level == WARN) ? "[WARN] " : (level == ERROR_LOG) ? "[ERROR] " : (level == DEBUG) ? "[DEBUG] " : "[INFO] ";
        std::string full_msg = ss.str() + lvlStr + msg;
        std::cout << full_msg << "\n";
        if (to_file) { log_file << full_msg << "\n"; log_file.flush(); }
    }
};

SimpleLogger logger("client.log");
std::mutex scrape_mutex;

// --- OPENSSL INITIALIZATION ---
void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

// --- UPDATED CONTEXT CREATION ---
SSL_CTX* create_client_context(const std::string& ca_path, const std::string& cert_path, const std::string& key_path) {
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        logger.log(SimpleLogger::ERROR_LOG, "Unable to create SSL context");
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_load_verify_locations(ctx, ca_path.c_str(), NULL) <= 0) {
        logger.log(SimpleLogger::WARN, "Failed to load CA: " + ca_path);
    }
    if (SSL_CTX_use_certificate_file(ctx, cert_path.c_str(), SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, key_path.c_str(), SSL_FILETYPE_PEM) <= 0) {
        logger.log(SimpleLogger::ERROR_LOG, "Failed to load client mTLS certs from " + cert_path);
        exit(EXIT_FAILURE);
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    return ctx;
}

// --- SYSTEM HELPERS ---
bool is_elevated() {
#ifdef _WIN32
    BOOL fRet = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION Elevation;
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
            fRet = Elevation.TokenIsElevated;
        }
    }
    if (hToken) CloseHandle(hToken);
    return fRet;
#else
    return geteuid() == 0;
#endif
}

void get_primary_ip(char* buffer, size_t size) {
    safe_strncpy(buffer, "127.0.0.1", size);
#ifdef _WIN32
    ULONG outBufLen = 15000;
    PIP_ADAPTER_ADDRESSES pAddresses = (PIP_ADAPTER_ADDRESSES)malloc(outBufLen);
    if (!pAddresses) return;
    if (GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, pAddresses, &outBufLen) == NO_ERROR) {
        PIP_ADAPTER_ADDRESSES pCurr = pAddresses;
        while (pCurr) {
            if (pCurr->OperStatus == IfOperStatusUp && pCurr->IfType != IF_TYPE_SOFTWARE_LOOPBACK) {
                PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pCurr->FirstUnicastAddress;
                if (pUnicast) {
                    sockaddr_in* sa_in = (sockaddr_in*)pUnicast->Address.lpSockaddr;
                    inet_ntop(AF_INET, &(sa_in->sin_addr), buffer, (socklen_t)size);
                    break;
                }
            }
            pCurr = pCurr->Next;
        }
    }
    free(pAddresses);
#else
    struct ifaddrs* ifaddr, * ifa;
    if (getifaddrs(&ifaddr) == -1) return;
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
            if (!(ifa->ifa_flags & IFF_LOOPBACK) && (ifa->ifa_flags & IFF_RUNNING)) {
                struct sockaddr_in* sa_in = (struct sockaddr_in*)ifa->ifa_addr;
                inet_ntop(AF_INET, &(sa_in->sin_addr), buffer, size);
                break;
            }
        }
    }
    freeifaddrs(ifaddr);
#endif
}

// --- METRIC GATHERING ---
void get_machine_info(RawTelemetry& r) {
    char hostname[64];
    if (gethostname(hostname, sizeof(hostname)) == 0) safe_strncpy(r.machine_name, hostname, sizeof(r.machine_name));
    get_primary_ip(r.machine_ip, sizeof(r.machine_ip));
#ifdef _WIN32
    DWORD len = 32; GetUserNameA(r.os_user, &len);
#else
    struct passwd* pw = getpwuid(geteuid());
    if (pw) safe_strncpy(r.os_user, pw->pw_name, sizeof(r.os_user));
#endif
}

void get_raw_cpu(RawTelemetry& r) {
#ifdef _WIN32
    FILETIME idle, kernel, user;
    if (GetSystemTimes(&idle, &kernel, &user)) {
        auto to_u64 = [](FILETIME f) { return ((uint64_t)f.dwHighDateTime << 32) | f.dwLowDateTime; };
        r.cpu_idle_ticks = to_u64(idle);
        r.cpu_kernel_ticks = to_u64(kernel);
        r.cpu_user_ticks = to_u64(user);
    }
#else
    std::ifstream f("/proc/stat");
    std::string lbl; uint64_t u, n, s, i, iw, irq, sirq, st;
    if (f >> lbl >> u >> n >> s >> i >> iw >> irq >> sirq >> st) {
        r.cpu_user_ticks = u + n;
        r.cpu_kernel_ticks = s + irq + sirq;
        r.cpu_idle_ticks = i + iw;
    }
#endif
}

void get_raw_memory(RawTelemetry& r) {
#ifdef _WIN32
    MEMORYSTATUSEX m; m.dwLength = sizeof(m);
    GlobalMemoryStatusEx(&m);
    r.ram_total_bytes = m.ullTotalPhys;
    r.ram_avail_bytes = m.ullAvailPhys;
#else
    std::ifstream f("/proc/meminfo");
    std::string token; uint64_t val; std::string unit;
    while (f >> token >> val >> unit) {
        if (token == "MemTotal:") r.ram_total_bytes = val * 1024;
        else if (token == "MemAvailable:") r.ram_avail_bytes = val * 1024;
    }
#endif
}

void get_raw_disk(RawTelemetry& r) {
#ifdef _WIN32
    ULARGE_INTEGER f, t, tf;
    if (GetDiskFreeSpaceExA("C:\\", &f, &t, &tf)) {
        r.disk_total_bytes = t.QuadPart;
        r.disk_free_bytes = tf.QuadPart;
    }
#else
    struct statvfs s;
    if (statvfs("/", &s) == 0) {
        r.disk_total_bytes = (uint64_t)s.f_blocks * s.f_frsize;
        r.disk_free_bytes = (uint64_t)s.f_bavail * s.f_frsize;
    }
#endif
}

void get_raw_network(RawTelemetry& r) {
#ifdef _WIN32
    PMIB_IFTABLE t; DWORD sz = 0;
    GetIfTable(NULL, &sz, 0);
    t = (PMIB_IFTABLE)malloc(sz);
    if (t && GetIfTable(t, &sz, 0) == NO_ERROR) {
        r.net_bytes_in = 0; r.net_bytes_out = 0;
        for (DWORD i = 0; i < t->dwNumEntries; i++) {
            if (t->table[i].dwType != MIB_IF_TYPE_LOOPBACK) {
                r.net_bytes_in += t->table[i].dwInOctets;
                r.net_bytes_out += t->table[i].dwOutOctets;
            }
        }
    }
    if (t) free(t);
#else
    std::ifstream f("/proc/net/dev");
    std::string line;
    r.net_bytes_in = 0; r.net_bytes_out = 0;
    std::getline(f, line); std::getline(f, line);
    while (std::getline(f, line)) {
        if (line.find("lo:") != std::string::npos) continue;
        size_t colon = line.find(':');
        if (colon != std::string::npos) {
            std::istringstream iss(line.substr(colon + 1));
            uint64_t rx, tx, d;
            iss >> rx >> d >> d >> d >> d >> d >> d >> d >> tx;
            r.net_bytes_in += rx; r.net_bytes_out += tx;
        }
    }
#endif
}

void scrape_logs(RawTelemetry& r) {
    std::lock_guard<std::mutex> lock(scrape_mutex);
    std::memset(r.raw_log_chunk, 0, sizeof(r.raw_log_chunk));
#ifdef _WIN32
    EVT_HANDLE hResults = EvtQuery(NULL, L"System", NULL, EvtQueryChannelPath | EvtQueryReverseDirection);
    if (hResults) {
        EVT_HANDLE hEvent = NULL; DWORD dwRet = 0;
        if (EvtNext(hResults, 1, &hEvent, INFINITE, 0, &dwRet)) {
            DWORD dwUsed = 0, dwProp = 0;
            EvtRender(NULL, hEvent, EvtRenderEventXml, 0, NULL, &dwUsed, &dwProp);
            if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                std::vector<WCHAR> buf(dwUsed / sizeof(WCHAR));
                if (EvtRender(NULL, hEvent, EvtRenderEventXml, dwUsed, buf.data(), &dwUsed, &dwProp)) {
                    WideCharToMultiByte(CP_UTF8, 0, buf.data(), -1, r.raw_log_chunk, sizeof(r.raw_log_chunk) - 1, NULL, NULL);
                }
            }
            EvtClose(hEvent);
        }
        EvtClose(hResults);
    }
#else
    const char* paths[] = { "/var/log/syslog", "/var/log/messages" };
    for (const char* path : paths) {
        std::ifstream f(path, std::ios::binary | std::ios::ate);
        if (f.is_open()) {
            std::streamsize size = f.tellg();
            std::streamsize read_sz = std::min((std::streamsize)sizeof(r.raw_log_chunk) - 1, size);
            f.seekg(-read_sz, std::ios::end);
            f.read(r.raw_log_chunk, read_sz);
            break;
        }
    }
#endif
}

// --- UPDATED MAIN ---
int main(int argc, char* argv[]) {
    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    // 1. Load configuration from file
    AppConfig conf = load_config(CONFIG_FILE_NAME);

    std::string server_ip = conf.get("server_ip", "127.0.0.1");
    int port = conf.get_int("port", DEFAULT_PORT);
    int my_id = conf.get_int("device_id", 7001);

    if (!is_elevated()) logger.log(SimpleLogger::WARN, "Not running as Admin/Root. Log scraping may fail.");

    // 2. Security Setup
    init_openssl();
    SSL_CTX* ctx = create_client_context(
        conf.get("ca_path", "ca.crt"),
        conf.get("client_crt", "client.crt"),
        conf.get("client_key", "client.key")
    );

#ifdef _WIN32
    WSADATA w;
    if (WSAStartup(MAKEWORD(2, 2), &w) != 0) return 1;
#endif

    // 3. Primary Connection Loop
    while (g_running) {
        SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in a = { AF_INET, htons(port) };
        if (inet_pton(AF_INET, server_ip.c_str(), &a.sin_addr) <= 0) {
            logger.log(SimpleLogger::ERROR_LOG, "Invalid Server IP: " + server_ip);
            break;
        }

        logger.log(SimpleLogger::INFO, "Connecting to " + server_ip + ":" + std::to_string(port));
        if (connect(s, (sockaddr*)&a, sizeof(a)) < 0) {
            logger.log(SimpleLogger::WARN, "TCP Connection failed. Retrying...");
            closesocket(s);
            std::this_thread::sleep_for(std::chrono::milliseconds(CLIENT_SLEEP_MS));
            continue;
        }

        SSL* ssl = SSL_new(ctx);
        SSL_set1_host(ssl, server_ip.c_str());
        SSL_set_fd(ssl, (int)s);

        if (SSL_connect(ssl) <= 0) {
            logger.log(SimpleLogger::ERROR_LOG, "TLS Handshake failed (check certs/time).");
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            closesocket(s);
            std::this_thread::sleep_for(std::chrono::milliseconds(CLIENT_SLEEP_MS));
            continue;
        }
        logger.log(SimpleLogger::INFO, "TLS Established: " + std::string(SSL_get_cipher(ssl)));

        // 4. Telemetry Transmission Loop
        while (g_running) {
            RawTelemetry r;
            std::memset(&r, 0, sizeof(r));
            r.struct_version = 1;
            r.device_id = my_id;
            auto now = std::chrono::system_clock::now();
            r.timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();

            get_machine_info(r);
            get_raw_cpu(r);
            get_raw_memory(r);
            get_raw_disk(r);
            get_raw_network(r);
            scrape_logs(r);

            // Network Order Conversion
            RawTelemetry r_net = r;
            r_net.struct_version = htons(r.struct_version);
            r_net.device_id = htonl(r.device_id);
            r_net.timestamp_ms = htonll_custom(r.timestamp_ms);
            r_net.cpu_user_ticks = htonll_custom(r.cpu_user_ticks);
            r_net.cpu_kernel_ticks = htonll_custom(r.cpu_kernel_ticks);
            r_net.cpu_idle_ticks = htonll_custom(r.cpu_idle_ticks);
            r_net.ram_total_bytes = htonll_custom(r.ram_total_bytes);
            r_net.ram_avail_bytes = htonll_custom(r.ram_avail_bytes);
            r_net.disk_total_bytes = htonll_custom(r.disk_total_bytes);
            r_net.disk_free_bytes = htonll_custom(r.disk_free_bytes);
            r_net.net_bytes_in = htonll_custom(r.net_bytes_in);
            r_net.net_bytes_out = htonll_custom(r.net_bytes_out);

            uint32_t payload_crc = calculate_crc32(reinterpret_cast<const uint8_t*>(&r_net), sizeof(r_net));

            PacketHeader h;
            h.magic = htonl(PROTOCOL_MAGIC);
            h.version = htons(1);
            h.payload_len = htonl(sizeof(r_net));
            h.checksum = htonl(payload_crc);

            if (SSL_write(ssl, (char*)&h, sizeof(h)) <= 0) break;
            if (SSL_write(ssl, (char*)&r_net, sizeof(r_net)) <= 0) break;

            std::this_thread::sleep_for(std::chrono::milliseconds(CLIENT_SLEEP_MS));
        }

        logger.log(SimpleLogger::INFO, "Closing connection.");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        closesocket(s);
    }

    logger.log(SimpleLogger::INFO, "Graceful exit.");
    SSL_CTX_free(ctx);
    cleanup_openssl();
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
