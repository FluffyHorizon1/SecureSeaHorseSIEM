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

// --- Phase 1 + 3 Headers ---
#include "client_protocol.h" 
#include "crypto_utils.h"    // Phase 3: HMAC, CRL, OCSP, heartbeat types

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

// =============================================================================
// GLOBAL CONTROL
// =============================================================================
std::atomic<bool> g_running(true);

void handle_signal(int sig) {
    g_running = false;
}

// --- NETWORK ORDER HELPERS ---
inline uint64_t htonll_custom(uint64_t val) {
    static const int num = 42;
    if (*(const char*)&num == 42) {
        return (((uint64_t)htonl((uint32_t)val)) << 32) | htonl((uint32_t)(val >> 32));
    }
    return val;
}

// =============================================================================
// GLOBAL STATE
// =============================================================================
static std::unique_ptr<AsyncLogger> logger;
std::mutex scrape_mutex;

// Phase 3: Heartbeat state
static std::atomic<uint32_t>  heartbeat_seq{0};
static std::atomic<bool>      pong_received{true};   // Start true = healthy
static std::atomic<int64_t>   last_pong_time_ms{0};

// =============================================================================
// OPENSSL INITIALIZATION — Phase 3 Upgraded
// =============================================================================
void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

// Phase 3: OCSP must-staple flag (stored globally for callback)
static bool g_ocsp_must_staple = false;

SSL_CTX* create_client_context(const AppConfig& conf) {
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        logger->log(AsyncLogger::ERROR_LOG, "Unable to create SSL context");
        exit(EXIT_FAILURE);
    }

    std::string ca_path   = conf.get("ca_path", "ca.crt");
    std::string cert_path = conf.get("client_crt", "client.crt");
    std::string key_path  = conf.get("client_key", "client.key");

    if (SSL_CTX_load_verify_locations(ctx, ca_path.c_str(), NULL) <= 0) {
        logger->log(AsyncLogger::WARN, "Failed to load CA: " + ca_path);
    }
    if (SSL_CTX_use_certificate_file(ctx, cert_path.c_str(), SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, key_path.c_str(), SSL_FILETYPE_PEM) <= 0) {
        logger->log(AsyncLogger::ERROR_LOG, "Failed to load client mTLS certs from " + cert_path);
        exit(EXIT_FAILURE);
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    // =========================================================================
    // PHASE 3 [CRL]: Load Certificate Revocation List
    // =========================================================================
    std::string crl_path = conf.get("crl_path", "");
    if (!crl_path.empty()) {
        if (load_crl(ctx, crl_path)) {
            logger->log(AsyncLogger::INFO, "CRL loaded: " + crl_path);
        } else {
            logger->log(AsyncLogger::WARN, "CRL load failed: " + crl_path + " — continuing without CRL.");
        }
    }

    // =========================================================================
    // PHASE 3 [OCSP]: Request stapled OCSP response during handshake
    // =========================================================================
    bool ocsp_enabled = conf.get_bool("ocsp_stapling", true);
    g_ocsp_must_staple = conf.get_bool("ocsp_must_staple", false);

    if (ocsp_enabled) {
        enable_ocsp_stapling_client(ctx, &g_ocsp_must_staple);
        logger->log(AsyncLogger::INFO, "OCSP stapling: enabled"
            + std::string(g_ocsp_must_staple ? " (must-staple)" : " (soft-fail)"));
    }

    return ctx;
}

// =============================================================================
// SYSTEM HELPERS (unchanged from Phase 1)
// =============================================================================
bool is_elevated() {
#ifdef _WIN32
    BOOL fRet = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION Elevation;
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize))
            fRet = Elevation.TokenIsElevated;
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

// =============================================================================
// METRIC GATHERING (unchanged from v1.0.1)
// =============================================================================
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
    ULARGE_INTEGER freeBytes, totalBytes;
    if (GetDiskFreeSpaceExA("C:\\", NULL, &totalBytes, &freeBytes)) {
        r.disk_total_bytes = totalBytes.QuadPart;
        r.disk_free_bytes = freeBytes.QuadPart;
    }
#else
    struct statvfs st;
    if (statvfs("/", &st) == 0) {
        r.disk_total_bytes = (uint64_t)st.f_frsize * st.f_blocks;
        r.disk_free_bytes = (uint64_t)st.f_frsize * st.f_bavail;
    }
#endif
}

void get_raw_network(RawTelemetry& r) {
#ifdef _WIN32
    MIB_IF_ROW2 row;
    SecureZeroMemory(&row, sizeof(row));
    row.InterfaceIndex = 0;
    PMIB_IF_TABLE2 ifTable;
    if (GetIfTable2(&ifTable) == NO_ERROR) {
        for (ULONG i = 0; i < ifTable->NumEntries; i++) {
            if (ifTable->Table[i].InterfaceAndOperStatusFlags.HardwareInterface &&
                ifTable->Table[i].OperStatus == IfOperStatusUp) {
                r.net_bytes_in += ifTable->Table[i].InOctets;
                r.net_bytes_out += ifTable->Table[i].OutOctets;
            }
        }
        FreeMibTable(ifTable);
    }
#else
    std::ifstream f("/proc/net/dev");
    std::string line;
    std::getline(f, line); std::getline(f, line);
    while (std::getline(f, line)) {
        if (line.find("lo:") != std::string::npos) continue;
        size_t colon = line.find(':');
        if (colon != std::string::npos) {
            std::istringstream ss(line.substr(colon + 1));
            uint64_t rx, tx, dummy;
            ss >> rx;
            for (int i = 0; i < 7; i++) ss >> dummy;
            ss >> tx;
            r.net_bytes_in += rx;
            r.net_bytes_out += tx;
        }
    }
#endif
}

void scrape_logs(RawTelemetry& r) {
    std::lock_guard<std::mutex> lock(scrape_mutex);
    std::memset(r.raw_log_chunk, 0, sizeof(r.raw_log_chunk));
#ifdef _WIN32
    const wchar_t* query = L"Event/System[Level<=3]";
    EVT_HANDLE hResults = EvtQuery(NULL, L"Security", query, EvtQueryChannelPath | EvtQueryReverseDirection);
    if (!hResults) hResults = EvtQuery(NULL, L"System", query, EvtQueryChannelPath | EvtQueryReverseDirection);
    if (hResults) {
        EVT_HANDLE hEvent = NULL;
        DWORD dwReturned = 0;
        if (EvtNext(hResults, 1, &hEvent, 1000, 0, &dwReturned)) {
            DWORD bufUsed = 0, propCount = 0;
            EvtRender(NULL, hEvent, EvtRenderEventXml, 0, NULL, &bufUsed, &propCount);
            if (bufUsed > 0) {
                std::vector<wchar_t> buf(bufUsed / sizeof(wchar_t) + 1);
                if (EvtRender(NULL, hEvent, EvtRenderEventXml, bufUsed, buf.data(), &bufUsed, &propCount)) {
                    std::wstring ws(buf.data());
                    std::string narrow(ws.begin(), ws.end());
                    safe_strncpy(r.raw_log_chunk, narrow.c_str(), sizeof(r.raw_log_chunk));
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

// =============================================================================
// PHASE 3: NETWORK HELPERS (SSL read/write with v2 headers)
// =============================================================================
bool send_exact_ssl(SSL* ssl, const void* buf, int len) {
    int total = 0;
    while (total < len) {
        int b = SSL_write(ssl, (const char*)buf + total, len - total);
        if (b <= 0) return false;
        total += b;
    }
    return true;
}

bool recv_exact_ssl(SSL* ssl, void* buf, int len) {
    int total = 0;
    while (total < len) {
        int b = SSL_read(ssl, (char*)buf + total, len - total);
        if (b <= 0) return false;
        total += b;
    }
    return true;
}

// =============================================================================
// PHASE 3: SEND TELEMETRY (v2 with HMAC, or v1 fallback)
// =============================================================================
bool send_telemetry_v2(SSL* ssl, const RawTelemetry& r_net, const uint8_t* hmac_key) {
    PacketHeaderV2 hdr = build_v2_header(
        MSG_TELEMETRY,
        sizeof(r_net),
        reinterpret_cast<const uint8_t*>(&r_net),
        hmac_key
    );

    if (!send_exact_ssl(ssl, &hdr, sizeof(hdr))) return false;
    if (!send_exact_ssl(ssl, &r_net, sizeof(r_net))) return false;
    return true;
}

bool send_telemetry_v1(SSL* ssl, const RawTelemetry& r_net) {
    uint32_t payload_crc = calculate_crc32(
        reinterpret_cast<const uint8_t*>(&r_net), sizeof(r_net));

    PacketHeader h;
    h.magic       = htonl(PROTOCOL_MAGIC);
    h.version     = htons(1);
    h.payload_len = htonl(sizeof(r_net));
    h.checksum    = htonl(payload_crc);

    if (!send_exact_ssl(ssl, &h, sizeof(h))) return false;
    if (!send_exact_ssl(ssl, &r_net, sizeof(r_net))) return false;
    return true;
}

// =============================================================================
// PHASE 3: SEND HEARTBEAT PING
// =============================================================================
bool send_heartbeat_ping(SSL* ssl, int32_t device_id, const uint8_t* hmac_key) {
    HeartbeatPayload ping;
    auto now = std::chrono::system_clock::now();
    ping.timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    ping.device_id = htonl(device_id);
    ping.seq       = htonl(heartbeat_seq.fetch_add(1));

    // Network-order the timestamp
    ping.timestamp_ms = static_cast<int64_t>(htonll_custom(static_cast<uint64_t>(ping.timestamp_ms)));

    PacketHeaderV2 hdr = build_v2_header(
        MSG_HEARTBEAT_PING,
        sizeof(ping),
        reinterpret_cast<const uint8_t*>(&ping),
        hmac_key
    );

    if (!send_exact_ssl(ssl, &hdr, sizeof(hdr))) return false;
    if (!send_exact_ssl(ssl, &ping, sizeof(ping))) return false;
    return true;
}

// =============================================================================
// PHASE 3: HEARTBEAT RECEIVER THREAD
// =============================================================================
// Runs alongside the main telemetry loop. Reads incoming pong responses
// and updates the last_pong_time_ms timestamp.
// =============================================================================
void heartbeat_receiver_thread(SSL* ssl) {
    while (g_running) {
        // Non-blocking check: set a read timeout via SSL_set_mode
        // We use a simple approach: try to read a v2 header
        PacketHeaderV2 hdr;
        if (!recv_exact_ssl(ssl, &hdr, sizeof(hdr))) {
            break;  // Connection lost
        }

        uint16_t version  = ntohs(hdr.version);
        uint8_t  msg_type = hdr.msg_type;
        uint32_t plen     = ntohl(hdr.payload_len);

        if (version == 2 && msg_type == MSG_HEARTBEAT_PONG) {
            // Read and discard the pong payload
            if (plen > 0 && plen <= 1024) {
                std::vector<char> buf(plen);
                recv_exact_ssl(ssl, buf.data(), plen);
            }

            pong_received = true;
            auto now = std::chrono::system_clock::now();
            last_pong_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                now.time_since_epoch()).count();

            logger->log(AsyncLogger::DEBUG, "Heartbeat PONG received");
        }
        else {
            // Unexpected message from server — skip payload
            if (plen > 0 && plen < 65536) {
                std::vector<char> buf(plen);
                recv_exact_ssl(ssl, buf.data(), plen);
            }
        }
    }
}

// =============================================================================
// MAIN — Phase 3 Upgraded
// =============================================================================
int main(int argc, char* argv[]) {
    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    // -------------------------------------------------------------------------
    // PHASE 1 [CLI]: Parse command-line arguments
    // -------------------------------------------------------------------------
    CliArgs cli = parse_client_cli(argc, argv);

    if (cli.show_help) {
        print_client_usage(argv[0]);
        return 0;
    }
    if (cli.show_version) {
        std::cout << "SecureSeaHorse Client v1.3.0 (Phase 3)\n";
        return 0;
    }

    // -------------------------------------------------------------------------
    // 1. Load configuration from file, then apply CLI overrides
    // -------------------------------------------------------------------------
    AppConfig conf = load_config(cli.config_path);
    cli.apply_overrides(conf);

    std::string server_ip = conf.get("server_ip", "127.0.0.1");
    int port              = conf.get_int("port", DEFAULT_PORT);
    int my_id             = conf.get_int("device_id", 7001);

    // Phase 3 config
    bool   hmac_enabled       = conf.get_bool("hmac_enabled", true);
    int    heartbeat_interval = conf.get_int("heartbeat_interval_s", 15);
    int    heartbeat_timeout  = conf.get_int("heartbeat_timeout_s", 45);
    std::string cert_pin      = conf.get("cert_pin_sha256", "");

    // -------------------------------------------------------------------------
    // PHASE 1 [ASYNC LOGGER]: Initialize
    // -------------------------------------------------------------------------
    {
        std::string log_path = conf.get("log_file", "client.log");
        size_t max_log_size  = conf.get_size("log_max_bytes", 10 * 1024 * 1024);
        int max_log_files    = conf.get_int("log_max_files", 5);
        logger = std::make_unique<AsyncLogger>(log_path, max_log_size, max_log_files, true);
    }

    logger->log(AsyncLogger::INFO, "=== SecureSeaHorse Client v1.3.0 (Phase 3) starting ===");
    logger->log(AsyncLogger::INFO, "Config loaded from: " + cli.config_path);
    logger->log(AsyncLogger::INFO, "Target: " + server_ip + ":" + std::to_string(port)
                 + " | Device ID: " + std::to_string(my_id));
    logger->log(AsyncLogger::INFO, "Security: HMAC=" + std::string(hmac_enabled ? "on" : "off")
                 + " Heartbeat=" + std::to_string(heartbeat_interval) + "s/"
                 + std::to_string(heartbeat_timeout) + "s timeout"
                 + (cert_pin.empty() ? "" : " Pin=configured"));

    if (!is_elevated()) logger->log(AsyncLogger::WARN, "Not running as Admin/Root. Log scraping may fail.");

    // -------------------------------------------------------------------------
    // 2. Security Setup (Phase 3: CRL + OCSP integrated)
    // -------------------------------------------------------------------------
    init_openssl();
    SSL_CTX* ctx = create_client_context(conf);

#ifdef _WIN32
    WSADATA w;
    if (WSAStartup(MAKEWORD(2, 2), &w) != 0) return 1;
#endif

    // -------------------------------------------------------------------------
    // PHASE 1 [EXPONENTIAL BACKOFF]
    // -------------------------------------------------------------------------
    ExponentialBackoff backoff(
        conf.get_int("backoff_base_ms", 1000),
        conf.get_int("backoff_max_ms", 60000)
    );

    // -------------------------------------------------------------------------
    // 3. Primary Connection Loop
    // -------------------------------------------------------------------------
    while (g_running) {
        SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in a = { AF_INET, htons(static_cast<uint16_t>(port)) };
        if (inet_pton(AF_INET, server_ip.c_str(), &a.sin_addr) <= 0) {
            logger->log(AsyncLogger::ERROR_LOG, "Invalid Server IP: " + server_ip);
            break;
        }

        logger->log(AsyncLogger::INFO, "Connecting to " + server_ip + ":" + std::to_string(port)
                     + " (attempt " + std::to_string(backoff.attempt_count() + 1) + ")");

        if (connect(s, (sockaddr*)&a, sizeof(a)) < 0) {
            int delay = backoff.next_delay_ms();
            logger->log(AsyncLogger::WARN, "TCP Connection failed. Retrying in "
                         + std::to_string(delay) + "ms");
            closesocket(s);
            auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(delay);
            while (g_running && std::chrono::steady_clock::now() < deadline)
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        SSL* ssl = SSL_new(ctx);
        SSL_set1_host(ssl, server_ip.c_str());
        SSL_set_fd(ssl, (int)s);

        if (SSL_connect(ssl) <= 0) {
            int delay = backoff.next_delay_ms();
            logger->log(AsyncLogger::ERROR_LOG, "TLS Handshake failed. Retrying in "
                         + std::to_string(delay) + "ms");
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            closesocket(s);
            auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(delay);
            while (g_running && std::chrono::steady_clock::now() < deadline)
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        // =====================================================================
        // PHASE 3 [CERT PINNING]: Verify server certificate fingerprint
        // =====================================================================
        if (!cert_pin.empty()) {
            if (!verify_cert_pin(ssl, cert_pin)) {
                logger->log(AsyncLogger::ERROR_LOG,
                    "Certificate pin mismatch! Expected: " + cert_pin + ". Aborting connection.");
                SSL_shutdown(ssl);
                SSL_free(ssl);
                closesocket(s);
                // Don't retry with backoff — this is a hard security failure
                std::this_thread::sleep_for(std::chrono::seconds(5));
                continue;
            }
            logger->log(AsyncLogger::INFO, "Certificate pin verified.");
        }

        // Connection successful — reset backoff
        backoff.reset();
        logger->log(AsyncLogger::INFO, "TLS Established: " + std::string(SSL_get_cipher(ssl)));

        // =====================================================================
        // PHASE 3 [HMAC]: Derive session HMAC key from TLS keying material
        // =====================================================================
        uint8_t hmac_key[HMAC_KEY_LEN] = {0};
        bool hmac_active = false;

        if (hmac_enabled) {
            if (derive_hmac_key(ssl, hmac_key)) {
                hmac_active = true;
                logger->log(AsyncLogger::INFO, "HMAC-SHA256: session key derived (protocol v2).");
            } else {
                logger->log(AsyncLogger::WARN, "HMAC key derivation failed — falling back to CRC32 (v1).");
            }
        }

        // =====================================================================
        // PHASE 3 [HEARTBEAT]: Set socket read timeout for receiver thread
        // =====================================================================
#ifdef _WIN32
        DWORD ssl_timeout = heartbeat_timeout * 1000;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&ssl_timeout, sizeof(ssl_timeout));
#else
        struct timeval tv;
        tv.tv_sec = heartbeat_timeout; tv.tv_usec = 0;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
#endif

        // Launch heartbeat receiver thread
        pong_received = true;
        heartbeat_seq = 0;
        auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        last_pong_time_ms = now_ms;

        std::atomic<bool> session_alive{true};
        std::thread hb_receiver;

        if (hmac_active && heartbeat_interval > 0) {
            hb_receiver = std::thread([ssl, &session_alive]() {
                while (g_running && session_alive) {
                    PacketHeaderV2 hdr;
                    if (!recv_exact_ssl(ssl, &hdr, sizeof(hdr))) {
                        session_alive = false;
                        break;
                    }

                    uint16_t version  = ntohs(hdr.version);
                    uint8_t  msg_type = hdr.msg_type;
                    uint32_t plen     = ntohl(hdr.payload_len);

                    if (version == 2 && msg_type == MSG_HEARTBEAT_PONG && plen <= 1024) {
                        if (plen > 0) {
                            std::vector<char> buf(plen);
                            recv_exact_ssl(ssl, buf.data(), plen);
                        }
                        pong_received = true;
                        auto now = std::chrono::system_clock::now();
                        last_pong_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                            now.time_since_epoch()).count();
                        logger->log(AsyncLogger::DEBUG, "Heartbeat PONG received");
                    } else if (plen > 0 && plen < 65536) {
                        std::vector<char> buf(plen);
                        recv_exact_ssl(ssl, buf.data(), plen);
                    }
                }
            });
        }

        // =====================================================================
        // 4. Telemetry + Heartbeat Transmission Loop
        // =====================================================================
        auto last_heartbeat = std::chrono::steady_clock::now();

        while (g_running && session_alive) {
            // --- Gather telemetry ---
            RawTelemetry r;
            std::memset(&r, 0, sizeof(r));
            r.struct_version = 1;
            r.device_id = my_id;
            auto now = std::chrono::system_clock::now();
            r.timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                now.time_since_epoch()).count();

            get_machine_info(r);
            get_raw_cpu(r);
            get_raw_memory(r);
            get_raw_disk(r);
            get_raw_network(r);
            scrape_logs(r);

            // --- Network Order Conversion ---
            RawTelemetry r_net = r;
            r_net.struct_version   = htons(r.struct_version);
            r_net.device_id        = htonl(r.device_id);
            r_net.timestamp_ms     = htonll_custom(r.timestamp_ms);
            r_net.cpu_user_ticks   = htonll_custom(r.cpu_user_ticks);
            r_net.cpu_kernel_ticks = htonll_custom(r.cpu_kernel_ticks);
            r_net.cpu_idle_ticks   = htonll_custom(r.cpu_idle_ticks);
            r_net.ram_total_bytes  = htonll_custom(r.ram_total_bytes);
            r_net.ram_avail_bytes  = htonll_custom(r.ram_avail_bytes);
            r_net.disk_total_bytes = htonll_custom(r.disk_total_bytes);
            r_net.disk_free_bytes  = htonll_custom(r.disk_free_bytes);
            r_net.net_bytes_in     = htonll_custom(r.net_bytes_in);
            r_net.net_bytes_out    = htonll_custom(r.net_bytes_out);

            // --- Send with appropriate protocol version ---
            bool ok;
            if (hmac_active) {
                ok = send_telemetry_v2(ssl, r_net, hmac_key);
            } else {
                ok = send_telemetry_v1(ssl, r_net);
            }
            if (!ok) break;

            // --- Heartbeat ping (if interval elapsed) ---
            if (hmac_active && heartbeat_interval > 0) {
                auto since_hb = std::chrono::steady_clock::now() - last_heartbeat;
                if (since_hb >= std::chrono::seconds(heartbeat_interval)) {
                    if (!send_heartbeat_ping(ssl, my_id, hmac_key)) break;
                    last_heartbeat = std::chrono::steady_clock::now();
                    logger->log(AsyncLogger::DEBUG, "Heartbeat PING sent (seq="
                                 + std::to_string(heartbeat_seq.load()) + ")");
                }

                // Check for pong timeout
                auto now_tp = std::chrono::system_clock::now();
                int64_t now_epoch = std::chrono::duration_cast<std::chrono::milliseconds>(
                    now_tp.time_since_epoch()).count();
                int64_t last_pong = last_pong_time_ms.load();
                if ((now_epoch - last_pong) > (heartbeat_timeout * 1000)) {
                    logger->log(AsyncLogger::WARN, "Heartbeat timeout — no pong in "
                                 + std::to_string(heartbeat_timeout) + "s. Reconnecting.");
                    break;
                }
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(CLIENT_SLEEP_MS));
        }

        // --- Session teardown ---
        session_alive = false;
        logger->log(AsyncLogger::INFO, "Closing connection. Will reconnect with backoff.");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        closesocket(s);

        // Wait for receiver thread to notice the closed socket
        if (hb_receiver.joinable()) {
            hb_receiver.join();
        }

        // Clear HMAC key from memory
        OPENSSL_cleanse(hmac_key, HMAC_KEY_LEN);

        if (g_running) {
            int delay = backoff.next_delay_ms();
            logger->log(AsyncLogger::INFO, "Reconnecting in " + std::to_string(delay) + "ms...");
            auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(delay);
            while (g_running && std::chrono::steady_clock::now() < deadline)
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    logger->log(AsyncLogger::INFO, "=== Graceful exit ===");
    logger.reset();
    SSL_CTX_free(ctx);
    cleanup_openssl();
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
