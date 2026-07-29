#ifndef REST_SERVER_H
#define REST_SERVER_H

#ifndef NOMINMAX
#define NOMINMAX
#endif

// =============================================================================
// SecureSeaHorse SIEM -- Phase 7: Embedded REST API Server
// =============================================================================
// Provides:
//   - Lightweight HTTP/1.1 server on a configurable port
//   - Bearer token authentication
//   - JSON response builder (no external dependency)
//   - Route registration with method + path matching
//   - Static file serving for embedded dashboard
//   - Thread-per-request model using the existing thread pool pattern
// =============================================================================

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
typedef int socklen_t;
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#define SOCKET int
#define INVALID_SOCKET (-1)
#define closesocket close
#endif

#include <string>
#include <vector>
#include <map>
#include <functional>
#include <sstream>
#include <algorithm>
#include <thread>
#include <atomic>
#include <mutex>
#include <cstring>
#include <cstdint>

// =============================================================================
// HTTP REQUEST
// =============================================================================
struct HttpRequest {
    std::string method;          // GET, POST, PUT, DELETE
    std::string path;            // /api/devices
    std::string query_string;    // device_id=1001&limit=50
    std::string body;            // POST body
    std::map<std::string, std::string> headers;
    std::map<std::string, std::string> query_params;

    std::string get_param(const std::string& key, const std::string& def = "") const {
        auto it = query_params.find(key);
        return (it != query_params.end()) ? it->second : def;
    }

    int get_param_int(const std::string& key, int def = 0) const {
        auto it = query_params.find(key);
        if (it == query_params.end()) return def;
        try { return std::stoi(it->second); } catch (...) { return def; }
    }

    std::string get_header(const std::string& key) const {
        auto it = headers.find(key);
        return (it != headers.end()) ? it->second : "";
    }

    std::string bearer_token() const {
        std::string auth = get_header("authorization");
        if (auth.size() > 7 && auth.substr(0, 7) == "Bearer ") {
            return auth.substr(7);
        }
        return "";
    }
};

// =============================================================================
// HTTP RESPONSE
// =============================================================================
struct HttpResponse {
    int status_code = 200;
    std::string status_text = "OK";
    std::string content_type = "application/json";
    std::string body;
    std::map<std::string, std::string> headers;

    // Convenience builders
    static HttpResponse json(const std::string& json_body, int code = 200) {
        HttpResponse r;
        r.status_code = code;
        r.status_text = status_for(code);
        r.content_type = "application/json";
        r.body = json_body;
        return r;
    }

    static HttpResponse html(const std::string& html_body, int code = 200) {
        HttpResponse r;
        r.status_code = code;
        r.status_text = status_for(code);
        r.content_type = "text/html; charset=utf-8";
        r.body = html_body;
        return r;
    }

    static HttpResponse error(int code, const std::string& message) {
        return json("{\"error\":\"" + json_escape(message) + "\"}", code);
    }

    std::string serialize() const {
        std::ostringstream oss;
        oss << "HTTP/1.1 " << status_code << " " << status_text << "\r\n";
        oss << "Content-Type: " << content_type << "\r\n";
        oss << "Content-Length: " << body.size() << "\r\n";
        oss << "Access-Control-Allow-Origin: *\r\n";
        oss << "Access-Control-Allow-Headers: Authorization, Content-Type\r\n";
        oss << "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n";
        oss << "Connection: close\r\n";
        for (const auto& [k, v] : headers) {
            oss << k << ": " << v << "\r\n";
        }
        oss << "\r\n";
        oss << body;
        return oss.str();
    }

    static std::string json_escape(const std::string& s) {
        std::string out;
        out.reserve(s.size() + 16);
        for (char c : s) {
            switch (c) {
                case '"':  out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\n': out += "\\n";  break;
                case '\r': out += "\\r";  break;
                case '\t': out += "\\t";  break;
                default:   out += c;      break;
            }
        }
        return out;
    }

    static std::string status_for(int code) {
        switch (code) {
            case 200: return "OK";
            case 201: return "Created";
            case 400: return "Bad Request";
            case 401: return "Unauthorized";
            case 403: return "Forbidden";
            case 404: return "Not Found";
            case 405: return "Method Not Allowed";
            case 500: return "Internal Server Error";
            default:  return "Unknown";
        }
    }
};

// =============================================================================
// JSON BUILDER -- Simple helper for constructing JSON without a library
// =============================================================================
class JsonBuilder {
public:
    JsonBuilder& begin_object() { buf_ += "{"; first_ = true; return *this; }
    JsonBuilder& end_object()   { buf_ += "}"; return *this; }
    JsonBuilder& begin_array()  { buf_ += "["; first_ = true; return *this; }
    JsonBuilder& end_array()    { buf_ += "]"; return *this; }

    JsonBuilder& key(const std::string& k) {
        comma();
        buf_ += "\"" + HttpResponse::json_escape(k) + "\":";
        return *this;
    }

    JsonBuilder& val_str(const std::string& v) {
        buf_ += "\"" + HttpResponse::json_escape(v) + "\"";
        return *this;
    }

    JsonBuilder& val_int(int64_t v) {
        buf_ += std::to_string(v);
        return *this;
    }

    JsonBuilder& val_double(double v) {
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(2) << v;
        buf_ += oss.str();
        return *this;
    }

    JsonBuilder& val_bool(bool v) {
        buf_ += v ? "true" : "false";
        return *this;
    }

    JsonBuilder& val_null() {
        buf_ += "null";
        return *this;
    }

    // key-value shortcuts
    JsonBuilder& kv_str(const std::string& k, const std::string& v) { return key(k).val_str(v); }
    JsonBuilder& kv_int(const std::string& k, int64_t v) { return key(k).val_int(v); }
    JsonBuilder& kv_double(const std::string& k, double v) { return key(k).val_double(v); }
    JsonBuilder& kv_bool(const std::string& k, bool v) { return key(k).val_bool(v); }

    // Insert raw JSON (for nested objects/arrays)
    JsonBuilder& raw(const std::string& json) { buf_ += json; return *this; }

    // Array element separator
    JsonBuilder& next() { comma(); return *this; }

    std::string str() const { return buf_; }
    void clear() { buf_.clear(); first_ = true; }

private:
    std::string buf_;
    bool first_ = true;

    void comma() {
        if (!first_) buf_ += ",";
        first_ = false;
    }
};

// =============================================================================
// ROUTE HANDLER TYPE
// =============================================================================
using RouteHandler = std::function<HttpResponse(const HttpRequest&)>;

struct Route {
    std::string method;   // "GET", "POST", "*"
    std::string path;     // "/api/devices"
    RouteHandler handler;
    bool auth_required = true;   // Require bearer token?
};

// =============================================================================
// REST SERVER CONFIG
// =============================================================================
struct RestConfig {
    bool        enabled       = true;
    int         port          = 8080;
    std::string bind_address  = "0.0.0.0";
    std::string api_token     = "";        // Static bearer token (empty = no auth)
    int         max_body_size = 1024 * 64; // 64KB max request body
    int         read_timeout  = 5;         // Seconds
};

// =============================================================================
// REST SERVER
// =============================================================================
class RestServer {
public:
    explicit RestServer(const RestConfig& cfg = {})
        : config_(cfg) {}

    ~RestServer() { stop(); }

    // -------------------------------------------------------------------------
    // ROUTE REGISTRATION
    // -------------------------------------------------------------------------
    void get(const std::string& path, RouteHandler handler, bool auth = true) {
        routes_.push_back({"GET", path, std::move(handler), auth});
    }

    void post(const std::string& path, RouteHandler handler, bool auth = true) {
        routes_.push_back({"POST", path, std::move(handler), auth});
    }

    void any(const std::string& path, RouteHandler handler, bool auth = false) {
        routes_.push_back({"*", path, std::move(handler), auth});
    }

    // -------------------------------------------------------------------------
    // START: Launch listener thread
    // -------------------------------------------------------------------------
    bool start() {
        if (!config_.enabled) return false;

        listen_sock_ = socket(AF_INET, SOCK_STREAM, 0);
        if (listen_sock_ == INVALID_SOCKET) return false;

        int optval = 1;
        setsockopt(listen_sock_, SOL_SOCKET, SO_REUSEADDR, (const char*)&optval, sizeof(optval));

        // Set socket timeout for accept
#ifdef _WIN32
        DWORD timeout = 1000;
        setsockopt(listen_sock_, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
#else
        struct timeval tv;
        tv.tv_sec = 1; tv.tv_usec = 0;
        setsockopt(listen_sock_, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
#endif

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(static_cast<uint16_t>(config_.port));
        inet_pton(AF_INET, config_.bind_address.c_str(), &addr.sin_addr);

        if (bind(listen_sock_, (sockaddr*)&addr, sizeof(addr)) < 0) {
            closesocket(listen_sock_);
            return false;
        }

        if (listen(listen_sock_, 16) < 0) {
            closesocket(listen_sock_);
            return false;
        }

        running_ = true;
        listener_thread_ = std::thread([this]() { accept_loop(); });
        return true;
    }

    // -------------------------------------------------------------------------
    // STOP: Shutdown gracefully
    // -------------------------------------------------------------------------
    void stop() {
        running_ = false;
        if (listen_sock_ != INVALID_SOCKET) {
            closesocket(listen_sock_);
            listen_sock_ = INVALID_SOCKET;
        }
        if (listener_thread_.joinable()) {
            listener_thread_.join();
        }
    }

    bool is_running() const { return running_; }
    size_t total_requests() const { return total_requests_.load(); }

    const RestConfig& config() const { return config_; }

private:
    RestConfig config_;
    std::vector<Route> routes_;
    SOCKET listen_sock_ = INVALID_SOCKET;
    std::thread listener_thread_;
    std::atomic<bool> running_{false};
    std::atomic<size_t> total_requests_{0};

    // =========================================================================
    // ACCEPT LOOP
    // =========================================================================
    void accept_loop() {
        while (running_) {
            sockaddr_in client_addr{};
            socklen_t client_len = sizeof(client_addr);
            SOCKET client = accept(listen_sock_, (sockaddr*)&client_addr, &client_len);
            if (client == INVALID_SOCKET) continue;

            // Handle in detached thread (simple model -- sufficient for dashboard)
            std::thread([this, client]() {
                handle_request(client);
            }).detach();
        }
    }

    // =========================================================================
    // HANDLE REQUEST
    // =========================================================================
    void handle_request(SOCKET sock) {
        total_requests_++;

        // Set read timeout
#ifdef _WIN32
        DWORD timeout = config_.read_timeout * 1000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
#else
        struct timeval tv;
        tv.tv_sec = config_.read_timeout; tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
#endif

        // Read request (up to max body size + headers)
        // Defense in depth:
        //  - SO_RCVTIMEO set above limits individual recv() stalls
        //  - max_iterations caps slowloris attempts (one-byte-at-a-time)
        //  - Content-Length is parsed defensively with bounds + exception handling
        std::string raw;
        raw.reserve(4096);
        char buf[4096];
        int total_read = 0;
        const int max_total = config_.max_body_size + 16384;  // headers budget
        int iterations = 0;
        const int max_iterations = 1024;  // Cap recv() calls to prevent slowloris

        bool header_complete = false;
        int declared_content_len = -1;
        size_t headers_end_offset = 0;

        while (total_read < max_total && iterations < max_iterations) {
            iterations++;
            int n = recv(sock, buf, sizeof(buf), 0);
            if (n <= 0) break;
            raw.append(buf, n);
            total_read += n;

            if (!header_complete) {
                size_t header_end = raw.find("\r\n\r\n");
                if (header_end == std::string::npos) continue;

                header_complete = true;
                headers_end_offset = header_end + 4;

                // Case-insensitive header search -- build a lowercase copy of headers only
                std::string hdrs_lower = raw.substr(0, header_end);
                for (char& c : hdrs_lower) {
                    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + 32);
                }

                size_t cl_pos = hdrs_lower.find("content-length:");
                if (cl_pos != std::string::npos) {
                    size_t val_start = cl_pos + 15;
                    size_t cl_end = hdrs_lower.find("\r\n", val_start);
                    if (cl_end == std::string::npos) cl_end = hdrs_lower.size();
                    // Guard: cl_end must be >= val_start
                    if (cl_end > val_start) {
                        std::string cl_str = hdrs_lower.substr(val_start, cl_end - val_start);
                        // Trim whitespace
                        while (!cl_str.empty() && (cl_str.front() == ' ' || cl_str.front() == '\t')) cl_str.erase(cl_str.begin());
                        while (!cl_str.empty() && (cl_str.back() == ' ' || cl_str.back() == '\t' || cl_str.back() == '\r')) cl_str.pop_back();
                        try {
                            long cl_parsed = std::stol(cl_str);
                            // Reject negative or oversized Content-Length
                            if (cl_parsed < 0 || cl_parsed > config_.max_body_size) {
                                closesocket(sock);
                                return;
                            }
                            declared_content_len = static_cast<int>(cl_parsed);
                        } catch (...) {
                            closesocket(sock);
                            return;  // Malformed Content-Length -- drop
                        }
                    }
                }
            }

            // Header complete; check if body is fully received
            if (declared_content_len < 0) break;  // No body expected
            if (static_cast<int>(raw.size() - headers_end_offset) >= declared_content_len) break;
        }

        if (raw.empty()) {
            closesocket(sock);
            return;
        }

        // Parse request
        HttpRequest req = parse_request(raw);

        // Handle CORS preflight
        if (req.method == "OPTIONS") {
            HttpResponse resp;
            resp.status_code = 204;
            resp.status_text = "No Content";
            resp.body = "";
            std::string wire = resp.serialize();
            send(sock, wire.c_str(), static_cast<int>(wire.size()), 0);
            closesocket(sock);
            return;
        }

        // Find matching route
        HttpResponse resp = HttpResponse::error(404, "Not Found");

        for (const auto& route : routes_) {
            if ((route.method == "*" || route.method == req.method) &&
                match_path(route.path, req.path))
            {
                // Auth check
                if (route.auth_required && !config_.api_token.empty()) {
                    if (req.bearer_token() != config_.api_token) {
                        resp = HttpResponse::error(401, "Invalid or missing API token");
                        break;
                    }
                }

                try {
                    resp = route.handler(req);
                } catch (const std::exception& e) {
                    resp = HttpResponse::error(500, std::string("Internal error: ") + e.what());
                } catch (...) {
                    resp = HttpResponse::error(500, "Unknown internal error");
                }
                break;
            }
        }

        // Send response
        std::string wire = resp.serialize();
        send(sock, wire.c_str(), static_cast<int>(wire.size()), 0);
        closesocket(sock);
    }

    // =========================================================================
    // PARSE HTTP REQUEST
    // =========================================================================
    static HttpRequest parse_request(const std::string& raw) {
        HttpRequest req;
        std::istringstream iss(raw);
        std::string line;

        // Helper lambda: trim leading/trailing whitespace and CR
        auto trim = [](std::string& s) {
            while (!s.empty() && (s.back() == '\r' || s.back() == '\n' || s.back() == ' ' || s.back() == '\t'))
                s.pop_back();
            size_t start = 0;
            while (start < s.size() && (s[start] == ' ' || s[start] == '\t'))
                start++;
            if (start > 0) s.erase(0, start);
        };

        // Request line: GET /api/devices?limit=10 HTTP/1.1
        if (std::getline(iss, line)) {
            trim(line);
            // Reject absurdly long request lines (prevent header attacks)
            if (line.size() > 8192) return req;
            size_t sp1 = line.find(' ');
            size_t sp2 = (sp1 != std::string::npos) ? line.find(' ', sp1 + 1) : std::string::npos;
            if (sp1 != std::string::npos && sp2 != std::string::npos && sp2 > sp1 + 1) {
                req.method = line.substr(0, sp1);
                std::string uri = line.substr(sp1 + 1, sp2 - sp1 - 1);

                size_t q = uri.find('?');
                if (q != std::string::npos) {
                    req.path = uri.substr(0, q);
                    req.query_string = uri.substr(q + 1);
                    req.query_params = parse_query(req.query_string);
                } else {
                    req.path = uri;
                }
            }
        }

        // Headers -- cap count to prevent memory exhaustion
        int header_count = 0;
        const int max_headers = 100;
        while (std::getline(iss, line)) {
            trim(line);
            if (line.empty()) break;
            if (++header_count > max_headers) break;
            // Reject oversized individual headers
            if (line.size() > 8192) continue;
            size_t colon = line.find(':');
            if (colon != std::string::npos && colon > 0) {
                std::string key = line.substr(0, colon);
                std::string val = line.substr(colon + 1);
                trim(key);
                trim(val);
                // Store lowercase key for case-insensitive lookup
                std::transform(key.begin(), key.end(), key.begin(),
                    [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                req.headers[key] = val;
            }
        }

        // Body
        size_t body_start = raw.find("\r\n\r\n");
        if (body_start != std::string::npos) {
            req.body = raw.substr(body_start + 4);
        }

        return req;
    }

    static std::map<std::string, std::string> parse_query(const std::string& qs) {
        std::map<std::string, std::string> params;
        std::istringstream iss(qs);
        std::string pair;
        while (std::getline(iss, pair, '&')) {
            size_t eq = pair.find('=');
            if (eq != std::string::npos) {
                params[pair.substr(0, eq)] = url_decode(pair.substr(eq + 1));
            } else {
                params[pair] = "";
            }
        }
        return params;
    }

    static std::string url_decode(const std::string& s) {
        std::string out;
        for (size_t i = 0; i < s.size(); i++) {
            if (s[i] == '%' && i + 2 < s.size()) {
                int hex = 0;
                if (sscanf(s.substr(i + 1, 2).c_str(), "%x", &hex) == 1) {
                    out += static_cast<char>(hex);
                    i += 2;
                }
            } else if (s[i] == '+') {
                out += ' ';
            } else {
                out += s[i];
            }
        }
        return out;
    }

    static bool match_path(const std::string& pattern, const std::string& path) {
        // Exact match or prefix match for wildcard routes
        if (pattern == path) return true;
        if (pattern.back() == '*' && path.find(pattern.substr(0, pattern.size() - 1)) == 0) return true;
        return false;
    }
};

#endif
