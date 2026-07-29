#ifndef RBAC_H
#define RBAC_H

#ifndef NOMINMAX
#define NOMINMAX
#endif

// =============================================================================
// SecureSeaHorse SIEM -- Phase 20: Multi-Tenancy, RBAC, JWT Auth
// =============================================================================
// Replaces the simple shared bearer token in the REST server with a proper
// user model:
//   - Tenants isolate device inventories and stored data
//   - Users belong to exactly one tenant and have a single role
//   - 4 roles: admin > analyst > operator > viewer
//   - Authentication via signed JWT (HS256, so no external CA needed)
//   - Audit log captures every authenticated request and role check
//
// Integrates with rest_server.h by wrapping handlers in require_role().
// The underlying fleet / threat stores remain unchanged -- the gate is
// applied at the HTTP layer (and optionally at query time via tenant_id).
// =============================================================================

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <deque>
#include <fstream>
#include <functional>
#include <map>
#include <mutex>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

// =============================================================================
// ROLES
// =============================================================================
enum class Role : int { VIEWER = 1, OPERATOR = 2, ANALYST = 3, ADMIN = 4 };

inline std::string role_to_str(Role r) {
    switch (r) {
        case Role::ADMIN:    return "admin";
        case Role::ANALYST:  return "analyst";
        case Role::OPERATOR: return "operator";
        case Role::VIEWER:   return "viewer";
    }
    return "viewer";
}

inline Role role_from_str(const std::string& s) {
    std::string l = s;
    std::transform(l.begin(), l.end(), l.begin(), ::tolower);
    if (l == "admin") return Role::ADMIN;
    if (l == "analyst") return Role::ANALYST;
    if (l == "operator") return Role::OPERATOR;
    return Role::VIEWER;
}

// =============================================================================
// USER
// =============================================================================
struct User {
    std::string username;
    std::string tenant_id;
    Role        role = Role::VIEWER;
    std::string pw_salt;          // hex
    std::string pw_hash;          // SHA-256(salt || password) as hex
    bool        disabled = false;
    int64_t     created_ms = 0;
    int64_t     last_login_ms = 0;
};

// =============================================================================
// TENANT
// =============================================================================
struct Tenant {
    std::string id;               // short slug like "acme"
    std::string display_name;
    int64_t     created_ms = 0;
    bool        enabled = true;
    size_t      device_limit = 0; // 0 = unlimited
};

// =============================================================================
// AUDIT LOG ENTRY
// =============================================================================
struct AuditEntry {
    int64_t     timestamp_ms = 0;
    std::string username;
    std::string tenant_id;
    std::string action;           // "login", "api_request", "role_denied", ...
    std::string detail;
    std::string source_ip;
    bool        success = false;
};

// =============================================================================
// JWT UTILITIES (HS256 only, hand-rolled so we don't pull in an external lib)
// =============================================================================
namespace jwt_internal {

inline std::string b64url_encode(const uint8_t* data, size_t len) {
    static const char tab[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    for (size_t i = 0; i < len; i += 3) {
        uint32_t n = (uint32_t)data[i] << 16;
        if (i + 1 < len) n |= (uint32_t)data[i + 1] << 8;
        if (i + 2 < len) n |= data[i + 2];
        out += tab[(n >> 18) & 63];
        out += tab[(n >> 12) & 63];
        if (i + 1 < len) out += tab[(n >> 6) & 63];
        if (i + 2 < len) out += tab[n & 63];
    }
    return out;
}
inline std::string b64url_encode(const std::string& s) {
    return b64url_encode(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}
inline std::string b64url_decode(const std::string& in) {
    static int8_t tbl[256];
    static bool init = false;
    if (!init) {
        for (int i = 0; i < 256; i++) tbl[i] = -1;
        const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        for (int i = 0; i < 64; i++) tbl[(unsigned char)t[i]] = (int8_t)i;
        init = true;
    }
    std::string out;
    int val = 0, bits = -8;
    for (unsigned char c : in) {
        if (c == '=' || c == '\n' || c == '\r') continue;
        int v = tbl[c];
        if (v < 0) continue;
        val = (val << 6) | v;
        bits += 6;
        if (bits >= 0) {
            out.push_back(static_cast<char>((val >> bits) & 0xFF));
            bits -= 8;
        }
    }
    return out;
}

} // namespace jwt_internal

// =============================================================================
// RBAC MANAGER
// =============================================================================
class RbacManager {
public:
    struct Config {
        bool enabled = true;
        std::string secret;            // HS256 signing key (minimum 32 bytes)
        int token_lifetime_s = 3600;   // 1 hour default
        std::string users_file = "users.db";    // Line-based store
        std::string tenants_file = "tenants.db";
        std::string audit_log = "audit.log";
        size_t audit_ring_max = 5000;
    };

    explicit RbacManager(const Config& cfg) : config_(cfg) {
        load();
    }

    // -------------------------------------------------------------------------
    // USER / TENANT MANAGEMENT
    // -------------------------------------------------------------------------
    bool create_tenant(const std::string& id, const std::string& display) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (tenants_.count(id)) return false;
        Tenant t;
        t.id = id; t.display_name = display;
        t.created_ms = now_ms();
        tenants_[id] = t;
        save_tenants_locked();
        return true;
    }

    bool create_user(const std::string& username, const std::string& password,
                     const std::string& tenant_id, Role role)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (users_.count(username)) return false;
        if (!tenants_.count(tenant_id)) return false;
        User u;
        u.username = username;
        u.tenant_id = tenant_id;
        u.role = role;
        u.pw_salt = random_hex(16);
        u.pw_hash = hash_password(u.pw_salt, password);
        u.created_ms = now_ms();
        users_[username] = u;
        save_users_locked();
        return true;
    }

    bool set_password(const std::string& username, const std::string& new_password) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = users_.find(username);
        if (it == users_.end()) return false;
        it->second.pw_salt = random_hex(16);
        it->second.pw_hash = hash_password(it->second.pw_salt, new_password);
        save_users_locked();
        return true;
    }

    bool disable_user(const std::string& username) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = users_.find(username);
        if (it == users_.end()) return false;
        it->second.disabled = true;
        save_users_locked();
        return true;
    }

    // -------------------------------------------------------------------------
    // AUTHENTICATION
    // -------------------------------------------------------------------------
    struct LoginResult {
        bool success = false;
        std::string jwt;
        std::string reason;
        std::string tenant_id;
        Role role = Role::VIEWER;
    };

    LoginResult login(const std::string& username, const std::string& password,
                      const std::string& source_ip)
    {
        LoginResult r;
        std::unique_lock<std::mutex> lock(mutex_);
        auto it = users_.find(username);
        if (it == users_.end() || it->second.disabled) {
            lock.unlock();
            audit_locked("login", username, "", source_ip, false, "unknown user or disabled");
            r.reason = "invalid credentials";
            return r;
        }
        std::string attempt = hash_password(it->second.pw_salt, password);
        if (attempt != it->second.pw_hash) {
            lock.unlock();
            audit_locked("login", username, it->second.tenant_id, source_ip, false, "bad password");
            r.reason = "invalid credentials";
            return r;
        }
        it->second.last_login_ms = now_ms();
        r.success = true;
        r.tenant_id = it->second.tenant_id;
        r.role = it->second.role;
        r.jwt = issue_token_locked(it->second);
        save_users_locked();
        lock.unlock();
        audit_locked("login", username, r.tenant_id, source_ip, true, "token issued");
        return r;
    }

    struct Claims {
        std::string username;
        std::string tenant_id;
        Role role = Role::VIEWER;
        int64_t exp_ms = 0;
        bool valid = false;
    };

    Claims verify_jwt(const std::string& jwt) const {
        Claims c;
        size_t d1 = jwt.find('.');
        size_t d2 = jwt.find('.', d1 + 1);
        if (d1 == std::string::npos || d2 == std::string::npos) return c;
        std::string signing = jwt.substr(0, d2);
        std::string sig_b64 = jwt.substr(d2 + 1);

        std::string expected = hs256(signing);
        std::string expected_b64 = jwt_internal::b64url_encode(
            reinterpret_cast<const uint8_t*>(expected.data()), expected.size());
        if (expected_b64 != sig_b64) return c;

        std::string payload = jwt_internal::b64url_decode(jwt.substr(d1 + 1, d2 - d1 - 1));
        // Very small JSON parser for: {"sub":"...","tid":"...","role":"...","exp":N}
        c.username  = extract_json_str(payload, "sub");
        c.tenant_id = extract_json_str(payload, "tid");
        c.role      = role_from_str(extract_json_str(payload, "role"));
        c.exp_ms    = extract_json_num(payload, "exp");
        if (c.exp_ms > 0 && c.exp_ms < now_ms()) return c;
        c.valid = true;
        return c;
    }

    // -------------------------------------------------------------------------
    // AUTHORISATION
    // -------------------------------------------------------------------------
    bool allow(Role user_role, Role required) const {
        return static_cast<int>(user_role) >= static_cast<int>(required);
    }

    // -------------------------------------------------------------------------
    // AUDIT LOG
    // -------------------------------------------------------------------------
    void audit(const std::string& action, const std::string& user,
               const std::string& tenant, const std::string& ip,
               bool success, const std::string& detail)
    {
        audit_locked(action, user, tenant, ip, success, detail);
    }

    std::vector<AuditEntry> recent_audit(size_t limit = 100) const {
        std::lock_guard<std::mutex> lock(mutex_);
        size_t start = audit_ring_.size() > limit ? audit_ring_.size() - limit : 0;
        return std::vector<AuditEntry>(audit_ring_.begin() + static_cast<long>(start),
                                       audit_ring_.end());
    }

    size_t user_count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return users_.size();
    }
    size_t tenant_count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return tenants_.size();
    }

private:
    Config config_;
    mutable std::mutex mutex_;
    std::map<std::string, User>   users_;
    std::map<std::string, Tenant> tenants_;
    std::deque<AuditEntry>        audit_ring_;

    static int64_t now_ms() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }

    std::string random_hex(size_t n) const {
        static thread_local std::mt19937_64 rng(
            static_cast<uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count()));
        std::uniform_int_distribution<uint32_t> dist(0, 15);
        static const char hex[] = "0123456789abcdef";
        std::string s; s.reserve(n * 2);
        for (size_t i = 0; i < n * 2; i++) s += hex[dist(rng)];
        return s;
    }

    static std::string hash_password(const std::string& salt, const std::string& pw) {
        unsigned char out[SHA256_DIGEST_LENGTH];
        std::string combined = salt + pw;
        SHA256(reinterpret_cast<const unsigned char*>(combined.data()), combined.size(), out);
        std::ostringstream hex;
        hex << std::hex << std::setfill('0');
        for (unsigned char c : out) hex << std::setw(2) << (int)c;
        return hex.str();
    }

    std::string hs256(const std::string& data) const {
        unsigned int len = 0;
        unsigned char out[EVP_MAX_MD_SIZE];
        HMAC(EVP_sha256(),
             config_.secret.data(), static_cast<int>(config_.secret.size()),
             reinterpret_cast<const unsigned char*>(data.data()), data.size(),
             out, &len);
        return std::string(reinterpret_cast<const char*>(out), len);
    }

    std::string issue_token_locked(const User& u) const {
        int64_t exp = now_ms() + config_.token_lifetime_s * 1000LL;
        std::string header_json  = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        std::string payload_json = "{\"sub\":\"" + u.username + "\",\"tid\":\""
            + u.tenant_id + "\",\"role\":\"" + role_to_str(u.role)
            + "\",\"exp\":" + std::to_string(exp) + "}";
        std::string h_b64 = jwt_internal::b64url_encode(header_json);
        std::string p_b64 = jwt_internal::b64url_encode(payload_json);
        std::string sig = hs256(h_b64 + "." + p_b64);
        std::string s_b64 = jwt_internal::b64url_encode(
            reinterpret_cast<const uint8_t*>(sig.data()), sig.size());
        return h_b64 + "." + p_b64 + "." + s_b64;
    }

    static std::string extract_json_str(const std::string& json, const std::string& key) {
        std::string needle = "\"" + key + "\":\"";
        auto p = json.find(needle);
        if (p == std::string::npos) return "";
        p += needle.size();
        auto e = json.find('"', p);
        if (e == std::string::npos) return "";
        return json.substr(p, e - p);
    }

    static int64_t extract_json_num(const std::string& json, const std::string& key) {
        std::string needle = "\"" + key + "\":";
        auto p = json.find(needle);
        if (p == std::string::npos) return 0;
        p += needle.size();
        std::string num;
        while (p < json.size() && (std::isdigit(static_cast<unsigned char>(json[p])) || json[p] == '-'))
            num += json[p++];
        try { return std::stoll(num); } catch (...) { return 0; }
    }

    void audit_locked(const std::string& action, const std::string& user,
                      const std::string& tenant, const std::string& ip,
                      bool success, const std::string& detail)
    {
        AuditEntry e;
        e.timestamp_ms = now_ms();
        e.username = user; e.tenant_id = tenant;
        e.action = action; e.source_ip = ip;
        e.success = success; e.detail = detail;

        std::lock_guard<std::mutex> lock(mutex_);
        audit_ring_.push_back(e);
        while (audit_ring_.size() > config_.audit_ring_max) audit_ring_.pop_front();

        // Append to file
        std::ofstream f(config_.audit_log, std::ios::app);
        if (f.is_open()) {
            f << e.timestamp_ms << "|" << user << "|" << tenant
              << "|" << action << "|" << (success ? "ok" : "fail")
              << "|" << ip << "|" << detail << "\n";
        }
    }

    void save_users_locked() {
        std::ofstream f(config_.users_file, std::ios::trunc);
        if (!f.is_open()) return;
        f << "# username|tenant|role|salt|hash|disabled|created|last_login\n";
        for (const auto& kv : users_) {
            const User& u = kv.second;
            f << u.username << "|" << u.tenant_id << "|" << role_to_str(u.role)
              << "|" << u.pw_salt << "|" << u.pw_hash
              << "|" << (u.disabled ? 1 : 0) << "|" << u.created_ms
              << "|" << u.last_login_ms << "\n";
        }
    }
    void save_tenants_locked() {
        std::ofstream f(config_.tenants_file, std::ios::trunc);
        if (!f.is_open()) return;
        f << "# id|display|created|enabled|device_limit\n";
        for (const auto& kv : tenants_) {
            const Tenant& t = kv.second;
            f << t.id << "|" << t.display_name << "|" << t.created_ms
              << "|" << (t.enabled ? 1 : 0) << "|" << t.device_limit << "\n";
        }
    }

    void load() {
        std::lock_guard<std::mutex> lock(mutex_);
        {
            std::ifstream f(config_.tenants_file);
            std::string line;
            while (std::getline(f, line)) {
                if (line.empty() || line[0] == '#') continue;
                std::istringstream iss(line);
                std::string t;
                Tenant tn;
                if (std::getline(iss, t, '|')) tn.id = t;
                if (std::getline(iss, t, '|')) tn.display_name = t;
                if (std::getline(iss, t, '|')) { try { tn.created_ms = std::stoll(t); } catch (...) {} }
                if (std::getline(iss, t, '|')) tn.enabled = (t == "1");
                if (std::getline(iss, t, '|')) { try { tn.device_limit = std::stoull(t); } catch (...) {} }
                if (!tn.id.empty()) tenants_[tn.id] = tn;
            }
        }
        {
            std::ifstream f(config_.users_file);
            std::string line;
            while (std::getline(f, line)) {
                if (line.empty() || line[0] == '#') continue;
                std::istringstream iss(line);
                std::string t;
                User u;
                if (std::getline(iss, t, '|')) u.username = t;
                if (std::getline(iss, t, '|')) u.tenant_id = t;
                if (std::getline(iss, t, '|')) u.role = role_from_str(t);
                if (std::getline(iss, t, '|')) u.pw_salt = t;
                if (std::getline(iss, t, '|')) u.pw_hash = t;
                if (std::getline(iss, t, '|')) u.disabled = (t == "1");
                if (std::getline(iss, t, '|')) { try { u.created_ms = std::stoll(t); } catch (...) {} }
                if (std::getline(iss, t, '|')) { try { u.last_login_ms = std::stoll(t); } catch (...) {} }
                if (!u.username.empty()) users_[u.username] = u;
            }
        }
    }
};

#endif
