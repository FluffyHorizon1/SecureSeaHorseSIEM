// =============================================================================
// rbac_manager.h -- Phase 20 (v4.0.0)
// -----------------------------------------------------------------------------
// Multi-tenant authentication + authorization. Replaces the single bearer
// token from Phase 7 with a full JWT flow (HS256 for on-prem installs,
// RS256 when an external IdP is configured).
//
// Four built-in roles:
//   admin      -- everything, including tenant management
//   operator   -- dashboard, IR actions, update policy, playbooks
//   analyst    -- dashboard read, hunt queries, correlations, IR read-only
//   auditor    -- read-only access to reports + audit trail only
//
// Every REST request is resolved to a (tenant_id, role) pair. Data-layer
// queries gain a WHERE tenant_id = $N filter across telemetry, events,
// threats, ioc_matches, fim_events, correlations, and audit_log.
// =============================================================================
#pragma once

#include <chrono>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace seahorse::rbac {

enum class Role { Admin, Operator, Analyst, Auditor };
enum class Permission {
    ReadDashboard,
    ReadEvents,
    ReadThreats,
    ReadIoC,
    ReadFim,
    ReadCorrelations,
    ReadReports,
    ReadAuditLog,
    WriteIrActions,
    WritePlaybooks,
    WriteUpdatePolicy,
    WriteTenants,
    WriteUsers,
    RunHuntQuery,
};

struct Tenant {
    std::string id;                         // uuid
    std::string name;
    bool        enabled = true;
    int         device_quota = 0;           // 0 = unlimited
    std::chrono::system_clock::time_point created_at;
};

struct User {
    std::string id;
    std::string tenant_id;
    std::string email;
    std::string password_hash;              // argon2id
    Role        role = Role::Analyst;
    bool        enabled = true;
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point last_login_at;
};

struct Session {
    std::string user_id;
    std::string tenant_id;
    Role        role = Role::Analyst;
    std::chrono::system_clock::time_point expires_at;
};

class RbacManager {
public:
    // JWT config. `hmac_secret` is drawn from server.conf; rotated via
    // `/api/auth/rotate_secret` (admin-only).
    void configure_hmac(const std::string& hmac_secret);
    void configure_oidc(const std::string& issuer_url, const std::string& client_id);

    // Login path: verify password, issue JWT. Token TTL is configurable
    // (default 8h).
    std::optional<std::string> issue_token(const std::string& email,
                                           const std::string& password);

    // Validate an `Authorization: Bearer ...` header and return the session.
    std::optional<Session> authenticate(const std::string& bearer);

    // Pure check — does this role have this permission?
    static bool has(Role r, Permission p);

    // CRUD
    Tenant create_tenant(const std::string& name);
    User   create_user(const std::string& tenant_id,
                       const std::string& email,
                       const std::string& password,
                       Role role);
    void   disable_user(const std::string& user_id);

    // Audit log. Every state-changing API call appends one row.
    void audit(const std::string& actor_user_id,
               const std::string& action,
               const std::string& target,
               const std::string& outcome);

private:
    mutable std::mutex mtx_;
    std::unordered_map<std::string, Tenant> tenants_;
    std::unordered_map<std::string, User>   users_;
    std::string hmac_secret_;
    std::string oidc_issuer_;
    std::string oidc_client_id_;
};

} // namespace seahorse::rbac
