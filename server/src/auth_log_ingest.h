#ifndef SEAHORSE_AUTH_LOG_INGEST_H
#define SEAHORSE_AUTH_LOG_INGEST_H

// Shared ingest path for MSG_LOG_BATCH records (and unit/e2e tests).
// Parses each record with SessionScanner (source tag selects the parser,
// not the server OS), then forwards AuthEvents to AlertEngine and
// CorrelationEngine so brute-force alerts and the auth_brute_force
// correlation rule can fire.

#include "log_batch.h"
#include "session_tracker.h"
#include "regex_engine.h"
#include "alert_engine.h"
#include "correlation_engine.h"

#include <string>
#include <vector>

struct AuthIngestHooks {
    AlertEngine*        alerts     = nullptr;
    CorrelationEngine*  correlator = nullptr;
};

inline std::string auth_event_severity(AuthEventType t) {
    switch (t) {
        case AuthEventType::AUTH_LOGIN_FAILED:        return "medium";
        case AuthEventType::AUTH_PRIVILEGE_ESCALATION:return "high";
        case AuthEventType::AUTH_ACCOUNT_LOCKOUT:     return "high";
        case AuthEventType::AUTH_LOGIN_SUCCESS:       return "low";
        case AuthEventType::AUTH_LOGOUT:              return "low";
    }
    return "low";
}

inline std::vector<AuthEvent> parse_log_batch(SessionScanner& scanner, const LogBatch& batch) {
    for (const auto& rec : batch.records) {
        int64_t ts = rec.timestamp_ms ? rec.timestamp_ms : batch.timestamp_ms;
        scanner.parse_auth_record(rec.source, rec.text, ts);
    }
    return scanner.collect_auth_events();
}

inline void emit_auth_events(int32_t device_id, const std::string& client_ip,
                             const std::vector<AuthEvent>& events,
                             const AuthIngestHooks& hooks) {
    if (events.empty()) return;

    std::vector<SecurityEvent> sec;
    for (const auto& a : events) {
        if (hooks.correlator) {
            CorrEvent ce;
            ce.device_id    = device_id;
            ce.timestamp_ms = a.timestamp_ms;
            ce.source       = "session";
            ce.category     = auth_event_str(a.type);
            ce.severity     = auth_event_severity(a.type);
            ce.machine_ip   = client_ip;
            ce.target_user  = a.username;
            ce.indicator    = a.source_ip;
            ce.detail       = a.detail;
            hooks.correlator->ingest(ce);
        }

        if (a.type == AuthEventType::AUTH_LOGIN_FAILED) {
            // auth_failure: 5 in 300s; brute_force: 3 in 60s. Each failed
            // logon is a datapoint for both threshold categories.
            sec.push_back({"auth_log_failed", "medium", "auth_failure", a.detail});
            sec.push_back({"auth_log_failed", "high",   "brute_force",  a.detail});
        } else if (a.type == AuthEventType::AUTH_PRIVILEGE_ESCALATION) {
            sec.push_back({"auth_log_privesc", "high", "privilege_escalation", a.detail});
        } else if (a.type == AuthEventType::AUTH_ACCOUNT_LOCKOUT) {
            sec.push_back({"auth_log_lockout", "high", "account_lockout", a.detail});
        }
    }
    if (hooks.alerts && !sec.empty())
        hooks.alerts->ingest(device_id, client_ip, sec);
}

inline std::vector<AuthEvent> ingest_log_batch(SessionScanner& scanner,
                                               const LogBatch& batch,
                                               const std::string& client_ip,
                                               const AuthIngestHooks& hooks) {
    auto events = parse_log_batch(scanner, batch);
    emit_auth_events(batch.device_id, client_ip, events, hooks);
    return events;
}

#endif
