# SecureSeaHorse v5.0 — Server Integration Snippets

This document shows the exact edits to `src/server/server.cpp` needed to
wire the Phase 16-25 subsystems into the existing v3.1.4 pipeline. Each
snippet is self-contained and gated by a config flag so you can enable
one phase at a time.

Each snippet follows the same pattern already used for Phases 4-15:
construct the subsystem in `main()` after the existing initialisers,
feed it events inside `process_report()` / `process_*_report()`, and
expose any REST / WebSocket routes alongside the Phase 7 routes. Cleanup
goes in the `.reset()` block at the bottom of `main()`.

---

## 1. Add includes at the top of server.cpp

```cpp
// --- Phases 16-25 ---
#include "sigma_engine.h"        // Phase 16
#include "report_generator.h"    // Phase 18
#include "rbac.h"                // Phase 20
#include "soar_connector.h"      // Phase 21
#include "syslog_io.h"           // Phase 22
#include "hunt_query.h"          // Phase 23
#include "ml_anomaly.h"          // Phase 24
```

## 2. Add global unique_ptr instances

```cpp
static std::unique_ptr<SigmaEngine>       sigma;       // Phase 16
static std::unique_ptr<ReportGenerator>   reporter;    // Phase 18
static std::unique_ptr<RbacManager>       rbac;        // Phase 20
static std::unique_ptr<SoarConnector>     soar;        // Phase 21
static std::unique_ptr<SyslogListener>    syslog_in;   // Phase 22
static std::unique_ptr<SyslogForwarder>   syslog_out;  // Phase 22
static std::unique_ptr<HuntQueryEngine>   hunt;        // Phase 23
static std::unique_ptr<MlAnomalyDetector> ml;          // Phase 24
static std::atomic<size_t>                g_ml_findings{0};
```

## 3. Initialise each subsystem in `main()`

Place these blocks after the existing Phase 15 correlation-engine
initialisation, in ascending phase order.

```cpp
// ---------------------------------------------------------------------
// PHASE 16: Sigma Rule Engine
// ---------------------------------------------------------------------
if (conf.get_bool("sigma_enabled", true)) {
    SigmaEngineConfig sc;
    sc.rules_dir         = conf.get("sigma_rules_dir", "config/sigma_rules");
    sc.reload_interval_s = conf.get_int("sigma_reload_s", 300);
    sigma = std::make_unique<SigmaEngine>(sc);
    logger->log(AsyncLogger::INFO,
        "Sigma: ENABLED | " + std::to_string(sigma->rule_count()) + " rules loaded");
} else {
    logger->log(AsyncLogger::INFO, "Sigma: disabled.");
}

// ---------------------------------------------------------------------
// PHASE 18: Reporting & Compliance
// ---------------------------------------------------------------------
if (conf.get_bool("reports_enabled", true)) {
    ReportGeneratorConfig rc;
    rc.output_dir = conf.get("reports_dir", "reports");
    reporter = std::make_unique<ReportGenerator>(rc);
    logger->log(AsyncLogger::INFO,
        "Reports: ENABLED | output_dir=" + rc.output_dir);
}

// ---------------------------------------------------------------------
// PHASE 20: RBAC
// ---------------------------------------------------------------------
if (conf.get_bool("rbac_enabled", false)) {
    RbacConfig rc;
    rc.hmac_secret   = conf.get("rbac_secret", "");
    rc.users_db_path = conf.get("rbac_users_db", "rbac/users.db");
    rc.tenants_db    = conf.get("rbac_tenants_db", "rbac/tenants.db");
    rc.audit_log     = conf.get("rbac_audit_log", "rbac/audit.log");
    rc.token_ttl_s   = conf.get_int("rbac_token_ttl_s", 28800);
    if (rc.hmac_secret.empty() || rc.hmac_secret.find("changeme") != std::string::npos) {
        logger->log(AsyncLogger::ERROR_LOG,
            "RBAC: rbac_secret is unset or default -- refusing to start. "
            "Set a long random value in server.conf.");
        return 1;
    }
    rbac = std::make_unique<RbacManager>(rc);
    logger->log(AsyncLogger::INFO,
        "RBAC: ENABLED | users=" + std::to_string(rbac->user_count())
        + " tenants=" + std::to_string(rbac->tenant_count()));
}

// ---------------------------------------------------------------------
// PHASE 21: SOAR
// ---------------------------------------------------------------------
if (conf.get_bool("soar_enabled", false)) {
    SoarConfig sc;
    sc.backend_str      = conf.get("soar_backend", "generic_webhook");
    sc.url              = conf.get("soar_url", "");
    sc.auth_header      = conf.get("soar_auth_header", "");
    sc.inbound_secret   = conf.get("soar_inbound_secret", "");
    soar = std::make_unique<SoarConnector>(sc);
    soar->start();
    logger->log(AsyncLogger::INFO,
        "SOAR: ENABLED | backend=" + sc.backend_str + " | url=" + sc.url);
}

// ---------------------------------------------------------------------
// PHASE 22: Syslog I/O
// ---------------------------------------------------------------------
{
    std::string listen_udp = conf.get("syslog_listen_udp", "");
    std::string listen_tcp = conf.get("syslog_listen_tcp", "");
    if (!listen_udp.empty() || !listen_tcp.empty()) {
        SyslogListenerConfig lc;
        lc.udp_bind = listen_udp;
        lc.tcp_bind = listen_tcp;
        lc.on_event = [](const SyslogEvent& ev) {
            // Route syslog events through the same pipeline as telemetry logs
            if (regex_engine) {
                auto sec_events = regex_engine->analyze(ev.message);
                for (const auto& se : sec_events) {
                    if (pg_store) pg_store->insert_security_event(
                        0, ev.timestamp_ms, ev.hostname.c_str(),
                        se.rule_name, se.severity, se.category, se.matched_text);
                }
            }
            if (sigma) {
                SigmaEvent evt;
                evt.message = ev.message;
                evt.product = "syslog";
                evt.service = ev.app_name;
                auto hits = sigma->evaluate(evt);
                for (const auto& h : hits) {
                    logger->log(AsyncLogger::WARN,
                        "[SIGMA-SYSLOG] " + h.rule_name + " from " + ev.hostname);
                }
            }
        };
        syslog_in = std::make_unique<SyslogListener>(lc);
        syslog_in->start();
        logger->log(AsyncLogger::INFO,
            "Syslog listener: udp=" + listen_udp + " tcp=" + listen_tcp);
    }

    if (conf.get_bool("syslog_forward_enabled", false)) {
        SyslogForwarderConfig fc;
        fc.destination = conf.get("syslog_forward_dest", "");
        fc.proto       = conf.get("syslog_forward_proto", "udp");
        fc.format      = conf.get("syslog_forward_format", "cef");
        syslog_out = std::make_unique<SyslogForwarder>(fc);
        logger->log(AsyncLogger::INFO,
            "Syslog forwarder: " + fc.destination + " [" + fc.format + "/" + fc.proto + "]");
    }
}

// ---------------------------------------------------------------------
// PHASE 23: Hunt DSL
// ---------------------------------------------------------------------
if (pg_store) {
    hunt = std::make_unique<HuntQueryEngine>(pg_store.get());
    logger->log(AsyncLogger::INFO, "Hunt DSL: ENABLED");
}

// ---------------------------------------------------------------------
// PHASE 24: ML Anomaly Detection
// ---------------------------------------------------------------------
if (conf.get_bool("ml_enabled", true)) {
    MlAnomalyDetector::Config mc;
    mc.window_size         = conf.get_size("ml_window_size", 2048);
    mc.warmup_samples      = conf.get_int("ml_warmup_samples", 128);
    mc.retrain_interval_s  = conf.get_int("ml_retrain_interval_s", 300);
    mc.score_threshold     = std::stod(conf.get("ml_score_threshold", "0.65"));
    mc.critical_threshold  = std::stod(conf.get("ml_critical_threshold", "0.85"));
    mc.forest_config.num_trees = conf.get_int("ml_forest_trees", 64);
    mc.forest_config.subsample = conf.get_int("ml_forest_subsample", 256);
    mc.beacon_config.max_jitter   = std::stod(conf.get("ml_beacon_max_jitter", "0.15"));
    mc.beacon_config.min_autocorr = std::stod(conf.get("ml_beacon_min_autocorr", "0.35"));
    mc.beacon_config.min_samples  = conf.get_int("ml_beacon_min_samples", 12);
    mc.beacon_config.window_size  = conf.get_size("ml_beacon_window", 64);
    ml = std::make_unique<MlAnomalyDetector>(mc);
    logger->log(AsyncLogger::INFO,
        "ML Anomaly: ENABLED | trees=" + std::to_string(mc.forest_config.num_trees)
        + " warmup=" + std::to_string(mc.warmup_samples)
        + " threshold=" + std::to_string(mc.score_threshold));
}
```

## 4. Extend `process_report()` to feed the new subsystems

Add this block **after** the existing Phase 10 network inspector block
and **before** the final standard log line:

```cpp
// =============================================================================
// PHASES 16, 24: Sigma + ML Anomaly
// =============================================================================

// --- Phase 16: Sigma rule evaluation ---
if (sigma) {
    SigmaEvent se;
    se.message = raw_log;
    se.product = "linux";         // TODO: detect from machine_name
    se.category = "telemetry";
    auto hits = sigma->evaluate(se);
    for (const auto& h : hits) {
        g_total_threats++;
        if (pg_store) {
            pg_store->insert_threat_detection(
                current.device_id, current.timestamp_ms, current.machine_ip,
                "sigma", h.rule_name, h.severity, h.confidence,
                h.mitre_id, h.mitre_name, h.mitre_tactic,
                h.description, h.evidence);
        }
        logger->log(AsyncLogger::WARN,
            "[SIGMA] " + h.rule_name + " | dev=" + std::to_string(current.device_id)
            + " | " + h.severity + " | " + h.description);

        if (correlator) {
            CorrEvent ce;
            ce.device_id = current.device_id; ce.timestamp_ms = current.timestamp_ms;
            ce.source = "sigma"; ce.category = h.rule_name;
            ce.severity = h.severity; ce.machine_ip = current.machine_ip;
            ce.detail = h.description;
            correlator->ingest(ce);
        }
        if (ir_engine) {
            Incident inc;
            inc.device_id = current.device_id; inc.timestamp_ms = current.timestamp_ms;
            inc.machine_ip = current.machine_ip; inc.source = "sigma";
            inc.category = h.rule_name; inc.severity = h.severity;
            inc.mitre_id = h.mitre_id; inc.description = h.description;
            ir_engine->report_incident(inc);
        }
    }
}

// --- Phase 24: ML anomaly observation ---
if (ml) {
    AnomalyFeatures feat;
    feat.cpu_pct        = cpu_usage;
    feat.ram_pct        = (current.ram_total_bytes > 0)
        ? 100.0 * (1.0 - (double)current.ram_avail_bytes / (double)current.ram_total_bytes)
        : 0.0;
    feat.net_in_rate    = static_cast<double>(current.net_bytes_in - last.net_bytes_in);
    feat.net_out_rate   = static_cast<double>(current.net_bytes_out - last.net_bytes_out);
    feat.event_rate     = static_cast<double>(sec_events.size());
    feat.auth_fail_rate = static_cast<double>(new_fails);
    feat.interval_ms    = static_cast<double>(current.timestamp_ms - last.timestamp_ms);

    auto findings = ml->observe(current.device_id, current.timestamp_ms,
                                current.machine_ip, feat);
    for (const auto& f : findings) {
        g_ml_findings++;
        if (pg_store) {
            pg_store->insert_threat_detection(
                f.device_id, f.timestamp_ms, f.machine_ip.c_str(),
                "ml_anomaly", f.detector, f.severity, f.confidence,
                f.mitre_id, "", f.mitre_tactic, f.description, f.evidence);
        }
        logger->log(AsyncLogger::WARN,
            "[ML] " + f.detector + " | dev=" + std::to_string(f.device_id)
            + " | score=" + std::to_string(f.score) + " | " + f.description);

        if (ir_engine && (f.severity == "high" || f.severity == "critical")) {
            Incident inc;
            inc.device_id = f.device_id; inc.timestamp_ms = f.timestamp_ms;
            inc.machine_ip = f.machine_ip; inc.source = "ml_anomaly";
            inc.category = f.detector; inc.severity = f.severity;
            inc.mitre_id = f.mitre_id; inc.description = f.description;
            ir_engine->report_incident(inc);
        }
    }
}

// --- Phase 21: Forward every high+ threat to SOAR ---
// (Add this inside the existing threat loop in process_report)
if (soar && (t.severity == "high" || t.severity == "critical")) {
    SoarOutbound out;
    out.timestamp_ms = t.timestamp_ms;
    out.device_id    = t.device_id;
    out.severity     = t.severity;
    out.category     = t.category;
    out.mitre_id     = t.mitre_id;
    out.description  = t.description;
    soar->enqueue(out);
}
```

## 5. Handle MSG_USB_REPORT (Phase 19) in `handle_client_ssl()`

In the `switch (msg_type)` block, add:

```cpp
case MSG_USB_REPORT: {   // Phase 19
    if (plen > 0) process_usb_report(payload.data(), plen, peer_ip);
    break;
}
```

And define the handler near the other `process_*_report()` functions:

```cpp
void process_usb_report(const char* data, uint32_t len, const std::string& client_ip) {
    std::string payload(data, len);
    UsbReport report = deserialize_usb_report(payload);
    if (report.device_id == 0) return;

    logger->log(AsyncLogger::INFO,
        "[USB] device=" + std::to_string(report.device_id)
        + " present=" + std::to_string(report.devices.size())
        + " changes=" + std::to_string(report.changes.size()));

    for (const auto& ch : report.changes) {
        std::string sev = "low";
        if (ch.type == UsbChangeType::WHITELIST_VIOLATION) sev = "high";
        else if (ch.type == UsbChangeType::INSERTED && ch.device.category == "storage") sev = "medium";

        logger->log(sev == "high" ? AsyncLogger::WARN : AsyncLogger::INFO,
            "[USB] " + usb_change_str(ch.type) + " | dev=" + std::to_string(report.device_id)
            + " | " + ch.device.vendor_id + ":" + ch.device.product_id
            + " " + ch.device.description);

        if (correlator) {
            CorrEvent ce;
            ce.device_id = report.device_id; ce.timestamp_ms = report.timestamp_ms;
            ce.source = "usb"; ce.category = usb_change_str(ch.type);
            ce.severity = sev; ce.machine_ip = client_ip;
            ce.indicator = ch.device.vendor_id + ":" + ch.device.product_id;
            correlator->ingest(ce);
        }
        if (ir_engine && ch.type == UsbChangeType::WHITELIST_VIOLATION) {
            Incident inc;
            inc.device_id = report.device_id; inc.timestamp_ms = report.timestamp_ms;
            inc.machine_ip = client_ip; inc.source = "usb_monitor";
            inc.category = "whitelist_violation"; inc.severity = "high";
            inc.description = "Unauthorised USB device: "
                + ch.device.vendor_id + ":" + ch.device.product_id;
            ir_engine->report_incident(inc);
        }
    }
}
```

## 6. Register new REST routes (inside the Phase 7 REST block)

```cpp
// Phase 20: Authentication
rest_server->post("/api/auth/login", [](const HttpRequest& req) {
    if (!rbac) return HttpResponse::error(503, "RBAC disabled");
    auto body = parse_json_body(req.body);
    auto res = rbac->login(body["username"], body["password"]);
    if (!res.ok) return HttpResponse::error(401, res.error);
    JsonBuilder j;
    j.begin_object()
     .kv_str("token", res.token)
     .kv_str("role", res.role)
     .kv_str("tenant", res.tenant_id)
     .end_object();
    return HttpResponse::json(j.str());
}, false);

rest_server->get("/api/auth/me", [](const HttpRequest& req) {
    if (!rbac) return HttpResponse::error(503, "RBAC disabled");
    auto claims = rbac->verify_jwt(req.bearer_token());
    if (!claims.ok) return HttpResponse::error(401, "Invalid token");
    JsonBuilder j;
    j.begin_object()
     .kv_str("username", claims.username)
     .kv_str("role", claims.role)
     .kv_str("tenant", claims.tenant_id)
     .end_object();
    return HttpResponse::json(j.str());
}, false);

// Phase 18: Compliance report generation
rest_server->post("/api/reports/generate", [](const HttpRequest& req) {
    if (!reporter) return HttpResponse::error(503, "Reporting disabled");
    auto body = parse_json_body(req.body);
    ReportInputs in;
    in.framework = body["framework"];
    in.tenant_id = "default";
    in.window_start_ms = current_ms() - 30LL * 24 * 3600 * 1000;
    in.window_end_ms   = current_ms();
    if (pg_store) {
        in.threat_count = pg_store->count_table("threat_detections");
        in.ioc_count    = pg_store->count_table("ioc_matches");
        in.fim_count    = pg_store->count_table("fim_events");
    }
    auto r = reporter->generate(in);
    reporter->save(r);
    JsonBuilder j;
    j.begin_object()
     .kv_str("path", r.saved_path)
     .kv_str("url", "/reports/" + fs::path(r.saved_path).filename().string())
     .end_object();
    return HttpResponse::json(j.str());
});

// Phase 21: SOAR inbound callback
rest_server->post("/api/soar/callback", [](const HttpRequest& req) {
    if (!soar) return HttpResponse::error(503, "SOAR disabled");
    return soar->handle_inbound(req);
}, false);  // Auth is via HMAC header, not bearer token

// Phase 23: Hunt query
rest_server->post("/api/hunt", [](const HttpRequest& req) {
    if (!hunt) return HttpResponse::error(503, "Hunt DSL disabled");
    auto body = parse_json_body(req.body);
    auto result = hunt->execute(body["query"]);
    if (!result.ok) return HttpResponse::error(400, result.error);
    return HttpResponse::json(result.json);
});

// Phase 24: ML anomalies
rest_server->get("/api/anomalies", [clamp_limit](const HttpRequest& req) {
    int limit = clamp_limit(req.get_param_int("limit", 50));
    if (!pg_store) return HttpResponse::json("[]");
    return HttpResponse::json(pg_store->query_json(
        "SELECT device_id, timestamp_ms, machine_ip, sub_type AS detector, "
        "confidence AS score, severity, description "
        "FROM threat_detections WHERE category = 'ml_anomaly' "
        "ORDER BY received_at DESC", 0, nullptr, limit));
});
```

## 7. Extend `/api/stats` with new counters

Inside the existing stats handler, after the `net_inspector` block:

```cpp
if (sigma)   j.kv_int("sigma_hits",  static_cast<int64_t>(sigma->total_hits()));
if (rbac)    j.kv_int("rbac_users",  static_cast<int64_t>(rbac->user_count()));
if (soar)    j.kv_int("soar_sent",   static_cast<int64_t>(soar->total_sent()));
if (syslog_in) j.kv_int("syslog_received", static_cast<int64_t>(syslog_in->total_received()));
if (ml) {
    j.kv_int("ml_findings", static_cast<int64_t>(ml->total_findings()));
    j.kv_int("ml_observed", static_cast<int64_t>(ml->total_observed()));
    j.kv_bool("ml_trained", ml->is_trained());
}
```

## 8. Cleanup at shutdown

Extend the existing `.reset()` cleanup block:

```cpp
if (syslog_in)  syslog_in->stop();
if (soar)       soar->stop();
ml.reset();
hunt.reset();
syslog_out.reset();
syslog_in.reset();
soar.reset();
rbac.reset();
reporter.reset();
sigma.reset();
```

---

## Note on the Phase 25 WebSocket

The React UI expects `/ws/stream` to deliver JSON events. The existing
`rest_server.h` is HTTP/1.1 only. Adding WebSocket support is
straightforward:

1. Detect `Upgrade: websocket` in `parse_request()` and split the stream
   into an HTTP fork and a WS fork.
2. Implement RFC 6455 frame parsing (opcode, masking, payload length).
3. Keep a thread-safe broadcast list of connected sockets, wake them
   from the same places that currently log an event.

This is a meaningful amount of code — a few hundred lines — but it slots
cleanly on top of the existing `accept_loop()`. Until it lands, the SPA's
`useLiveStream()` hook will cleanly fall through and the UI continues to
work off the 15-second REST polling path.
