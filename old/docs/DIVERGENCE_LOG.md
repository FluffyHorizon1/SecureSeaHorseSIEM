# v5.0 Merge Divergence Log

This file is the audit trail of every point where the actual Phase 16-25 header APIs diverged from `docs/SERVER_INTEGRATION_SNIPPETS.md`, and how the merge adapted. You asked for adaptation to the real code, not a forced literal transcription of the snippets; everything below is how that got resolved.

Symbols:
- `[ADAPTED]` -- snippet was changed to match the real API (no runtime difference in intent).
- `[BLOCKER]` -- the snippet as written will not compile / will cause a collision and required a real decision.
- `[FALLBACK]` -- the snippet assumed an API that does not exist, so the merge ships a functional stand-in and flags what's needed to upgrade it later.

---

## 1. Phase 16 -- Sigma Rule Engine   [ADAPTED]

| Snippet | Real API |
| --- | --- |
| `SigmaEngineConfig sc;` | `SigmaEngine::Config sc;` |
| `std::vector<SigmaHit> hits = sigma->evaluate(ev);` | `void SigmaEngine::evaluate(const SigmaEvent&)` -- hits arrive via a callback registered at construction. |
| `SigmaEvent.message / .product / .service` | `SigmaEvent.source / .category / .fields[]` -- raw log goes into `fields["Message"]`. |
| `SigmaHit.rule_name / .confidence / .mitre_name / .mitre_tactic / .evidence` | `SigmaHit.rule_id / rule_title / severity / tags / mitre_id / description / matched_field / matched_value`. There is no `confidence`, `mitre_tactic`, or `mitre_name`. |

**Adaptation in merge:** At construction, installed a lambda that performs all the side effects the snippet did inline (DB insert via `insert_threat_detection`, structured log, route to `correlator` / `ir_engine`, push to SOAR on high+). `insert_threat_detection` is called with `confidence = 1.0` (Sigma doesn't emit one) and `mitre_tactic` left empty. `evidence` is synthesised as `matched_field + "=" + matched_value`.

**SigmaEvent feed on telemetry:** Populated with the full telemetry snapshot so rules can match on resource metrics and network deltas in addition to log content. Fields emitted per telemetry report:

- **Identity / log:** `Message`, `User`, `Computer`, `SourceIp`
- **Resource metrics:** `CpuPct`, `RamPct`, `DiskFreePct`, `RamTotalBytes`, `RamAvailBytes`, `DiskTotalBytes`, `DiskFreeBytes`
- **Network:** `NetBytesIn`, `NetBytesOut`, `NetDeltaIn`, `NetDeltaOut`
- **Auth / events:** `AuthFailures`, `EventCount`, `IntervalMs`

All numeric fields are emitted as decimal strings (Sigma's field matcher does string comparison; use the `|gt` / `|lt` modifiers in your rules for numeric thresholds). On process reports, feeds `Image`, `CommandLine`, `ProcessName`, `User` under `category="process_creation"`. On syslog inbound, feeds `Message`, `Computer`, `SourceIp`, `Service` under `category=<app_name>`.

## 2. Phase 17 -- Self-Protection   [ADAPTED]

APIs match fairly well. The only note is that the watchdog's `on_stall` callback is a constructor argument, not a `Config` field. Bundled in `ClientSelfProtection` wrapper class.

## 3. Phase 18 -- Report Generator   [ADAPTED]

| Snippet | Real API |
| --- | --- |
| `ReportGeneratorConfig rc;` | `ReportGenerator::Config rc;` |
| `r = reporter->generate(in);` | `Report r = reporter->render(in);` |
| `ReportInputs { threat_count, ioc_count, fim_count, window_start_ms, window_end_ms, tenant_id }` | `ReportInputs { threats_total, ioc_hits_total, fim_events_total, period_start_ms, period_end_ms, ... }`. No `tenant_id` field. |
| `r.saved_path` (field) | `reporter->save(r)` returns the path string directly. |

**Adaptation in `/api/reports/generate`:**
```cpp
Report r = reporter->render(in);
std::string saved = reporter->save(r);
std::string fn = std::filesystem::path(saved).filename().string();
```

Also added a reasonable `report_period` value ("Monthly") and `organization_name` from config since `ReportGenerator::Config` actually has those fields.

## 4. Phase 19 -- USB Monitor   [ADAPTED]

| Snippet | Real API |
| --- | --- |
| `UsbChangeType::INSERTED` / `REMOVED` / `WHITELIST_VIOLATION` | `UsbChangeType::USB_INSERTED` / `USB_REMOVED` / `USB_UNAUTHORIZED` |
| `UsbDeviceEntry.category` | `UsbDeviceEntry.device_class` |
| `UsbDeviceEntry.description` | `UsbDeviceEntry.product_name` |
| `usb_change_str()` helper | does not exist; inlined a local helper at the top of `server.cpp` and emitted the strings `"inserted"`, `"removed"`, `"unauthorized"` consistent with `serialize_usb_report()` for round-trip fidelity. |

Everything else (message-type dispatch, `deserialize_usb_report`, SOAR forwarding on unauthorized insertions) matches cleanly.

**Cross-platform note:** `usb_monitor.h` contains a `#pragma comment(lib, "setupapi.lib")` inside its `#ifdef _WIN32` block. On Windows the server build will now inherit a setupapi link dependency (it's already present for the client build). On Linux there's no new dependency -- the #ifdef excludes it cleanly.

## 5. Phase 20 -- RBAC   [ADAPTED]

| Snippet | Real API |
| --- | --- |
| `RbacConfig` | `RbacManager::Config` |
| `hmac_secret` | `secret` |
| `users_db_path` | `users_file` |
| `tenants_db` | `tenants_file` |
| `token_ttl_s` | `token_lifetime_s` |
| `rbac->login(username, password)` | `rbac->login(username, password, source_ip)` -- 3 args. The `source_ip` is plumbed through as `"rest_api"` for the merged login endpoint; if you want real client IPs here, you'll need to plumb `req.remote_addr` from the HttpRequest (see note in Section 13). |
| `LoginResult.ok / .token / .error` | `LoginResult.success / .jwt / .reason / .role` (Role enum) |
| `Claims.ok` | `Claims.valid` |
| `res.role` as string | `role_to_str(res.role)` helper call |

**Security hardening (above snippet):** RBAC refuses to start if `secret` is (a) empty, (b) contains the literal `"changeme"`, or (c) is shorter than 32 bytes. The snippet only checked (a) and (b). Short secrets defeat HMAC. The exit code is 1.

## 6. Phase 21 -- SOAR Connector   [ADAPTED + BLOCKER]

| Snippet | Real API |
| --- | --- |
| `SoarConfig` | `SoarConnector::Config` |
| `sc.backend_str = "cortex_xsoar"` | `sc.backend = SoarBackend::CORTEX_XSOAR` (enum). Merge code maps the string to the enum. |
| `sc.url` | `sc.base_url` |
| `sc.inbound_secret` | does not exist on the Config; the connector's inbound authentication is the responsibility of the HTTP layer above it. See note in Section 13. |
| `soar->enqueue(out)` | `soar->push(out)` |
| `soar->total_sent()` | `soar->sent()`. Also added `soar->failed()` for the dashboard. |
| `soar->handle_inbound(req)` | does not exist. Real API is `soar->receive(SoarInbound)` where `SoarInbound = { action, target, reason, request_id }`. |
| `SoarOutbound.category` | does not exist. Mapped to the `fields["category"]` map entry instead. Kept `type`, `source`, and `title` as structured fields. |

### [BLOCKER] -- `HttpResponse` collision

`soar_connector.h` declared a top-level `struct HttpResponse` in the global namespace (lines 72 and 95 of the original). `rest_server.h` also declares `HttpResponse` in the global namespace and is used throughout `server.cpp` (`HttpResponse::json(...)`, `HttpResponse::error(...)`, `HttpResponse::json_escape(...)`, `HttpResponse::html(...)`). Including both headers together would cause an unambiguous redefinition error.

**Resolution:** I patched `soar_connector.h` to rename its internal `HttpResponse` to `SoarHttpResponse` everywhere it appears (4 locations). The struct is only used as the return type of the internal `HttpPoster::post()` and `BasicHttpPoster::post()` methods; no caller outside the file touches it, so the rename has zero API impact on `server.cpp`. The patched file is shipped as `src/server/soar_connector.h` in this output and drops in over the original.

### SOAR inbound callback

Since `handle_inbound(HttpRequest)` does not exist, the merge parses the HTTP body in the REST route and constructs a `SoarInbound` manually:

```cpp
SoarInbound in;
in.action     = json_field(req.body, "action");
in.target     = json_field(req.body, "target");
in.reason     = json_field(req.body, "reason");
in.request_id = json_field(req.body, "request_id");
soar->receive(in);
```

HMAC verification on inbound callbacks is not performed in the merge because I could not confirm the `HttpRequest` API exposes a way to read arbitrary headers (see Section 13). If you want a signed-webhook guarantee, the cleanest path is to have your upstream SOAR platform sign the body and post the signature *inside the JSON payload* (e.g., as a `_sig` field), then add:

```cpp
std::string sig = json_field(req.body, "_sig");
// hmac(conf["soar_inbound_secret"], body_without_sig_field) == sig ?
```

That keeps the verification fully portable to whatever `HttpRequest` your `rest_server.h` actually offers.

## 7. Phase 22 -- Syslog I/O   [ADAPTED]

| Snippet | Real API |
| --- | --- |
| `SyslogListenerConfig` | `SyslogListener::Config` |
| `lc.udp_bind = "0.0.0.0:514"` (string) | `lc.udp_port = 514; lc.bind_address = "0.0.0.0"` (int + string). Merge splits `host:port` from config. |
| `lc.tcp_bind` (string) | same, via `tcp_port`. |
| `lc.on_event = [](...) { ... };` (Config field) | Constructor takes the handler as its **second argument**: `SyslogListener(lc, handler)`. |
| `SyslogEvent.timestamp_ms` | `SyslogEvent.received_ms` |
| `SyslogForwarderConfig.destination / .proto / .format` (all strings) | `SyslogForwarder::Config.host / .port / .use_tcp (bool) / .format (enum)`. Merge splits `host:port` from config and maps string format ("cef"/"leef"/"rfc5424") to `SyslogFormat` enum. |

## 8. Phase 23 -- Hunt DSL   [ADAPTED]

**The `HuntQueryEngine` class does not exist.** The real API is a free function:

```cpp
HuntResult compile_hunt(const std::string& query);
// where HuntResult { bool ok; std::string error; CompiledQuery compiled{sql, params}; }
```

There is no execution primitive inside the hunt_query header itself -- the compiler produces SQL + bound parameters. You confirmed that `pg_store->query_json(sql, n_params, params[], limit)` exists on the existing db_layer, so the `/api/hunt` route now:

1. Compiles the DSL with `compile_hunt()`.
2. Converts `compiled.params` (vector of std::string) into a `const char*` array.
3. Calls `pg_store->query_json(compiled.sql.c_str(), n_params, params_cstr.data(), limit)`.
4. Returns the JSON result directly.

If the DB is offline or `query_json` returns an empty string, the route falls back to returning the compiled SQL preview with `"executed":false`:

```json
{"ok":true,"executed":false,"sql":"SELECT ... WHERE ...","params":["p1","p2"]}
```

That way the operator still sees what the DSL compiled to and the endpoint never hard-fails. The `?limit=N` query param is honoured (clamped to 1..1000).

Gate flag: `g_hunt_enabled` is set to true iff `pg_store` is connected at startup. When false, `/api/hunt` returns 503.

## 9. Phase 24 -- ML Anomaly   [ADAPTED -- minor]

Mostly clean. The snippet called `j.kv_bool("ml_trained", ml->is_trained())` in the stats handler. I could not verify that `JsonBuilder` has a `kv_bool` method (only `kv_int` and `kv_str` are used elsewhere in `server.cpp`), so the merge emits `ml_trained` as an integer 0 or 1 via `kv_int`. If `kv_bool` exists in your `JsonBuilder`, change this line back to the boolean form.

The `AnomalyFinding` struct has `mitre_tactic` and `mitre_id`, so `insert_threat_detection` gets correct MITRE tagging.

## 10. Phase 25 -- Web UI WebSocket   [NOT MERGED]

The v5.0 package ships `src/webui/index.html` and the changelog notes a hard dependency on `/ws/stream` for live events. `rest_server.h` is HTTP/1.1 only. Adding a conformant RFC 6455 implementation is a few hundred lines of parser + broadcast logic that belongs in `rest_server.h` itself, not in a merge patch on `server.cpp`. The SPA will continue to work off the 15-second REST polling path.

## 11. /api/anomalies endpoint   [ADAPTED]

With `query_json` confirmed, the endpoint now issues a targeted SELECT:

```sql
SELECT device_id, timestamp_ms, machine_ip,
       sub_type AS detector, confidence AS score,
       severity, mitre_id, description, evidence
FROM threat_detections
WHERE category = 'ml_anomaly'
  [AND device_id = $1]     -- only if device_id query param provided
ORDER BY received_at DESC
```

Fallback: if `query_json` returns an empty string (DB blip, malformed query, etc.) the route falls back to `pg_store->query_threats(limit, device_id)` so the caller still gets recent threats. The UI can filter on `category == "ml_anomaly"` in the fallback path.

## 12. /api/auth/me via POST + body   [ADAPTED]

`HttpRequest::bearer_token()` (from snippet) is unverified. To avoid depending on an unknown API, `/api/auth/me` is exposed as POST with `{"token":"..."}` in the body. If your `HttpRequest` actually does expose `bearer_token()` or `get_header()`, feel free to re-expose this as GET -- the RBAC call is the same.

## 13. Unknown / unverified HttpRequest API

I could not confirm any of these from the existing server.cpp usage (only `req.get_param_int(...)` is present):

| Possible API | Where it'd be nice |
| --- | --- |
| `req.body` | Login / report gen / SOAR callback / hunt -- **assumed to exist** in the merge. If your `rest_server.h` uses a different name (e.g. `req.post_body()`), one grep+replace fixes it. |
| `req.get_header("Authorization")` | `/api/auth/me`, SOAR callback HMAC. **Not used** in the merge. |
| `req.bearer_token()` | `/api/auth/me` via GET. **Not used** in the merge. |
| `req.remote_addr` / `req.client_ip` | `login(source_ip)` currently passes `"rest_api"` as a placeholder. |

If any of these exist, the merge will work with a trivial edit. If none exist, the merge still works; some endpoints just use POST+body or placeholder IPs.

## 14. HttpResponse methods assumed

The merge uses `HttpResponse::json(std::string)`, `HttpResponse::html(std::string)`, `HttpResponse::error(int, const char*)`, and `HttpResponse::json_escape(std::string)`. All four are already used by the original `server.cpp` in this session, so they are confirmed.

## 15. JsonBuilder methods used

Confirmed in original server.cpp: `begin_object()`, `end_object()`, `kv_int(k, v)`, `kv_str(k, v)`, `str()`. **Not used** by the merge: `kv_bool`, fluent chaining (the merge uses statement form only to avoid chaining assumptions). `ml_trained` is emitted as int 0/1 for that reason.

## 16. Cleanup ordering

The merge extends the existing `.reset()` block in the correct subsystem-dependency order:
1. Stop async producers first (`syslog_in`, `soar`).
2. Reset front-end subsystems that may still queue to back-end subsystems (`ml`, `syslog_out`, `syslog_in`, `soar`, `rbac`, `reporter`, `sigma`).
3. Reset `pg_store` last because every Phase 16-25 feed lambda captures `pg_store` via the global `unique_ptr`.

`hunt` is not a unique_ptr because `HuntQueryEngine` does not exist; the `g_hunt_enabled` atomic bool is simply left to destruct with the process.

---

## Files produced

| File | What it is |
| --- | --- |
| `src/server/server.cpp` | Merged server, ~1100 lines. Drops in over existing v3.1.4 `server.cpp`. |
| `src/server/crypto_utils.h` | v3.1.4 file + `MSG_USB_REPORT = 0x08` appended to the MsgType enum. |
| `src/server/soar_connector.h` | Official v5.0 file with internal `HttpResponse` renamed to `SoarHttpResponse` (mechanical rename, 4 sites). |
| `src/client/crypto_utils.h` | v3.1.4 file + `MSG_USB_REPORT = 0x08`. Preserves your custom `host_to_network16/32` helpers. |
| `src/client/seahorse_client_v5_additions.h` | New drop-in header: `ClientSelfProtection`, `ClientUsbMonitor`, `UsbReportQueue`, `drain_usb_queue()`. |
| `CLIENT_INTEGRATION_PATCH.md` | 8-step edit list for `client.cpp` (~20 lines of insertion, 0 lines removed). |
| `DIVERGENCE_LOG.md` | This file. |

## Files I chose NOT to touch

- `src/server/sigma_engine.h`, `rbac.h`, `report_generator.h`, `syslog_io.h`, `hunt_query.h`, `ml_anomaly.h`, `src/client/self_protection.h`, `src/client/usb_monitor.h` -- used as-shipped.
- `src/server/rest_server.h`, `db_layer.h`, etc. -- v3.1.4 unchanged.
- `src/webui/index.html` -- Phase 25 UI is out of scope of a server merge.
