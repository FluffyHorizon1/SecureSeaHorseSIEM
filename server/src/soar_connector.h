// =============================================================================
// soar_connector.h -- Phase 21 (v4.0.0)
// -----------------------------------------------------------------------------
// Bidirectional bridge between SeaHorse's incident response engine and
// external SOAR platforms. Three stock connectors ship in-tree; the
// `Generic` connector is a thin shim that posts JSON to a webhook, so any
// SOAR with an inbound webhook can be used without code changes.
//
// Outbound: each IR action (block_ip, quarantine, run_script, ...) mirrors
// into the external SOAR as an enriched case.
// Inbound: a small HTTP listener (on the existing REST port, path
// `/api/soar/callback`) accepts actions queued externally — "please block
// this IP on every fleet member" — and routes them into the IR engine.
// =============================================================================
#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <optional>
#include <queue>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace seahorse::soar {

enum class Vendor { Generic, SplunkSoar, CortexXsoar, TheHive };

struct ConnectorConfig {
    Vendor       vendor = Vendor::Generic;
    std::string  base_url;
    std::string  api_key;
    std::string  tenant_id;           // SeaHorse tenant that owns this bridge
    bool         verify_tls = true;
    int          timeout_s = 10;
    int          retry_count = 3;
};

struct OutboundCase {
    std::string seahorse_event_id;    // primary key in our DB
    std::string title;
    std::string severity;
    std::string category;             // brute_force | c2 | fim | correlation | ...
    std::vector<std::string> mitre_ids;
    std::string json_body;            // full enrichment payload
    std::chrono::system_clock::time_point created_at;
};

struct InboundAction {
    std::string soar_case_id;
    std::string action;               // block_ip | quarantine | disable_user | ...
    std::string target;
    std::string requested_by;         // SOAR-side user/actor
    std::string reason;
};

using ActionSink = std::function<void(const InboundAction&)>;

class SoarConnector {
public:
    explicit SoarConnector(ConnectorConfig cfg, ActionSink sink)
        : cfg_(std::move(cfg)), sink_(std::move(sink)) {}

    // Non-blocking enqueue. A background thread drains the queue and retries
    // with exponential backoff on 5xx.
    void push_case(const OutboundCase& c);

    // Called by rest_server when an inbound `/api/soar/callback` POST
    // arrives. Body must be JSON; returns false if the body fails validation.
    bool accept_inbound(const std::string& json_body, const std::string& signature);

    // Lifecycle.
    void start();
    void stop();

private:
    ConnectorConfig            cfg_;
    ActionSink                 sink_;
    std::queue<OutboundCase>   out_queue_;
    std::mutex                 mtx_;
    std::condition_variable    cv_;
    std::thread                worker_;
    std::atomic<bool>          running_{false};

    bool post_case(const OutboundCase& c);
};

} // namespace seahorse::soar
