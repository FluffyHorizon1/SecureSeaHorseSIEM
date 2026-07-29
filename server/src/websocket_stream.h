// =============================================================================
// websocket_stream.h -- Phase 25 (v5.0.0)
// -----------------------------------------------------------------------------
// Minimal RFC 6455 WebSocket server used to push live events to the React
// dashboard. Shares the same bind port as the REST server (Phase 7): HTTP/1.1
// GET requests with `Upgrade: websocket` are handed off from rest_server.h
// into this module.
//
// Channels:
//   /ws/threats       -- Phase 4 traffic-classifier hits
//   /ws/ioc           -- Phase 5 IoC matches
//   /ws/fim           -- Phase 6 file-integrity events
//   /ws/events        -- Phase 2 security_events (regex + sigma)
//   /ws/correlations  -- Phase 15 correlation engine output
//   /ws/ir            -- Phase 8 incident-response actions
//
// Every socket is JWT-authenticated at the upgrade handshake (Phase 20).
// Per-client tenant scoping is applied server-side — the client cannot
// request events from a tenant it doesn't belong to.
// =============================================================================
#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace seahorse::ws {

enum class Channel { Threats, Ioc, Fim, Events, Correlations, Ir };

struct Subscription {
    std::string client_id;            // uuid
    std::string tenant_id;
    std::string user_id;
    std::unordered_set<Channel> channels;
};

class WebSocketServer {
public:
    // Broadcast to every subscriber of `ch` within `tenant_id`. JSON body is
    // caller-supplied and must already be serialized. Backpressure: a slow
    // client is marked for drop after 512 queued messages.
    void broadcast(const std::string& tenant_id, Channel ch,
                   const std::string& json_body);

    // Upgrade handoff from rest_server. Returns true on successful upgrade;
    // the caller must stop using `fd`.
    bool upgrade(int fd, const std::string& path,
                 const std::string& bearer_token);

    // Lifecycle.
    void start();
    void stop();

    // Stats for /api/ws/stats.
    struct Stats {
        std::size_t connected_clients = 0;
        std::size_t messages_sent = 0;
        std::size_t messages_dropped = 0;
        std::size_t bytes_out = 0;
    };
    Stats stats() const;

private:
    struct ClientSocket;               // impl-local
    std::unordered_map<std::string, std::shared_ptr<ClientSocket>> clients_;
    mutable std::mutex mtx_;
    std::atomic<std::size_t> sent_{0};
    std::atomic<std::size_t> dropped_{0};
    std::atomic<std::size_t> bytes_out_{0};
};

} // namespace seahorse::ws
