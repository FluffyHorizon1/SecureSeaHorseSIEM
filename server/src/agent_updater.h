// =============================================================================
// agent_updater.h -- Phase 17 (v3.5.0)
// -----------------------------------------------------------------------------
// Server-side piece of the signed auto-update channel. The client reports its
// installed version in the handshake; if the server has a newer signed build
// available for that platform the next `MSG_HEARTBEAT_PONG` (0x02) carries a
// `MSG_UPDATE_OFFER (0x08)` notification.
//
// Binaries are served over the existing mTLS channel — no new port. Each
// release is signed with the same CA used for the TLS cert infrastructure, so
// the agent verifies the signature before replacing its own binary.
//
// Roll-out is controlled by a tenant-scoped policy: percentage, ring, or
// manual. Phase 20 RBAC adds the UI for editing the policy.
// =============================================================================
#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace seahorse::updater {

struct ReleaseArtifact {
    std::string version;                    // semver "5.0.0"
    std::string platform;                   // linux-x86_64 | windows-x86_64 | linux-arm64
    std::string sha256_hex;                 // release integrity digest
    std::string signature_b64;              // RSA-PSS over sha256, base64
    std::size_t size_bytes = 0;
    std::string file_path;                  // server-local path to binary
};

struct RolloutPolicy {
    enum class Mode { Off, Canary, Percentage, All };
    Mode mode = Mode::Off;
    int  canary_device_ids_max = 5;         // first N device_ids get the build
    int  percentage = 10;                   // 0..100
};

class AgentUpdater {
public:
    // Load release manifest (JSON) at startup. Manifest lists every signed
    // artifact with its platform + sha256 + signature.
    bool load_manifest(const std::string& manifest_path);

    // Called from the message dispatcher: given the reporting device's version
    // and platform, returns the artifact we want it to upgrade to, or nullopt.
    std::optional<ReleaseArtifact> offer_for(int device_id,
                                             const std::string& current_version,
                                             const std::string& platform) const;

    // Stream a verified artifact over the existing TLS socket. The SSL* is
    // managed by the dispatcher — we only write frames.
    bool send_artifact(void* ssl, const ReleaseArtifact& art) const;

    // Roll-out controls surfaced at /api/updates/policy (RBAC-gated in v4.0+).
    void           set_policy(const RolloutPolicy& p);
    RolloutPolicy  policy() const { return policy_; }

private:
    RolloutPolicy policy_;
    std::unordered_map<std::string, ReleaseArtifact> by_platform_;   // platform → latest
    std::chrono::system_clock::time_point loaded_at_{};
};

} // namespace seahorse::updater
