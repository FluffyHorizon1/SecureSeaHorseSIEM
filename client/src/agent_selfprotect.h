// =============================================================================
// agent_selfprotect.h -- Phase 17 (v3.5.0) [CLIENT SIDE]
// -----------------------------------------------------------------------------
// Tamper-resistance for the agent itself. Three layers:
//   1. Watchdog -- a tiny companion process (seahorse-wd) that restarts the
//      agent if it exits, is killed, or misses its heartbeat file for >30 s.
//      The watchdog registers itself as a service dependency so stopping
//      `SeaHorseClient` without `--allow-stop` flips it into a panic-restart
//      loop. Legitimate uninstalls call `disable_watchdog` first.
//
//   2. Self-hash verify -- on startup, the agent SHA-256s its own binary
//      and compares against the baseline recorded at install time. If the
//      hash drifts, the agent refuses to start and logs a tamper event over
//      TLS to the server (using the stored cert + pinned fingerprint).
//
//   3. Signed update apply -- when the server offers a new build
//      (Phase 17 `MSG_UPDATE_OFFER`), the agent validates the RSA-PSS
//      signature against the bundled CA cert before atomically swapping
//      the on-disk binary (rename-over-ourselves on Linux, MoveFileEx
//      MOVEFILE_DELAY_UNTIL_REBOOT on Windows).
// =============================================================================
#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>

namespace seahorse::selfprotect {

struct TamperReport {
    enum class Reason { BinaryHashMismatch, ConfigUnexpectedWrite, WatchdogKilled, CertStoreModified };
    Reason      reason = Reason::BinaryHashMismatch;
    std::string detail;
    std::string observed_sha256;
    std::string expected_sha256;
};

class SelfProtect {
public:
    // Call early in main(). On failure returns false and the caller should
    // exit non-zero after emitting a tamper report.
    bool verify_self_hash(const std::filesystem::path& binary_path,
                          const std::filesystem::path& baseline_hash_file);

    // Writes the current heartbeat file (atomic rename + fsync) on each
    // main-loop tick. The watchdog process mmaps the same file and reboots
    // us if it stalls.
    void heartbeat_tick();

    // Atomic binary swap. `verify_signature` uses the bundled CA cert from
    // the TLS config to check an RSA-PSS SHA-256 signature.
    bool apply_signed_update(const std::filesystem::path& downloaded_binary,
                             const std::string& signature_b64,
                             const std::filesystem::path& ca_pem);

    // Emergency: reports a tamper event to the server over the existing TLS
    // channel, then terminates the agent with exit code 42.
    [[noreturn]] void report_and_exit(const TamperReport& r);

    // Watchdog lifecycle.
    static bool install_watchdog();
    static bool disable_watchdog();

private:
    std::filesystem::path heartbeat_path_;
};

} // namespace seahorse::selfprotect
