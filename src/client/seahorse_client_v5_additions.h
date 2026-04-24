#ifndef SEAHORSE_CLIENT_V5_ADDITIONS_H
#define SEAHORSE_CLIENT_V5_ADDITIONS_H

// =============================================================================
// SecureSeaHorse SIEM -- Client v5.0 additions (Phases 17 & 19)
// =============================================================================
// This header bundles the glue needed to add:
//   - Phase 17 self-protection (TamperDetector, AgentWatchdog, AutoUpdater)
//   - Phase 19 USB inventory scanner
// to the existing Phase 1-15 client.cpp with minimal surgery.
//
// Design notes
// ------------
// The existing client.cpp sends all frames from the main telemetry thread;
// there is no SSL send mutex. To preserve that single-writer invariant, the
// USB scanner runs on its own thread but only *produces* serialized USB
// frames into a thread-safe queue. The main loop drains the queue on each
// iteration and dispatches through the normal build_v2_header + send_exact_ssl
// path. This avoids introducing a send mutex that would otherwise need to
// wrap every send site in the existing file.
//
// Integration points in client.cpp: see CLIENT_INTEGRATION_PATCH.md.
// =============================================================================

#include <atomic>
#include <chrono>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "self_protection.h"
#include "usb_monitor.h"
#include "crypto_utils.h"

// Forward declaration of the helper that the existing client.cpp already
// provides (or provide this one if missing). We don't assume a specific name,
// so we expose a callback type that the integration glue code can install.
using SsSendFn = bool(*)(MsgType type, const std::string& payload);

// =============================================================================
// USB PRODUCER QUEUE -- thread-safe deque of serialized UsbReport payloads
// =============================================================================
class UsbReportQueue {
public:
    void push(std::string&& payload) {
        std::lock_guard<std::mutex> lk(m_);
        q_.emplace_back(std::move(payload));
    }
    bool pop(std::string& out) {
        std::lock_guard<std::mutex> lk(m_);
        if (q_.empty()) return false;
        out = std::move(q_.front());
        q_.pop_front();
        return true;
    }
    size_t size() const {
        std::lock_guard<std::mutex> lk(m_);
        return q_.size();
    }
private:
    mutable std::mutex m_;
    std::deque<std::string> q_;
};

// =============================================================================
// USB SCANNER THREAD -- runs on its own cadence, enqueues USB frames
// =============================================================================
// Start with start_usb_scanner_thread(...). The thread exits when the atomic
// `running` flag transitions to false; call stop_usb_scanner_thread() before
// tearing down the queue.
// =============================================================================
class ClientUsbMonitor {
public:
    struct Config {
        bool  enabled = true;
        int   scan_interval_s = 60;
        int32_t device_id = 0;
        std::vector<std::string> whitelist;
    };

    ClientUsbMonitor(const Config& cfg, UsbReportQueue& queue)
      : config_(cfg), queue_(queue)
    {
        UsbScannerConfig sc;
        sc.enabled = cfg.enabled;
        sc.scan_interval_s = cfg.scan_interval_s;
        sc.whitelist = cfg.whitelist;
        scanner_ = std::make_unique<UsbScanner>(sc);
    }

    ~ClientUsbMonitor() { stop(); }

    void start() {
        if (!config_.enabled || running_) return;
        running_ = true;
        thread_ = std::thread([this]() { loop(); });
    }

    void stop() {
        running_ = false;
        if (thread_.joinable()) thread_.join();
    }

    size_t total_scans() const { return total_scans_.load(); }
    size_t total_changes() const { return total_changes_.load(); }

private:
    Config config_;
    UsbReportQueue& queue_;
    std::unique_ptr<UsbScanner> scanner_;
    std::thread thread_;
    std::atomic<bool> running_{false};
    std::atomic<size_t> total_scans_{0};
    std::atomic<size_t> total_changes_{0};
    bool baseline_set_ = false;

    void loop() {
        // Initial baseline scan -- no changes are emitted on the first pass,
        // we just learn what was present at startup.
        {
            auto first = scanner_->scan();
            scanner_->update_baseline(first);
            baseline_set_ = true;
            total_scans_++;
        }
        while (running_) {
            for (int i = 0; i < config_.scan_interval_s && running_; i++) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
            if (!running_) break;

            auto current = scanner_->scan();
            auto changes = scanner_->diff(current);
            total_scans_++;

            if (!changes.empty()) {
                total_changes_ += changes.size();
                UsbReport r;
                r.device_id    = config_.device_id;
                r.timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
                r.devices = current;
                r.changes = changes;
                queue_.push(serialize_usb_report(r));
            }
            scanner_->update_baseline(current);
        }
    }
};

// =============================================================================
// SELF-PROTECTION BUNDLE -- Tamper + Watchdog + AutoUpdater
// =============================================================================
// Instantiate once in main() after config load. Call watchdog->mark_alive()
// at the top of every telemetry loop iteration. Call tamper->verify() in the
// diagnostics/heartbeat cadence; on CHANGED or MISSING, trigger fail-safe.
// =============================================================================
class ClientSelfProtection {
public:
    struct Config {
        bool enabled = true;
        // Tamper
        std::string tamper_baseline_path = "agent_baseline.json";
        std::vector<std::string> protected_paths;
        int  tamper_check_interval_s = 60;
        // Watchdog
        int  watchdog_liveness_ping_s = 30;
        int  watchdog_stall_threshold_s = 180;
        // AutoUpdater
        std::string update_pubkey_path = "update_pubkey.pem";
        std::string update_staging_dir = "update_staging";
        std::string current_version = "3.1.4";
    };

    using OnStallCallback = std::function<void()>;

    explicit ClientSelfProtection(const Config& cfg, OnStallCallback on_stall = nullptr)
      : config_(cfg), on_stall_(std::move(on_stall))
    {
        if (!cfg.enabled) return;

        TamperDetector::Config tc;
        tc.enabled = true;
        tc.baseline_path    = cfg.tamper_baseline_path;
        tc.protected_paths  = cfg.protected_paths;
        tc.check_interval_s = cfg.tamper_check_interval_s;
        tamper_ = std::make_unique<TamperDetector>(tc);

        AgentWatchdog::Config wc;
        wc.enabled = true;
        wc.liveness_ping_interval_s = cfg.watchdog_liveness_ping_s;
        wc.stall_threshold_s        = cfg.watchdog_stall_threshold_s;
        watchdog_ = std::make_unique<AgentWatchdog>(wc, on_stall_);

        AutoUpdater::Config uc;
        uc.enabled              = true;
        uc.public_key_pem_path  = cfg.update_pubkey_path;
        uc.staging_dir          = cfg.update_staging_dir;
        uc.current_version      = cfg.current_version;
        updater_ = std::make_unique<AutoUpdater>(uc);
    }

    void start() {
        if (watchdog_) watchdog_->start();
    }

    void stop() {
        if (watchdog_) watchdog_->stop();
    }

    void mark_alive() {
        if (watchdog_) watchdog_->mark_alive();
    }

    // Call on your diagnostics cadence. Returns true if baseline is intact.
    bool verify_tamper_baseline() {
        if (!tamper_) return true;
        auto r = tamper_->verify();
        if (r.status == TamperDetector::Status::CHANGED
         || r.status == TamperDetector::Status::MISSING) {
            last_tamper_path_   = r.offending_path;
            last_tamper_expect_ = r.expected_hash;
            last_tamper_actual_ = r.actual_hash;
            return false;
        }
        return true;
    }

    std::string last_tamper_path()   const { return last_tamper_path_;   }
    std::string last_tamper_expect() const { return last_tamper_expect_; }
    std::string last_tamper_actual() const { return last_tamper_actual_; }

    TamperDetector* tamper()   { return tamper_.get(); }
    AgentWatchdog*  watchdog() { return watchdog_.get(); }
    AutoUpdater*    updater()  { return updater_.get(); }

private:
    Config config_;
    OnStallCallback on_stall_;
    std::unique_ptr<TamperDetector> tamper_;
    std::unique_ptr<AgentWatchdog>  watchdog_;
    std::unique_ptr<AutoUpdater>    updater_;
    std::string last_tamper_path_;
    std::string last_tamper_expect_;
    std::string last_tamper_actual_;
};

// =============================================================================
// DRAIN HELPER -- call once per telemetry cycle to ship any queued USB frames
// =============================================================================
// Usage (inside the existing telemetry loop, after mark_alive() and before
// the main telemetry send):
//
//   drain_usb_queue(usb_queue, [&](const std::string& payload) {
//       // Build v2 header with MSG_USB_REPORT and send over SSL.
//       PacketHeaderV2 hdr = build_v2_header(
//           MSG_USB_REPORT,
//           static_cast<uint32_t>(payload.size()),
//           reinterpret_cast<const uint8_t*>(payload.data()),
//           hmac_key);
//       if (!send_exact_ssl(ssl, &hdr, sizeof(hdr))) return false;
//       if (!send_exact_ssl(ssl, payload.data(), static_cast<int>(payload.size())))
//           return false;
//       return true;
//   });
// =============================================================================
template <typename SendFn>
inline void drain_usb_queue(UsbReportQueue& q, SendFn&& send) {
    std::string payload;
    while (q.pop(payload)) {
        if (!send(payload)) {
            // Failed to send -- requeue for next attempt and stop draining now.
            q.push(std::move(payload));
            break;
        }
    }
}

#endif // SEAHORSE_CLIENT_V5_ADDITIONS_H
