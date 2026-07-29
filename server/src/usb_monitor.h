// =============================================================================
// usb_monitor.h -- Phase 19 (v4.0.0) [SERVER SIDE]
// -----------------------------------------------------------------------------
// Server-side processor for `MSG_USB_REPORT (0x09)`. Clients emit this event
// whenever a USB mass-storage / HID / MTP device is attached or detached.
// The server:
//   1. Resolves the VID:PID against the global + per-tenant whitelist.
//   2. If unknown, fires an alert + correlates with any recent login event
//      to detect "physical badge-in + unknown USB within 60s" patterns.
//   3. Persists every event to the `usb_events` table.
//
// The client-side counterpart (client/src/usb_monitor.h) hooks
// WM_DEVICECHANGE on Windows and libudev on Linux.
// =============================================================================
#pragma once

#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>

namespace seahorse::usb {

struct UsbEvent {
    enum class Kind { Inserted, Removed };
    int         device_id = 0;
    Kind        kind = Kind::Inserted;
    std::string vendor_id;            // "0951"
    std::string product_id;           // "1666"
    std::string serial_number;        // best-effort; may be empty
    std::string product_name;         // "DataTraveler 3.0"
    std::string device_class;         // "Mass Storage" | "HID" | "MTP" | "Other"
    std::chrono::system_clock::time_point ts;
};

struct WhitelistEntry {
    std::string vid;
    std::string pid;
    std::string serial;               // empty = wildcard
    std::string tenant_id;            // "" = global
    std::string note;
};

class UsbMonitor {
public:
    void load_whitelist_csv(const std::string& path);
    void add_whitelist(const WhitelistEntry& e);
    void remove_whitelist(const std::string& vid, const std::string& pid);

    // Returns severity: "info" for a whitelisted device, "medium" for an
    // unknown mass-storage device, "high" if a device is inserted within the
    // post-login correlation window.
    std::string process_event(const UsbEvent& e, bool recent_login);

    // REST-facing getters.
    std::vector<UsbEvent> recent(int limit = 100) const;

private:
    mutable std::mutex     mtx_;
    std::vector<WhitelistEntry> whitelist_;
    std::vector<UsbEvent>  history_;
    std::size_t            max_history_ = 10000;

    bool is_whitelisted(const UsbEvent& e) const;
};

} // namespace seahorse::usb
