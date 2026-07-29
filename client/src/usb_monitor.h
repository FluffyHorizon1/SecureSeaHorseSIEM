// =============================================================================
// usb_monitor.h -- Phase 19 (v4.0.0) [CLIENT SIDE]
// -----------------------------------------------------------------------------
// Endpoint-side USB / peripheral insertion + removal detector. Reports every
// attach / detach event to the server via a new protocol message
// `MSG_USB_REPORT (0x09)`. The server (server/src/usb_monitor.h) checks the
// VID:PID / serial against a whitelist and fires a correlation signal if a
// suspicious device appears shortly after an interactive login.
//
// Platform back-ends:
//   - Windows: a hidden message-only window subscribed to `WM_DEVICECHANGE`
//     (`DBT_DEVICEARRIVAL` / `DBT_DEVICEREMOVECOMPLETE`). VID:PID pulled from
//     `SetupDiGetDeviceRegistryPropertyW` + the hardware-id string.
//   - Linux: `libudev_monitor` subscribed to the `usb` and `block` subsystems.
// =============================================================================
#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <thread>

namespace seahorse::client::usb {

struct UsbAttachEvent {
    enum class Kind { Attached, Detached };
    Kind        kind = Kind::Attached;
    std::string vendor_id;
    std::string product_id;
    std::string serial_number;
    std::string product_name;
    std::string device_class;       // "Mass Storage" | "HID" | "MTP" | ...
    std::chrono::system_clock::time_point ts;
};

using UsbCallback = std::function<void(const UsbAttachEvent&)>;

class UsbWatcher {
public:
    bool start(UsbCallback cb);
    void stop();

private:
    UsbCallback            cb_;
    std::thread            worker_;
    std::atomic<bool>      running_{false};

#ifdef _WIN32
    // HWND of the hidden message-only window.
    void* hwnd_ = nullptr;
    void  run_win32_loop();
#else
    int   udev_fd_ = -1;
    void  run_udev_loop();
#endif
};

} // namespace seahorse::client::usb
