#ifndef USB_MONITOR_H
#define USB_MONITOR_H

#ifndef NOMINMAX
#define NOMINMAX
#endif

// =============================================================================
// SecureSeaHorse SIEM -- Phase 19: USB & Peripheral Monitor (Client-Side)
// =============================================================================
// Provides:
//   - Enumeration of currently connected USB / removable storage devices
//   - Insertion/removal detection between scans
//   - Whitelist enforcement: flag any VID:PID not in the allow list
//   - Classifies into storage, HID, network, composite based on class code
//   - Windows: SetupAPI (SetupDiGetClassDevs, SP_DEVINFO_DATA)
//   - Linux:   walks /sys/bus/usb/devices/* and /proc/mounts for removables
//
// Wire-protocol: MSG_USB_REPORT (0x08)
// =============================================================================

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#pragma comment(lib, "setupapi.lib")
#else
#include <dirent.h>
#include <fstream>
#endif

// =============================================================================
// USB DEVICE ENTRY
// =============================================================================
struct UsbDeviceEntry {
    std::string vendor_id;      // "04F9"
    std::string product_id;     // "0042"
    std::string manufacturer;
    std::string product_name;
    std::string serial;
    std::string device_class;   // "storage", "hid", "network", "composite", "audio", "other"
    std::string mount_point;    // For storage devices only
    uint64_t    capacity_bytes = 0;
    bool        is_removable = true;

    std::string key() const { return vendor_id + ":" + product_id + ":" + serial; }
};

// =============================================================================
// USB CHANGE
// =============================================================================
enum class UsbChangeType { USB_INSERTED, USB_REMOVED, USB_UNAUTHORIZED };

struct UsbChange {
    UsbChangeType  type = UsbChangeType::USB_INSERTED;
    UsbDeviceEntry device;
    std::string    reason;
};

// =============================================================================
// USB REPORT -- wire payload
// =============================================================================
struct UsbReport {
    int32_t device_id    = 0;
    int64_t timestamp_ms = 0;
    std::vector<UsbDeviceEntry> devices;
    std::vector<UsbChange>      changes;
};

// =============================================================================
// SERIALIZATION
// =============================================================================
inline std::string serialize_usb_report(const UsbReport& r) {
    auto safe = [](std::string v) {
        for (char& c : v) if (c == '|' || c == '\n') c = ' ';
        return v;
    };
    std::ostringstream oss;
    oss << "USB|" << r.device_id << "|" << r.timestamp_ms << "|"
        << r.devices.size() << "|" << r.changes.size() << "\n";
    for (const auto& d : r.devices) {
        oss << safe(d.vendor_id) << "|" << safe(d.product_id) << "|"
            << safe(d.manufacturer) << "|" << safe(d.product_name) << "|"
            << safe(d.serial) << "|" << safe(d.device_class) << "|"
            << safe(d.mount_point) << "|" << d.capacity_bytes << "|"
            << (d.is_removable ? 1 : 0) << "\n";
    }
    oss << "USB_CHANGES\n";
    for (const auto& c : r.changes) {
        std::string t = "inserted";
        if (c.type == UsbChangeType::USB_REMOVED) t = "removed";
        else if (c.type == UsbChangeType::USB_UNAUTHORIZED) t = "unauthorized";
        oss << t << "|" << safe(c.device.vendor_id) << "|" << safe(c.device.product_id)
            << "|" << safe(c.device.serial) << "|" << safe(c.device.product_name)
            << "|" << safe(c.reason) << "\n";
    }
    oss << "USB_END\n";
    return oss.str();
}

inline UsbReport deserialize_usb_report(const std::string& data) {
    UsbReport r;
    std::istringstream iss(data);
    std::string line;
    if (!std::getline(iss, line) || line.substr(0, 4) != "USB|") return r;
    {
        std::istringstream hdr(line.substr(4));
        std::string t;
        if (std::getline(hdr, t, '|')) r.device_id = std::stoi(t);
        if (std::getline(hdr, t, '|')) r.timestamp_ms = std::stoll(t);
        uint32_t dev_count = 0;
        if (std::getline(hdr, t, '|')) dev_count = std::stoul(t);
        for (uint32_t i = 0; i < dev_count && std::getline(iss, line); i++) {
            if (line == "USB_CHANGES") break;
            UsbDeviceEntry d;
            std::istringstream row(line);
            std::string x;
            if (std::getline(row, x, '|')) d.vendor_id = x;
            if (std::getline(row, x, '|')) d.product_id = x;
            if (std::getline(row, x, '|')) d.manufacturer = x;
            if (std::getline(row, x, '|')) d.product_name = x;
            if (std::getline(row, x, '|')) d.serial = x;
            if (std::getline(row, x, '|')) d.device_class = x;
            if (std::getline(row, x, '|')) d.mount_point = x;
            if (std::getline(row, x, '|')) { try { d.capacity_bytes = std::stoull(x); } catch (...) {} }
            if (std::getline(row, x, '|')) d.is_removable = (x == "1");
            r.devices.push_back(std::move(d));
        }
    }
    while (std::getline(iss, line)) {
        if (line == "USB_END" || line == "USB_CHANGES") continue;
        UsbChange ch;
        std::istringstream row(line);
        std::string t;
        if (std::getline(row, t, '|')) {
            if (t == "removed") ch.type = UsbChangeType::USB_REMOVED;
            else if (t == "unauthorized") ch.type = UsbChangeType::USB_UNAUTHORIZED;
        }
        if (std::getline(row, t, '|')) ch.device.vendor_id = t;
        if (std::getline(row, t, '|')) ch.device.product_id = t;
        if (std::getline(row, t, '|')) ch.device.serial = t;
        if (std::getline(row, t, '|')) ch.device.product_name = t;
        if (std::getline(row, t, '|')) ch.reason = t;
        r.changes.push_back(std::move(ch));
    }
    return r;
}

// =============================================================================
// USB SCANNER
// =============================================================================
struct UsbScannerConfig {
    bool enabled = true;
    int  scan_interval_s = 60;
    // Whitelist entries in "VID:PID" format ("04F9:0042") or "VID:PID:SERIAL"
    std::vector<std::string> whitelist;
};

class UsbScanner {
public:
    explicit UsbScanner(const UsbScannerConfig& cfg = {}) : config_(cfg) {}

    std::vector<UsbDeviceEntry> scan() {
        std::vector<UsbDeviceEntry> out;
#ifdef _WIN32
        scan_windows(out);
#else
        scan_linux(out);
#endif
        return out;
    }

    std::vector<UsbChange> diff(const std::vector<UsbDeviceEntry>& current) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<UsbChange> changes;
        std::set<std::string> cur_keys;
        for (const auto& d : current) cur_keys.insert(d.key());

        // Inserted
        for (const auto& d : current) {
            if (baseline_keys_.count(d.key()) == 0) {
                UsbChange ch; ch.type = UsbChangeType::USB_INSERTED;
                ch.device = d; ch.reason = "Device inserted";
                changes.push_back(ch);

                // Whitelist check
                if (!config_.whitelist.empty() && !is_whitelisted(d)) {
                    UsbChange unauth;
                    unauth.type = UsbChangeType::USB_UNAUTHORIZED;
                    unauth.device = d;
                    unauth.reason = "VID:PID not in whitelist: " + d.vendor_id + ":" + d.product_id;
                    changes.push_back(unauth);
                }
            }
        }
        // Removed
        for (const auto& kd : baseline_) {
            if (cur_keys.find(kd.first) == cur_keys.end()) {
                UsbChange ch; ch.type = UsbChangeType::USB_REMOVED;
                ch.device = kd.second; ch.reason = "Device removed";
                changes.push_back(ch);
            }
        }
        return changes;
    }

    void update_baseline(const std::vector<UsbDeviceEntry>& devs) {
        std::lock_guard<std::mutex> lock(mutex_);
        baseline_.clear();
        baseline_keys_.clear();
        for (const auto& d : devs) {
            baseline_[d.key()] = d;
            baseline_keys_.insert(d.key());
        }
    }

private:
    UsbScannerConfig config_;
    mutable std::mutex mutex_;
    std::map<std::string, UsbDeviceEntry> baseline_;
    std::set<std::string> baseline_keys_;

    bool is_whitelisted(const UsbDeviceEntry& d) const {
        std::string k_short = d.vendor_id + ":" + d.product_id;
        std::string k_full  = k_short + ":" + d.serial;
        for (auto entry : config_.whitelist) {
            std::transform(entry.begin(), entry.end(), entry.begin(), ::toupper);
            std::string short_upper = k_short;
            std::string full_upper = k_full;
            std::transform(short_upper.begin(), short_upper.end(), short_upper.begin(), ::toupper);
            std::transform(full_upper.begin(), full_upper.end(), full_upper.begin(), ::toupper);
            if (entry == short_upper || entry == full_upper) return true;
        }
        return false;
    }

#ifdef _WIN32
    static std::string extract_id(const std::string& hw_id, const std::string& key) {
        auto p = hw_id.find(key);
        if (p == std::string::npos) return "";
        p += key.size();
        std::string r;
        while (p < hw_id.size() && std::isxdigit(static_cast<unsigned char>(hw_id[p]))) r += hw_id[p++];
        return r;
    }

    void scan_windows(std::vector<UsbDeviceEntry>& out) {
        HDEVINFO set = SetupDiGetClassDevsA(nullptr, "USB", nullptr,
            DIGCF_ALLCLASSES | DIGCF_PRESENT);
        if (set == INVALID_HANDLE_VALUE) return;
        SP_DEVINFO_DATA info; info.cbSize = sizeof(info);
        for (DWORD i = 0; SetupDiEnumDeviceInfo(set, i, &info); i++) {
            char buf[512] = {};
            UsbDeviceEntry d;
            d.device_class = "other";
            if (SetupDiGetDeviceRegistryPropertyA(set, &info, SPDRP_HARDWAREID, nullptr,
                reinterpret_cast<PBYTE>(buf), sizeof(buf), nullptr)) {
                std::string hw_id = buf;
                d.vendor_id  = extract_id(hw_id, "VID_");
                d.product_id = extract_id(hw_id, "PID_");
            }
            char name[256] = {};
            if (SetupDiGetDeviceRegistryPropertyA(set, &info, SPDRP_DEVICEDESC, nullptr,
                reinterpret_cast<PBYTE>(name), sizeof(name), nullptr)) {
                d.product_name = name;
            }
            char mfg[256] = {};
            if (SetupDiGetDeviceRegistryPropertyA(set, &info, SPDRP_MFG, nullptr,
                reinterpret_cast<PBYTE>(mfg), sizeof(mfg), nullptr)) {
                d.manufacturer = mfg;
            }
            char cls[64] = {};
            if (SetupDiGetDeviceRegistryPropertyA(set, &info, SPDRP_CLASS, nullptr,
                reinterpret_cast<PBYTE>(cls), sizeof(cls), nullptr)) {
                std::string c = cls;
                std::transform(c.begin(), c.end(), c.begin(), ::tolower);
                if      (c.find("disk") != std::string::npos) d.device_class = "storage";
                else if (c.find("usbstor") != std::string::npos) d.device_class = "storage";
                else if (c.find("hid") != std::string::npos)  d.device_class = "hid";
                else if (c.find("net") != std::string::npos)  d.device_class = "network";
                else if (c.find("media") != std::string::npos) d.device_class = "audio";
                else if (!c.empty()) d.device_class = c;
            }
            if (!d.vendor_id.empty() && !d.product_id.empty()) out.push_back(std::move(d));
        }
        SetupDiDestroyDeviceInfoList(set);
    }
#else
    void scan_linux(std::vector<UsbDeviceEntry>& out) {
        const char* base = "/sys/bus/usb/devices";
        DIR* d = opendir(base);
        if (!d) return;
        struct dirent* e;
        while ((e = readdir(d))) {
            if (e->d_name[0] == '.') continue;
            std::string dir = std::string(base) + "/" + e->d_name;
            UsbDeviceEntry dev;
            dev.vendor_id  = read_sysfs(dir + "/idVendor");
            dev.product_id = read_sysfs(dir + "/idProduct");
            if (dev.vendor_id.empty() || dev.product_id.empty()) continue;
            std::transform(dev.vendor_id.begin(), dev.vendor_id.end(), dev.vendor_id.begin(), ::toupper);
            std::transform(dev.product_id.begin(), dev.product_id.end(), dev.product_id.begin(), ::toupper);
            dev.manufacturer = read_sysfs(dir + "/manufacturer");
            dev.product_name = read_sysfs(dir + "/product");
            dev.serial       = read_sysfs(dir + "/serial");
            std::string cls  = read_sysfs(dir + "/bDeviceClass");
            // USB class codes: 08=storage, 03=HID, 09=hub, 0E=video, 01=audio, 02=comm
            if (cls == "08") dev.device_class = "storage";
            else if (cls == "03") dev.device_class = "hid";
            else if (cls == "02") dev.device_class = "network";
            else if (cls == "01") dev.device_class = "audio";
            else if (cls == "0e") dev.device_class = "video";
            else if (cls == "00") dev.device_class = "composite";
            else if (cls.empty()) dev.device_class = "other";
            else dev.device_class = cls;
            out.push_back(std::move(dev));
        }
        closedir(d);
    }

    static std::string read_sysfs(const std::string& path) {
        std::ifstream f(path);
        if (!f.is_open()) return "";
        std::string line;
        std::getline(f, line);
        while (!line.empty() && (line.back() == '\n' || line.back() == '\r' || line.back() == ' ')) line.pop_back();
        return line;
    }
#endif
};

#endif
