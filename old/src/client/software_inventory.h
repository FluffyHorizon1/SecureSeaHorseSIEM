#ifndef SOFTWARE_INVENTORY_H
#define SOFTWARE_INVENTORY_H

#ifndef NOMINMAX
#define NOMINMAX
#endif

// =============================================================================
// SecureSeaHorse SIEM -- Phase 14: Software & Patch Inventory (Client-Side)
// =============================================================================
// Provides:
//   - Installed software enumeration with name, version, publisher
//   - Change detection: newly installed/removed software between scans
//   - Windows: Registry Uninstall keys (both 32/64-bit)
//   - Linux: dpkg, rpm, pacman, apk
// =============================================================================

#include <string>
#include <vector>
#include <map>
#include <set>
#include <mutex>
#include <sstream>
#include <algorithm>
#include <cstdint>

#ifdef _WIN32
#include <windows.h>
#else
#include <cstdio>
#include <array>
#include <memory>
#endif

// =============================================================================
// SOFTWARE ENTRY
// =============================================================================
struct SoftwareEntry {
    std::string name;
    std::string version;
    std::string publisher;
    std::string install_date;    // YYYYMMDD or ISO
    std::string install_location;
    uint64_t    size_bytes = 0;
};

// =============================================================================
// SOFTWARE CHANGE
// =============================================================================
enum class SoftwareChangeType { SW_INSTALLED, SW_REMOVED, SW_UPDATED };

struct SoftwareChange {
    SoftwareChangeType type = SoftwareChangeType::SW_INSTALLED;
    SoftwareEntry      software;
    std::string        old_version;  // For updates
};

// =============================================================================
// SOFTWARE REPORT
// =============================================================================
struct SoftwareReport {
    int32_t     device_id     = 0;
    int64_t     timestamp_ms  = 0;
    uint32_t    total_count   = 0;
    std::vector<SoftwareEntry>  software;
    std::vector<SoftwareChange> changes;
};

// =============================================================================
// SERIALIZATION
// =============================================================================
inline std::string serialize_software_report(const SoftwareReport& r) {
    std::ostringstream oss;
    oss << "SWRPT|" << r.device_id << "|" << r.timestamp_ms << "|"
        << r.software.size() << "|" << r.changes.size() << "\n";

    for (const auto& s : r.software) {
        // Escape pipes
        auto safe = [](std::string v) {
            for (char& c : v) { if (c == '|' || c == '\n') c = ' '; }
            return v;
        };
        oss << safe(s.name) << "|" << safe(s.version) << "|" << safe(s.publisher) << "|"
            << safe(s.install_date) << "|" << s.size_bytes << "\n";
    }

    oss << "SW_CHANGES\n";
    for (const auto& c : r.changes) {
        std::string type_str;
        switch (c.type) {
            case SoftwareChangeType::SW_INSTALLED: type_str = "installed"; break;
            case SoftwareChangeType::SW_REMOVED:   type_str = "removed"; break;
            case SoftwareChangeType::SW_UPDATED:   type_str = "updated"; break;
        }
        oss << type_str << "|" << c.software.name << "|" << c.software.version << "|"
            << c.old_version << "\n";
    }
    oss << "SW_END\n";
    return oss.str();
}

inline SoftwareReport deserialize_software_report(const std::string& data) {
    SoftwareReport r;
    std::istringstream iss(data);
    std::string line;

    if (!std::getline(iss, line) || line.substr(0, 6) != "SWRPT|") return r;
    {
        std::istringstream hdr(line.substr(6));
        std::string tok;
        if (std::getline(hdr, tok, '|')) r.device_id = std::stoi(tok);
        if (std::getline(hdr, tok, '|')) r.timestamp_ms = std::stoll(tok);
        uint32_t sw_count = 0;
        if (std::getline(hdr, tok, '|')) sw_count = std::stoul(tok);

        for (uint32_t i = 0; i < sw_count && std::getline(iss, line); i++) {
            if (line == "SW_CHANGES") break;
            SoftwareEntry s;
            std::istringstream row(line);
            std::string t;
            if (std::getline(row, t, '|')) s.name = t;
            if (std::getline(row, t, '|')) s.version = t;
            if (std::getline(row, t, '|')) s.publisher = t;
            if (std::getline(row, t, '|')) s.install_date = t;
            if (std::getline(row, t, '|')) s.size_bytes = std::stoull(t);
            r.software.push_back(std::move(s));
        }
    }

    while (std::getline(iss, line)) {
        if (line == "SW_END" || line == "SW_CHANGES") continue;
        SoftwareChange c;
        std::istringstream row(line);
        std::string t;
        if (std::getline(row, t, '|')) {
            if (t == "removed") c.type = SoftwareChangeType::SW_REMOVED;
            else if (t == "updated") c.type = SoftwareChangeType::SW_UPDATED;
        }
        if (std::getline(row, t, '|')) c.software.name = t;
        if (std::getline(row, t, '|')) c.software.version = t;
        if (std::getline(row, t, '|')) c.old_version = t;
        r.changes.push_back(std::move(c));
    }
    return r;
}

// =============================================================================
// SOFTWARE SCANNER
// =============================================================================
struct SoftwareScannerConfig {
    bool enabled           = true;
    int  scan_interval_s   = 3600;  // Hourly
    uint32_t max_entries   = 10000;
};

class SoftwareScanner {
public:
    explicit SoftwareScanner(const SoftwareScannerConfig& cfg = {})
        : config_(cfg) {}

    std::vector<SoftwareEntry> scan() {
        std::vector<SoftwareEntry> entries;
#ifdef _WIN32
        scan_windows_registry(entries, KEY_WOW64_64KEY);
        scan_windows_registry(entries, KEY_WOW64_32KEY);
#else
        scan_linux(entries);
#endif
        // Deduplicate by name+version
        std::set<std::string> seen;
        std::vector<SoftwareEntry> unique;
        for (auto& e : entries) {
            std::string key = e.name + "|" + e.version;
            if (seen.insert(key).second) {
                unique.push_back(std::move(e));
            }
        }

        if (unique.size() > config_.max_entries)
            unique.resize(config_.max_entries);

        return unique;
    }

    std::vector<SoftwareChange> diff(const std::vector<SoftwareEntry>& current) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<SoftwareChange> changes;

        // Build name->version maps
        std::map<std::string, std::string> cur_map, base_map;
        for (const auto& s : current) cur_map[s.name] = s.version;
        for (const auto& s : baseline_) base_map[s.name] = s.version;

        // Installed
        for (const auto& s : current) {
            auto it = base_map.find(s.name);
            if (it == base_map.end()) {
                SoftwareChange c;
                c.type = SoftwareChangeType::SW_INSTALLED;
                c.software = s;
                changes.push_back(std::move(c));
            } else if (it->second != s.version) {
                SoftwareChange c;
                c.type = SoftwareChangeType::SW_UPDATED;
                c.software = s;
                c.old_version = it->second;
                changes.push_back(std::move(c));
            }
        }

        // Removed
        for (const auto& s : baseline_) {
            if (cur_map.find(s.name) == cur_map.end()) {
                SoftwareChange c;
                c.type = SoftwareChangeType::SW_REMOVED;
                c.software = s;
                changes.push_back(std::move(c));
            }
        }

        return changes;
    }

    void update_baseline(const std::vector<SoftwareEntry>& entries) {
        std::lock_guard<std::mutex> lock(mutex_);
        baseline_ = entries;
    }

    size_t baseline_count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return baseline_.size();
    }

private:
    SoftwareScannerConfig config_;
    mutable std::mutex mutex_;
    std::vector<SoftwareEntry> baseline_;

#ifdef _WIN32
    void scan_windows_registry(std::vector<SoftwareEntry>& entries, REGSAM wow_flag) {
        const wchar_t* paths[] = {
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
            L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
        };

        for (const auto* path : paths) {
            HKEY hKey;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_READ | wow_flag, &hKey) != ERROR_SUCCESS)
                continue;

            DWORD index = 0;
            wchar_t sub_key[256];
            DWORD sub_key_len;

            while (true) {
                sub_key_len = 256;
                if (RegEnumKeyExW(hKey, index++, sub_key, &sub_key_len, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
                    break;

                HKEY hSubKey;
                if (RegOpenKeyExW(hKey, sub_key, 0, KEY_READ | wow_flag, &hSubKey) != ERROR_SUCCESS)
                    continue;

                SoftwareEntry e;
                e.name = read_reg_string(hSubKey, L"DisplayName");
                if (e.name.empty()) { RegCloseKey(hSubKey); continue; }

                e.version = read_reg_string(hSubKey, L"DisplayVersion");
                e.publisher = read_reg_string(hSubKey, L"Publisher");
                e.install_date = read_reg_string(hSubKey, L"InstallDate");
                e.install_location = read_reg_string(hSubKey, L"InstallLocation");

                DWORD size = 0, sz_sz = sizeof(size);
                if (RegQueryValueExW(hSubKey, L"EstimatedSize", NULL, NULL, (LPBYTE)&size, &sz_sz) == ERROR_SUCCESS) {
                    e.size_bytes = static_cast<uint64_t>(size) * 1024; // KB to bytes
                }

                RegCloseKey(hSubKey);
                entries.push_back(std::move(e));
            }
            RegCloseKey(hKey);
        }
    }

    static std::string read_reg_string(HKEY key, const wchar_t* name) {
        wchar_t buf[512] = {};
        DWORD buf_size = sizeof(buf);
        if (RegQueryValueExW(key, name, NULL, NULL, (LPBYTE)buf, &buf_size) == ERROR_SUCCESS) {
            char narrow[512] = {};
            WideCharToMultiByte(CP_UTF8, 0, buf, -1, narrow, sizeof(narrow), NULL, NULL);
            return narrow;
        }
        return "";
    }
#else
    void scan_linux(std::vector<SoftwareEntry>& entries) {
        // Try dpkg first (Debian/Ubuntu)
        if (try_exec("dpkg-query -W -f='${Package}|${Version}|${Installed-Size}\\n' 2>/dev/null", entries, "dpkg"))
            return;
        // Try rpm (RHEL/Fedora)
        if (try_exec("rpm -qa --queryformat '%{NAME}|%{VERSION}-%{RELEASE}|%{SIZE}\\n' 2>/dev/null", entries, "rpm"))
            return;
        // Try pacman (Arch)
        try_exec("pacman -Q 2>/dev/null | awk '{print $1\"|\"$2\"|0\"}'", entries, "pacman");
    }

    bool try_exec(const char* cmd, std::vector<SoftwareEntry>& entries, const char* source) {
        std::array<char, 4096> buffer;
        auto file_closer = [](FILE* f) { if (f) pclose(f); };
        std::unique_ptr<FILE, decltype(file_closer)> pipe(popen(cmd, "r"), file_closer);
        if (!pipe) return false;

        bool found_any = false;
        while (fgets(buffer.data(), buffer.size(), pipe.get())) {
            std::string line = buffer.data();
            line.erase(line.find_last_not_of("\n\r") + 1);
            if (line.empty()) continue;

            SoftwareEntry e;
            std::istringstream iss(line);
            std::string tok;
            if (std::getline(iss, tok, '|')) e.name = tok;
            if (std::getline(iss, tok, '|')) e.version = tok;
            if (std::getline(iss, tok, '|')) {
                try { e.size_bytes = std::stoull(tok); } catch (...) {}
                // dpkg reports in KB
                if (std::string(source) == "dpkg") e.size_bytes *= 1024;
            }
            e.publisher = source;
            if (!e.name.empty()) {
                entries.push_back(std::move(e));
                found_any = true;
            }
        }
        return found_any;
    }
#endif
};

#endif
