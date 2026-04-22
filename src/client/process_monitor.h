#ifndef PROCESS_MONITOR_H
#define PROCESS_MONITOR_H

#ifndef NOMINMAX
#define NOMINMAX
#endif

// =============================================================================
// SecureSeaHorse SIEM -- Phase 11: Process Monitor (Client-Side)
// =============================================================================
// Provides:
//   - Process enumeration (PID, name, path, user, parent PID, CPU, memory)
//   - Snapshot comparison: detect new/terminated processes between scans
//   - Suspicious process detection: unsigned, high privilege, known bad names
//   - Text serialization for wire protocol (MSG_PROCESS_REPORT)
//   - Windows: CreateToolhelp32Snapshot / Linux: /proc filesystem
// =============================================================================

#include <string>
#include <vector>
#include <map>
#include <set>
#include <mutex>
#include <chrono>
#include <sstream>
#include <algorithm>
#include <cstdint>

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#pragma comment(lib, "psapi.lib")
#else
#include <dirent.h>
#include <unistd.h>
#include <fstream>
#include <cstring>
#endif

// =============================================================================
// PROCESS ENTRY
// =============================================================================
struct ProcessEntry {
    uint32_t    pid          = 0;
    uint32_t    ppid         = 0;     // Parent PID
    std::string name;                  // "svchost.exe", "sshd"
    std::string path;                  // Full executable path
    std::string user;                  // Owner username
    std::string cmdline;               // Command line arguments
    uint64_t    memory_bytes = 0;      // Working set / RSS
    double      cpu_percent  = 0.0;    // Approximate CPU usage
    int64_t     start_time   = 0;      // Process start timestamp (epoch ms)
    bool        is_elevated  = false;  // Running as admin/root
};

// =============================================================================
// PROCESS CHANGE
// =============================================================================
enum class ProcessChangeType {
    PROC_NEW,          // New process since last scan
    PROC_TERMINATED,   // Process ended since last scan
    PROC_SUSPICIOUS    // Flagged as suspicious
};

struct ProcessChange {
    ProcessChangeType type = ProcessChangeType::PROC_NEW;
    ProcessEntry      process;
    std::string       reason;   // Why flagged (for suspicious)
};

// =============================================================================
// PROCESS REPORT -- Sent over the wire
// =============================================================================
struct ProcessReport {
    int32_t     device_id     = 0;
    int64_t     timestamp_ms  = 0;
    uint32_t    total_count   = 0;
    std::vector<ProcessEntry> processes;
    std::vector<ProcessChange> changes;
};

// =============================================================================
// PROCESS MONITOR CONFIG
// =============================================================================
struct ProcessMonitorConfig {
    bool     enabled          = true;
    int      scan_interval_s  = 60;       // How often to scan (seconds)
    uint32_t max_processes    = 5000;      // Safety cap
    bool     track_cmdline    = true;      // Capture command line args
    bool     detect_suspicious = true;     // Enable heuristic detection
    std::vector<std::string> suspicious_names;   // Names to flag
    std::vector<std::string> watched_paths;      // Paths to watch closely
};

// =============================================================================
// SERIALIZATION: ProcessReport -> text for wire protocol
// =============================================================================
// Format:
//   PROC|<device_id>|<timestamp_ms>|<count>
//   <pid>|<ppid>|<name>|<path>|<user>|<memory>|<elevated>|<cmdline_b64>
//   ...
//   PROC_CHANGES|<change_count>
//   <type>|<pid>|<name>|<reason>
//   ...
//   PROC_END
// =============================================================================
inline std::string serialize_process_report(const ProcessReport& r) {
    std::ostringstream oss;
    oss << "PROC|" << r.device_id << "|" << r.timestamp_ms << "|" << r.processes.size() << "\n";

    for (const auto& p : r.processes) {
        oss << p.pid << "|" << p.ppid << "|" << p.name << "|" << p.path << "|"
            << p.user << "|" << p.memory_bytes << "|" << (p.is_elevated ? 1 : 0) << "|";
        // Base64-like encoding for cmdline (just escape pipes and newlines)
        std::string safe_cmd = p.cmdline;
        for (char& c : safe_cmd) {
            if (c == '|') c = ' ';
            if (c == '\n') c = ' ';
            if (c == '\r') c = ' ';
        }
        oss << safe_cmd << "\n";
    }

    oss << "PROC_CHANGES|" << r.changes.size() << "\n";
    for (const auto& c : r.changes) {
        std::string type_str;
        switch (c.type) {
            case ProcessChangeType::PROC_NEW:        type_str = "new"; break;
            case ProcessChangeType::PROC_TERMINATED: type_str = "terminated"; break;
            case ProcessChangeType::PROC_SUSPICIOUS: type_str = "suspicious"; break;
        }
        oss << type_str << "|" << c.process.pid << "|" << c.process.name << "|" << c.reason << "\n";
    }
    oss << "PROC_END\n";
    return oss.str();
}

inline ProcessReport deserialize_process_report(const std::string& data) {
    ProcessReport r;
    std::istringstream iss(data);
    std::string line;

    // Header: PROC|device_id|timestamp|count
    if (!std::getline(iss, line)) return r;
    if (line.substr(0, 5) != "PROC|") return r;
    {
        std::istringstream hdr(line.substr(5));
        std::string tok;
        if (std::getline(hdr, tok, '|')) r.device_id = std::stoi(tok);
        if (std::getline(hdr, tok, '|')) r.timestamp_ms = std::stoll(tok);
        if (std::getline(hdr, tok, '|')) r.total_count = std::stoul(tok);
    }

    // Process entries
    for (uint32_t i = 0; i < r.total_count && std::getline(iss, line); i++) {
        if (line.substr(0, 12) == "PROC_CHANGES") break;
        ProcessEntry p;
        std::istringstream row(line);
        std::string tok;
        if (std::getline(row, tok, '|')) p.pid = std::stoul(tok);
        if (std::getline(row, tok, '|')) p.ppid = std::stoul(tok);
        if (std::getline(row, tok, '|')) p.name = tok;
        if (std::getline(row, tok, '|')) p.path = tok;
        if (std::getline(row, tok, '|')) p.user = tok;
        if (std::getline(row, tok, '|')) p.memory_bytes = std::stoull(tok);
        if (std::getline(row, tok, '|')) p.is_elevated = (tok == "1");
        if (std::getline(row, tok, '|')) p.cmdline = tok;
        r.processes.push_back(std::move(p));
    }

    // Changes
    if (std::getline(iss, line)) {
        if (line.substr(0, 12) == "PROC_CHANGES") {
            uint32_t change_count = 0;
            auto bar = line.find('|');
            if (bar != std::string::npos)
                change_count = std::stoul(line.substr(bar + 1));
            for (uint32_t i = 0; i < change_count && std::getline(iss, line); i++) {
                if (line == "PROC_END") break;
                ProcessChange c;
                std::istringstream crow(line);
                std::string tok;
                if (std::getline(crow, tok, '|')) {
                    if (tok == "new") c.type = ProcessChangeType::PROC_NEW;
                    else if (tok == "terminated") c.type = ProcessChangeType::PROC_TERMINATED;
                    else c.type = ProcessChangeType::PROC_SUSPICIOUS;
                }
                if (std::getline(crow, tok, '|')) c.process.pid = std::stoul(tok);
                if (std::getline(crow, tok, '|')) c.process.name = tok;
                if (std::getline(crow, tok, '|')) c.reason = tok;
                r.changes.push_back(std::move(c));
            }
        }
    }

    return r;
}

// =============================================================================
// PROCESS SCANNER -- Platform-specific enumeration
// =============================================================================
class ProcessScanner {
public:
    explicit ProcessScanner(const ProcessMonitorConfig& cfg = {})
        : config_(cfg)
    {
        if (config_.suspicious_names.empty()) {
            config_.suspicious_names = {
                "mimikatz", "lazagne", "procdump", "psexec",
                "nc.exe", "ncat", "netcat", "nmap",
                "powershell_ise", "wscript", "cscript", "mshta",
                "certutil", "bitsadmin", "regsvr32", "rundll32",
                "whoami", "systeminfo", "tasklist", "net.exe",
                "cryptominer", "xmrig", "minerd", "cgminer"
            };
        }
    }

    // =========================================================================
    // SCAN: Enumerate all running processes
    // =========================================================================
    std::vector<ProcessEntry> scan() {
        std::vector<ProcessEntry> procs;

#ifdef _WIN32
        scan_windows(procs);
#else
        scan_linux(procs);
#endif

        // Safety cap
        if (procs.size() > config_.max_processes)
            procs.resize(config_.max_processes);

        return procs;
    }

    // =========================================================================
    // DIFF: Compare current scan to baseline, return changes
    // =========================================================================
    std::vector<ProcessChange> diff(const std::vector<ProcessEntry>& current) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<ProcessChange> changes;

        // Build current PID set
        std::map<uint32_t, const ProcessEntry*> current_map;
        for (const auto& p : current) current_map[p.pid] = &p;

        // Detect new processes
        for (const auto& p : current) {
            if (baseline_pids_.find(p.pid) == baseline_pids_.end()) {
                ProcessChange c;
                c.type = ProcessChangeType::PROC_NEW;
                c.process = p;
                c.reason = "New process started";
                changes.push_back(std::move(c));
            }
        }

        // Detect terminated processes
        for (const auto& kv : baseline_) {
            if (current_map.find(kv.first) == current_map.end()) {
                ProcessChange c;
                c.type = ProcessChangeType::PROC_TERMINATED;
                c.process = kv.second;
                c.reason = "Process terminated";
                changes.push_back(std::move(c));
            }
        }

        // Detect suspicious processes
        if (config_.detect_suspicious) {
            for (const auto& p : current) {
                std::string lower_name = p.name;
                std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);

                for (const auto& bad : config_.suspicious_names) {
                    std::string lower_bad = bad;
                    std::transform(lower_bad.begin(), lower_bad.end(), lower_bad.begin(), ::tolower);
                    if (lower_name.find(lower_bad) != std::string::npos) {
                        ProcessChange c;
                        c.type = ProcessChangeType::PROC_SUSPICIOUS;
                        c.process = p;
                        c.reason = "Matches suspicious name: " + bad;
                        changes.push_back(std::move(c));
                        break;
                    }
                }
            }
        }

        return changes;
    }

    // =========================================================================
    // UPDATE BASELINE
    // =========================================================================
    void update_baseline(const std::vector<ProcessEntry>& procs) {
        std::lock_guard<std::mutex> lock(mutex_);
        baseline_.clear();
        baseline_pids_.clear();
        for (const auto& p : procs) {
            baseline_[p.pid] = p;
            baseline_pids_.insert(p.pid);
        }
    }

    size_t baseline_count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return baseline_.size();
    }

private:
    ProcessMonitorConfig config_;
    mutable std::mutex mutex_;
    std::map<uint32_t, ProcessEntry> baseline_;
    std::set<uint32_t> baseline_pids_;

#ifdef _WIN32
    void scan_windows(std::vector<ProcessEntry>& procs) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return;

        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(pe);

        if (Process32FirstW(snap, &pe)) {
            do {
                ProcessEntry p;
                p.pid = pe.th32ProcessID;
                p.ppid = pe.th32ParentProcessID;

                // Convert wide name to narrow
                char narrow[260] = {};
                WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, narrow, sizeof(narrow), NULL, NULL);
                p.name = narrow;

                // Get full path and memory info
                HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
                if (hProc) {
                    // Full path
                    wchar_t wpath[MAX_PATH] = {};
                    DWORD pathLen = MAX_PATH;
                    if (QueryFullProcessImageNameW(hProc, 0, wpath, &pathLen)) {
                        char np[MAX_PATH] = {};
                        WideCharToMultiByte(CP_UTF8, 0, wpath, -1, np, sizeof(np), NULL, NULL);
                        p.path = np;
                    }

                    // Memory
                    PROCESS_MEMORY_COUNTERS pmc;
                    if (GetProcessMemoryInfo(hProc, &pmc, sizeof(pmc))) {
                        p.memory_bytes = pmc.WorkingSetSize;
                    }

                    // Elevation check
                    HANDLE hToken = NULL;
                    if (OpenProcessToken(hProc, TOKEN_QUERY, &hToken)) {
                        TOKEN_ELEVATION elev;
                        DWORD sz = sizeof(elev);
                        if (GetTokenInformation(hToken, TokenElevation, &elev, sizeof(elev), &sz)) {
                            p.is_elevated = (elev.TokenIsElevated != 0);
                        }
                        CloseHandle(hToken);
                    }

                    CloseHandle(hProc);
                }

                procs.push_back(std::move(p));
            } while (Process32NextW(snap, &pe));
        }

        CloseHandle(snap);
    }
#else
    void scan_linux(std::vector<ProcessEntry>& procs) {
        DIR* dir = opendir("/proc");
        if (!dir) return;

        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            // Only numeric directories (PIDs)
            bool is_pid = true;
            for (const char* c = entry->d_name; *c; c++) {
                if (*c < '0' || *c > '9') { is_pid = false; break; }
            }
            if (!is_pid) continue;

            uint32_t pid = std::stoul(entry->d_name);
            ProcessEntry p;
            p.pid = pid;

            std::string proc_dir = "/proc/" + std::string(entry->d_name);

            // Name and PPID from /proc/[pid]/stat
            {
                std::ifstream f(proc_dir + "/stat");
                if (f.is_open()) {
                    std::string stat_line;
                    std::getline(f, stat_line);
                    // Format: pid (comm) state ppid ...
                    auto lp = stat_line.find('(');
                    auto rp = stat_line.rfind(')');
                    if (lp != std::string::npos && rp != std::string::npos) {
                        p.name = stat_line.substr(lp + 1, rp - lp - 1);
                        std::istringstream rest(stat_line.substr(rp + 2));
                        std::string state;
                        rest >> state >> p.ppid;
                    }
                }
            }

            // Exe path from /proc/[pid]/exe symlink
            {
                char link[4096] = {};
                ssize_t len = readlink((proc_dir + "/exe").c_str(), link, sizeof(link) - 1);
                if (len > 0) {
                    link[len] = '\0';
                    p.path = link;
                }
            }

            // Cmdline from /proc/[pid]/cmdline
            if (config_.track_cmdline) {
                std::ifstream f(proc_dir + "/cmdline", std::ios::binary);
                if (f.is_open()) {
                    std::string cmd;
                    std::getline(f, cmd, '\0');
                    // Replace null bytes with spaces
                    std::string full;
                    char c;
                    f.seekg(0);
                    while (f.get(c)) {
                        full += (c == '\0') ? ' ' : c;
                    }
                    if (!full.empty()) p.cmdline = full;
                    else p.cmdline = cmd;
                }
            }

            // Memory from /proc/[pid]/status (VmRSS)
            {
                std::ifstream f(proc_dir + "/status");
                std::string line;
                while (std::getline(f, line)) {
                    if (line.substr(0, 6) == "VmRSS:") {
                        std::istringstream vs(line.substr(6));
                        uint64_t kb = 0;
                        vs >> kb;
                        p.memory_bytes = kb * 1024;
                        break;
                    }
                    if (line.substr(0, 4) == "Uid:") {
                        std::istringstream us(line.substr(4));
                        uint32_t uid = 0;
                        us >> uid;
                        p.is_elevated = (uid == 0);
                    }
                }
            }

            procs.push_back(std::move(p));
        }
        closedir(dir);
    }
#endif
};

#endif
