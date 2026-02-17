#ifndef TRAFFIC_CLASSIFIER_H
#define TRAFFIC_CLASSIFIER_H

#ifndef NOMINMAX
#define NOMINMAX
#endif

// =============================================================================
// SecureSeaHorse SIEM — Phase 4: Traffic Classification & Exploit Detection
// =============================================================================
// Provides:
//   - 6 attack categories: DDoS, Port Scan, Brute Force, Exfiltration,
//     C2 Beaconing, Lateral Movement
//   - Adaptive baselines (EWMA) + configurable fixed thresholds
//   - MITRE ATT&CK technique ID tagging on every detection
//   - Confidence scoring (0.0–1.0) from statistical anomaly z-scores
//   - Log pattern analysis (regex) + network volume analysis (baselines)
//   - Persistence: detections stored in security_events table via PgStore
// =============================================================================

#include <string>
#include <vector>
#include <regex>
#include <cmath>
#include <map>
#include <mutex>
#include <sstream>
#include <algorithm>
#include <cstdint>

#include "baseline_tracker.h"
#include "mitre_map.h"
#include "regex_engine.h"   // Required: SecurityEvent struct definition

// =============================================================================
// THREAT DETECTION — Output from the classifier
// =============================================================================
struct ThreatDetection {
    // --- Classification ---
    std::string category;      // "ddos", "portscan", "bruteforce", "exfiltration",
                               // "c2_beaconing", "lateral_movement"
    std::string sub_type;      // Specific variant, e.g. "ddos_syn_flood"
    std::string severity;      // "low", "medium", "high", "critical"
    double      confidence;    // 0.0 – 1.0

    // --- MITRE ATT&CK ---
    std::string mitre_id;      // e.g. "T1498.001"
    std::string mitre_name;    // e.g. "Network Denial of Service: Direct Network Flood"
    std::string mitre_tactic;  // e.g. "Impact"

    // --- Evidence ---
    std::string description;   // Human-readable explanation
    std::string evidence;      // Raw data that triggered the detection

    // --- Context ---
    int32_t     device_id;
    std::string machine_ip;
    int64_t     timestamp_ms;
};

// =============================================================================
// CLASSIFIER CONFIG — Thresholds with configurable overrides
// =============================================================================
struct ClassifierConfig {
    // --- DDoS thresholds ---
    double ddos_inbound_z          = 3.0;    // Z-score for inbound spike
    double ddos_inbound_abs_bytes  = 100e6;  // Absolute: 100MB/interval = flag
    double ddos_cpu_spike_z        = 2.5;    // CPU spike concurrent with network

    // --- Port Scan thresholds ---
    int    portscan_conn_refused_min = 10;   // Min "connection refused" in one log chunk
    int    portscan_reset_min        = 8;    // Min RST indicators

    // --- Brute Force thresholds ---
    int    brute_standard_min        = 5;    // Auth failures per interval
    int    brute_spray_unique_users  = 3;    // Distinct usernames = spray
    double brute_rate_z              = 2.5;  // Z-score vs baseline failure rate

    // --- Exfiltration thresholds ---
    double exfil_outbound_z          = 3.0;  // Z-score for outbound spike
    double exfil_outbound_abs_bytes  = 50e6; // Absolute: 50MB/interval outbound
    double exfil_ratio_z             = 2.5;  // In/out ratio anomaly

    // --- C2 Beaconing thresholds ---
    double c2_interval_jitter_max    = 0.15; // Max CoV (coefficient of variation)
                                              // of report intervals to flag beaconing
    int    c2_min_samples            = 10;   // Min intervals before checking

    // --- Lateral Movement thresholds ---
    int    lateral_internal_scan_min = 5;    // Min internal scan indicators in logs
    int    lateral_smb_rdp_min       = 3;    // Min SMB/RDP lateral indicators

    // --- Global ---
    bool   enabled                  = true;
};

// =============================================================================
// TRAFFIC CLASSIFIER
// =============================================================================
class TrafficClassifier {
public:
    explicit TrafficClassifier(const ClassifierConfig& cfg = {},
                                const BaselineTracker::Config& bl_cfg = {})
        : config_(cfg), baselines_(bl_cfg)
    {
        compile_patterns();
    }

    // =========================================================================
    // CLASSIFY — Main entry point
    // =========================================================================
    // Called once per telemetry report with:
    //   - Raw telemetry fields (network, CPU, etc.)
    //   - Security events already found by RegexEngine
    //   - The raw log chunk for additional pattern analysis
    // Returns all detected threats for this report.
    // =========================================================================
    std::vector<ThreatDetection> classify(
        int32_t device_id,
        int64_t timestamp_ms,
        const std::string& machine_ip,
        uint64_t net_bytes_in,
        uint64_t net_bytes_out,
        double cpu_pct,
        double ram_pct,
        const std::string& raw_log,
        const std::vector<SecurityEvent>& sec_events)
    {
        if (!config_.enabled) return {};

        std::vector<ThreatDetection> threats;

        // --- Count event categories from regex engine output ---
        int auth_failures = 0;
        int total_events  = static_cast<int>(sec_events.size());
        for (const auto& ev : sec_events) {
            if (ev.category == "auth_failure") auth_failures++;
        }

        // --- Update device baseline ---
        DeviceBaseline& bl = baselines_.update(
            device_id, timestamp_ms,
            net_bytes_in, net_bytes_out,
            cpu_pct, ram_pct,
            auth_failures, total_events);

        // --- Run all 6 detection modules ---
        detect_ddos(threats, device_id, timestamp_ms, machine_ip, bl, raw_log, cpu_pct);
        detect_portscan(threats, device_id, timestamp_ms, machine_ip, bl, raw_log);
        detect_bruteforce(threats, device_id, timestamp_ms, machine_ip, bl, raw_log, sec_events, auth_failures);
        detect_exfiltration(threats, device_id, timestamp_ms, machine_ip, bl, raw_log);
        detect_c2_beaconing(threats, device_id, timestamp_ms, machine_ip, bl, raw_log);
        detect_lateral_movement(threats, device_id, timestamp_ms, machine_ip, bl, raw_log);

        // --- Tag all detections with MITRE ATT&CK ---
        for (auto& t : threats) {
            MitreTechnique mt = lookup_mitre(t.sub_type);
            t.mitre_id     = mt.id;
            t.mitre_name   = mt.name;
            t.mitre_tactic = mt.tactic;
        }

        return threats;
    }

    // --- Diagnostics ---
    size_t baselined_devices() const { return baselines_.device_count(); }
    const ClassifierConfig& config() const { return config_; }

private:
    ClassifierConfig config_;
    BaselineTracker  baselines_;

    // Compiled regex patterns for log-based detection
    struct Patterns {
        // DDoS
        std::regex syn_flood;
        std::regex conn_table_full;
        std::regex amplification;

        // Port scan
        std::regex conn_refused;
        std::regex conn_reset;
        std::regex nmap_scan;
        std::regex service_probe;

        // C2 beaconing
        std::regex c2_cobalt_strike;
        std::regex c2_meterpreter;
        std::regex c2_beacon_pattern;
        std::regex dns_txt_query;

        // Lateral movement
        std::regex internal_scan;
        std::regex pass_the_hash;
        std::regex pass_the_ticket;
        std::regex smb_lateral;
        std::regex rdp_lateral;
        std::regex wmi_exec;
        std::regex psexec;

        // Exfiltration
        std::regex dns_tunnel;
        std::regex large_upload;

        // Brute force (enhanced)
        std::regex credential_stuffing;
        std::regex password_spray;
    } pat_;

    void compile_patterns() {
        auto rx = [](const char* pattern) -> std::regex {
            try {
                return std::regex(pattern,
                    std::regex_constants::ECMAScript |
                    std::regex_constants::icase |
                    std::regex_constants::optimize);
            } catch (...) {
                return std::regex("(?!)");
            }
        };

        // --- DDoS ---
        pat_.syn_flood       = rx(R"(syn flood|syncookies|possible syn flooding|tcp.*backlog)");
        pat_.conn_table_full = rx(R"(connection table full|nf_conntrack.*table full|too many open)");
        pat_.amplification   = rx(R"(amplification|reflected.*attack|dns.*amplif|ntp.*monlist|ssdp.*reflect)");

        // --- Port Scan ---
        pat_.conn_refused    = rx(R"(connection refused|refused connect|ECONNREFUSED)");
        pat_.conn_reset      = rx(R"(connection reset by peer|RST|reset by [\d.]+)");
        pat_.nmap_scan       = rx(R"(nmap|masscan|zmap|port scan detected|portscan)");
        pat_.service_probe   = rx(R"(service probe|banner grab|version detection|fingerprint)");

        // --- C2 Beaconing ---
        pat_.c2_cobalt_strike = rx(R"(cobalt\s*strike|beacon\.dll|cobaltstrike)");
        pat_.c2_meterpreter   = rx(R"(meterpreter|reverse.*shell|reverse_tcp|reverse_https)");
        pat_.c2_beacon_pattern = rx(R"(callback.*interval|beacon.*sleep|heartbeat.*c2|check.in.*interval)");
        pat_.dns_txt_query    = rx(R"(dns.*txt\s*query|type65|iodine|dnscat|dns2tcp)");

        // --- Lateral Movement ---
        pat_.internal_scan  = rx(R"(scanning\s+(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)|internal\s+scan|subnet\s+scan)");
        pat_.pass_the_hash  = rx(R"(pass.the.hash|pth\s+attack|ntlm\s+relay|sekurlsa|mimikatz.*hash)");
        pat_.pass_the_ticket = rx(R"(pass.the.ticket|kerberos.*ticket.*export|golden\s+ticket|silver\s+ticket)");
        pat_.smb_lateral    = rx(R"(smb.*lateral|admin\$|ipc\$.*lateral|psexec.*smb|smbexec)");
        pat_.rdp_lateral    = rx(R"(rdp.*lateral|mstsc.*internal|remote desktop.*(10\.|172\.|192\.168))");
        pat_.wmi_exec       = rx(R"(wmi(c|exec)|win32_process.*create|wmiprvse.*spawn)");
        pat_.psexec         = rx(R"(psexec|paexec|remcom|smbexec)");

        // --- Exfiltration ---
        pat_.dns_tunnel     = rx(R"(dns\s*tunnel|iodine|dnscat|dns2tcp|unusual\s+dns.*length|encoded.*subdomain)");
        pat_.large_upload   = rx(R"(large\s+upload|bulk\s+transfer|data\s+staging|exfil)");

        // --- Brute Force (enhanced) ---
        pat_.credential_stuffing = rx(R"(credential\s*stuff|multiple\s+accounts?\s+failed|bulk\s+login\s+attempt)");
        pat_.password_spray      = rx(R"(password\s*spray|single\s+password.*multiple\s+account|spray\s+attack)");
    }

    // --- Helper: count regex matches in log text ---
    int count_matches(const std::string& text, const std::regex& pattern) const {
        if (text.empty()) return 0;
        auto begin = std::sregex_iterator(text.begin(), text.end(), pattern);
        auto end   = std::sregex_iterator();
        return static_cast<int>(std::distance(begin, end));
    }

    // --- Helper: create a ThreatDetection with common fields ---
    ThreatDetection make_threat(const std::string& category,
                                 const std::string& sub_type,
                                 const std::string& severity,
                                 double confidence,
                                 int32_t device_id,
                                 int64_t timestamp_ms,
                                 const std::string& machine_ip,
                                 const std::string& desc,
                                 const std::string& evidence) const
    {
        ThreatDetection t;
        t.category     = category;
        t.sub_type     = sub_type;
        t.severity     = severity;
        t.confidence   = std::min(std::max(confidence, 0.0), 1.0);
        t.device_id    = device_id;
        t.machine_ip   = machine_ip;
        t.timestamp_ms = timestamp_ms;
        t.description  = desc;
        t.evidence     = evidence.substr(0, 512);
        return t;
    }

    // =========================================================================
    // 1. DDoS DETECTION
    // =========================================================================
    void detect_ddos(std::vector<ThreatDetection>& threats,
                     int32_t dev, int64_t ts, const std::string& ip,
                     const DeviceBaseline& bl, const std::string& log,
                     double cpu_pct)
    {
        // --- Statistical: inbound volume spike ---
        if (bl.net_bytes_in_rate.is_ready()) {
            double z = bl.net_bytes_in_rate.z_score();
            double abs_val = bl.net_bytes_in_rate.last_value;

            if (z >= config_.ddos_inbound_z || abs_val >= config_.ddos_inbound_abs_bytes) {
                double conf = baselines_.z_to_confidence(z);
                if (abs_val >= config_.ddos_inbound_abs_bytes) conf = std::max(conf, 0.7);

                // Concurrent CPU spike increases confidence
                double cpu_z = bl.cpu_usage.z_score();
                if (cpu_z >= config_.ddos_cpu_spike_z) conf = std::min(conf + 0.15, 0.95);

                std::string sev = (conf >= 0.7) ? "critical" : "high";
                std::stringstream evidence;
                evidence << "inbound_delta=" << std::fixed << std::setprecision(0) << abs_val
                         << "B z=" << std::setprecision(2) << z
                         << " mean=" << std::setprecision(0) << bl.net_bytes_in_rate.mean
                         << " cpu=" << std::setprecision(1) << cpu_pct << "%";

                threats.push_back(make_threat(
                    "ddos", "ddos_volumetric", sev, conf, dev, ts, ip,
                    "Anomalous inbound traffic volume — possible volumetric DDoS",
                    evidence.str()));
            }
        }

        // --- Log-based: SYN flood ---
        if (count_matches(log, pat_.syn_flood) > 0) {
            threats.push_back(make_threat(
                "ddos", "ddos_syn_flood", "critical", 0.85, dev, ts, ip,
                "SYN flood indicators detected in system logs",
                log.substr(0, 256)));
        }

        // --- Log-based: Connection table full ---
        if (count_matches(log, pat_.conn_table_full) > 0) {
            threats.push_back(make_threat(
                "ddos", "ddos_application_layer", "high", 0.75, dev, ts, ip,
                "Connection table exhaustion — possible application-layer DDoS",
                log.substr(0, 256)));
        }

        // --- Log-based: Amplification ---
        if (count_matches(log, pat_.amplification) > 0) {
            threats.push_back(make_threat(
                "ddos", "ddos_amplification", "critical", 0.8, dev, ts, ip,
                "Amplification/reflection attack indicators in logs",
                log.substr(0, 256)));
        }
    }

    // =========================================================================
    // 2. PORT SCAN DETECTION
    // =========================================================================
    void detect_portscan(std::vector<ThreatDetection>& threats,
                         int32_t dev, int64_t ts, const std::string& ip,
                         const DeviceBaseline& bl, const std::string& log)
    {
        int refused = count_matches(log, pat_.conn_refused);
        int resets  = count_matches(log, pat_.conn_reset);
        int nmap    = count_matches(log, pat_.nmap_scan);
        int probes  = count_matches(log, pat_.service_probe);

        // Direct tool signature
        if (nmap > 0) {
            threats.push_back(make_threat(
                "portscan", "portscan_sequential", "high", 0.9, dev, ts, ip,
                "Port scanning tool signature detected (nmap/masscan/zmap)",
                log.substr(0, 256)));
        }

        // High refused connection count → sequential scan
        if (refused >= config_.portscan_conn_refused_min) {
            double conf = std::min(0.5 + (refused - config_.portscan_conn_refused_min) * 0.05, 0.9);
            threats.push_back(make_threat(
                "portscan", "portscan_sequential", "medium", conf, dev, ts, ip,
                "High rate of refused connections (" + std::to_string(refused) + ") — possible port scan",
                "connection_refused_count=" + std::to_string(refused)));
        }

        // Reset flood → stealth scan (SYN/FIN/XMAS)
        if (resets >= config_.portscan_reset_min) {
            double conf = std::min(0.5 + (resets - config_.portscan_reset_min) * 0.05, 0.85);
            threats.push_back(make_threat(
                "portscan", "portscan_stealth", "medium", conf, dev, ts, ip,
                "High RST rate (" + std::to_string(resets) + ") — possible stealth scan",
                "reset_count=" + std::to_string(resets)));
        }

        // Service probing / version detection
        if (probes > 0) {
            threats.push_back(make_threat(
                "portscan", "portscan_service_enum", "medium", 0.7, dev, ts, ip,
                "Service enumeration / banner grabbing detected",
                log.substr(0, 256)));
        }
    }

    // =========================================================================
    // 3. BRUTE FORCE DETECTION
    // =========================================================================
    void detect_bruteforce(std::vector<ThreatDetection>& threats,
                           int32_t dev, int64_t ts, const std::string& ip,
                           const DeviceBaseline& bl, const std::string& log,
                           const std::vector<SecurityEvent>& sec_events,
                           int auth_failures)
    {
        // --- Statistical: auth failure rate anomaly ---
        if (bl.auth_failure_rate.is_ready() && auth_failures > 0) {
            double z = bl.auth_failure_rate.z_score();
            if (z >= config_.brute_rate_z && auth_failures >= config_.brute_standard_min) {
                double conf = baselines_.z_to_confidence(z);

                // Determine sub-type from log patterns
                std::string sub = "bruteforce_standard";
                if (count_matches(log, pat_.password_spray) > 0) {
                    sub = "bruteforce_password_spray";
                } else if (count_matches(log, pat_.credential_stuffing) > 0) {
                    sub = "bruteforce_credential_stuffing";
                } else {
                    // Heuristic: count distinct usernames in auth_failure events
                    std::map<std::string, int> user_counts;
                    for (const auto& ev : sec_events) {
                        if (ev.category == "auth_failure") {
                            // Try to extract username from matched text
                            std::smatch m;
                            std::regex user_rx(R"(for\s+(\S+)\s+from)",
                                std::regex_constants::icase);
                            if (std::regex_search(ev.matched_text, m, user_rx)) {
                                user_counts[m[1].str()]++;
                            }
                        }
                    }

                    if (static_cast<int>(user_counts.size()) >= config_.brute_spray_unique_users
                        && user_counts.size() > 1) {
                        // Many different usernames → password spray
                        sub = "bruteforce_password_spray";
                    }
                }

                std::stringstream evidence;
                evidence << "auth_failures=" << auth_failures
                         << " z=" << std::fixed << std::setprecision(2) << z
                         << " baseline_mean=" << std::setprecision(1) << bl.auth_failure_rate.mean;

                threats.push_back(make_threat(
                    "bruteforce", sub,
                    (auth_failures >= config_.brute_standard_min * 2) ? "critical" : "high",
                    conf, dev, ts, ip,
                    "Brute force attack detected — auth failure rate anomaly",
                    evidence.str()));
            }
        }

        // --- Absolute threshold (no baseline needed) ---
        if (auth_failures >= config_.brute_standard_min && !bl.auth_failure_rate.is_ready()) {
            threats.push_back(make_threat(
                "bruteforce", "bruteforce_standard", "high", 0.6, dev, ts, ip,
                "High auth failure count (" + std::to_string(auth_failures)
                + ") — possible brute force (baseline warming up)",
                "auth_failures=" + std::to_string(auth_failures)));
        }
    }

    // =========================================================================
    // 4. DATA EXFILTRATION DETECTION
    // =========================================================================
    void detect_exfiltration(std::vector<ThreatDetection>& threats,
                             int32_t dev, int64_t ts, const std::string& ip,
                             const DeviceBaseline& bl, const std::string& log)
    {
        // --- Statistical: outbound volume spike ---
        if (bl.net_bytes_out_rate.is_ready()) {
            double z = bl.net_bytes_out_rate.z_score();
            double abs_val = bl.net_bytes_out_rate.last_value;

            if (z >= config_.exfil_outbound_z || abs_val >= config_.exfil_outbound_abs_bytes) {
                double conf = baselines_.z_to_confidence(z);
                if (abs_val >= config_.exfil_outbound_abs_bytes) conf = std::max(conf, 0.65);

                std::stringstream evidence;
                evidence << "outbound_delta=" << std::fixed << std::setprecision(0) << abs_val
                         << "B z=" << std::setprecision(2) << z
                         << " mean=" << std::setprecision(0) << bl.net_bytes_out_rate.mean;

                threats.push_back(make_threat(
                    "exfiltration", "exfil_volume_anomaly", "high", conf, dev, ts, ip,
                    "Anomalous outbound data volume — possible data exfiltration",
                    evidence.str()));
            }
        }

        // --- Statistical: in/out ratio anomaly (sudden reversal) ---
        if (bl.net_in_out_ratio.is_ready()) {
            // Normally servers have higher inbound. If outbound suddenly
            // exceeds inbound drastically, that's suspicious.
            double z = bl.net_in_out_ratio.z_score();
            // We're interested in a NEGATIVE z (ratio dropped = more outbound)
            if (z <= -config_.exfil_ratio_z) {
                double conf = baselines_.z_to_confidence(z);
                threats.push_back(make_threat(
                    "exfiltration", "exfil_large_transfer", "medium", conf, dev, ts, ip,
                    "Network in/out ratio anomaly — outbound surge relative to inbound",
                    "ratio_z=" + std::to_string(z)));
            }
        }

        // --- Log-based: DNS tunneling ---
        if (count_matches(log, pat_.dns_tunnel) > 0) {
            threats.push_back(make_threat(
                "exfiltration", "exfil_dns_tunneling", "critical", 0.85, dev, ts, ip,
                "DNS tunneling tool or pattern detected in logs",
                log.substr(0, 256)));
        }
    }

    // =========================================================================
    // 5. C2 BEACONING DETECTION
    // =========================================================================
    void detect_c2_beaconing(std::vector<ThreatDetection>& threats,
                             int32_t dev, int64_t ts, const std::string& ip,
                             const DeviceBaseline& bl, const std::string& log)
    {
        // --- Statistical: low-jitter periodic reporting (beaconing indicator) ---
        // A legitimate host has variable report intervals.
        // C2 beacons have very regular intervals (low coefficient of variation).
        if (bl.report_interval_ms.is_ready() &&
            bl.report_interval_ms.samples >= config_.c2_min_samples)
        {
            double mean = bl.report_interval_ms.mean;
            double sd   = bl.report_interval_ms.stddev();

            if (mean > 0) {
                double cov = sd / mean;  // Coefficient of variation

                if (cov < config_.c2_interval_jitter_max && cov > 0.001) {
                    // Very regular intervals — suspicious
                    double conf = 0.4 + (config_.c2_interval_jitter_max - cov) / config_.c2_interval_jitter_max * 0.4;

                    std::stringstream evidence;
                    evidence << "interval_mean=" << std::fixed << std::setprecision(0) << mean
                             << "ms stddev=" << std::setprecision(0) << sd
                             << "ms CoV=" << std::setprecision(4) << cov;

                    threats.push_back(make_threat(
                        "c2_beaconing", "c2_periodic_beacon", "high", conf, dev, ts, ip,
                        "Periodic callback pattern detected — low jitter interval (possible C2 beacon)",
                        evidence.str()));
                }
            }
        }

        // --- Log-based: Known C2 framework signatures ---
        if (count_matches(log, pat_.c2_cobalt_strike) > 0) {
            threats.push_back(make_threat(
                "c2_beaconing", "c2_known_framework", "critical", 0.9, dev, ts, ip,
                "Cobalt Strike beacon signature detected",
                log.substr(0, 256)));
        }
        if (count_matches(log, pat_.c2_meterpreter) > 0) {
            threats.push_back(make_threat(
                "c2_beaconing", "c2_known_framework", "critical", 0.9, dev, ts, ip,
                "Meterpreter / reverse shell signature detected",
                log.substr(0, 256)));
        }
        if (count_matches(log, pat_.c2_beacon_pattern) > 0) {
            threats.push_back(make_threat(
                "c2_beaconing", "c2_http_beacon", "high", 0.7, dev, ts, ip,
                "C2 beacon communication pattern in logs",
                log.substr(0, 256)));
        }

        // --- DNS-based C2 ---
        if (count_matches(log, pat_.dns_txt_query) > 0) {
            threats.push_back(make_threat(
                "c2_beaconing", "c2_dns_beacon", "high", 0.8, dev, ts, ip,
                "DNS-based C2 channel indicators (TXT queries / tunneling tool)",
                log.substr(0, 256)));
        }
    }

    // =========================================================================
    // 6. LATERAL MOVEMENT DETECTION
    // =========================================================================
    void detect_lateral_movement(std::vector<ThreatDetection>& threats,
                                 int32_t dev, int64_t ts, const std::string& ip,
                                 const DeviceBaseline& bl, const std::string& log)
    {
        // --- Internal network scanning ---
        int internal_scans = count_matches(log, pat_.internal_scan);
        if (internal_scans >= config_.lateral_internal_scan_min) {
            double conf = std::min(0.5 + internal_scans * 0.08, 0.9);
            threats.push_back(make_threat(
                "lateral_movement", "lateral_internal_scan", "high", conf, dev, ts, ip,
                "Internal subnet scanning detected (" + std::to_string(internal_scans) + " indicators)",
                log.substr(0, 256)));
        }

        // --- Pass-the-Hash ---
        if (count_matches(log, pat_.pass_the_hash) > 0) {
            threats.push_back(make_threat(
                "lateral_movement", "lateral_pass_the_hash", "critical", 0.85, dev, ts, ip,
                "Pass-the-Hash attack indicators (NTLM relay / mimikatz)",
                log.substr(0, 256)));
        }

        // --- Pass-the-Ticket ---
        if (count_matches(log, pat_.pass_the_ticket) > 0) {
            threats.push_back(make_threat(
                "lateral_movement", "lateral_pass_the_ticket", "critical", 0.85, dev, ts, ip,
                "Pass-the-Ticket / Golden Ticket attack indicators",
                log.substr(0, 256)));
        }

        // --- SMB lateral ---
        int smb_count = count_matches(log, pat_.smb_lateral) + count_matches(log, pat_.psexec);
        if (smb_count >= config_.lateral_smb_rdp_min) {
            threats.push_back(make_threat(
                "lateral_movement", "lateral_smb", "high", 0.75, dev, ts, ip,
                "SMB-based lateral movement indicators (PsExec/admin shares)",
                log.substr(0, 256)));
        }

        // --- RDP lateral ---
        if (count_matches(log, pat_.rdp_lateral) >= 1) {
            threats.push_back(make_threat(
                "lateral_movement", "lateral_rdp", "medium", 0.6, dev, ts, ip,
                "RDP connection to internal host detected",
                log.substr(0, 256)));
        }

        // --- WMI execution ---
        if (count_matches(log, pat_.wmi_exec) > 0) {
            threats.push_back(make_threat(
                "lateral_movement", "lateral_wmi", "high", 0.75, dev, ts, ip,
                "WMI remote execution detected",
                log.substr(0, 256)));
        }
    }
};

#endif
