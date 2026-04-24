#ifndef REPORT_GENERATOR_H
#define REPORT_GENERATOR_H

#ifndef NOMINMAX
#define NOMINMAX
#endif

// =============================================================================
// SecureSeaHorse SIEM -- Phase 18: Reporting & Compliance
// =============================================================================
// Generates periodic HTML reports that summarise the security posture of the
// fleet across configurable compliance frameworks. Output is self-contained
// HTML (inline CSS, no external dependencies) so it can be emailed, archived,
// or rendered to PDF by an external tool (wkhtmltopdf, Chrome headless).
//
// Supported frameworks (built-in templates):
//   - PCI-DSS 4.0   (10 focus points: access, logging, vuln mgmt, ...)
//   - HIPAA         (Security Rule: Administrative / Physical / Technical)
//   - SOC 2 TSC     (Security / Availability / Confidentiality / Integrity)
//   - ISO 27001     (A.5-A.18 control families)
//   - Generic       (Raw detection + incident rollup, no framework mapping)
//
// The reporter does not itself schedule jobs -- it exposes render_report()
// which the main server calls on a timer (cron-style) or on demand via REST.
// =============================================================================

#include <algorithm>
#include <chrono>
#include <ctime>
#include <fstream>
#include <functional>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

// =============================================================================
// REPORT INPUT DATA -- Populated by the server before calling render
// =============================================================================
struct ReportInputs {
    std::string framework;        // "pci", "hipaa", "soc2", "iso27001", "generic"
    std::string report_period;    // "Daily", "Weekly", "Monthly"
    int64_t     period_start_ms = 0;
    int64_t     period_end_ms = 0;

    // Fleet rollup
    size_t devices_total    = 0;
    size_t devices_online   = 0;
    size_t devices_offline  = 0;
    size_t devices_quarantined = 0;

    // Threat / detection counts
    size_t threats_total    = 0;
    size_t threats_critical = 0;
    size_t threats_high     = 0;
    size_t threats_medium   = 0;

    // Category breakdown
    std::map<std::string, size_t> threat_by_category;

    // IoC, FIM, correlated incidents
    size_t ioc_hits_total   = 0;
    size_t fim_events_total = 0;
    size_t correlated_incidents = 0;

    // IR actions
    size_t ir_incidents         = 0;
    size_t ir_actions_executed  = 0;
    size_t ir_blocked_ips       = 0;
    size_t ir_quarantines       = 0;

    // Top N lists (each entry is a pre-formatted display string)
    std::vector<std::string> top_threats;      // e.g. "device=1001 | brute_force | MITRE T1110 | 42 events"
    std::vector<std::string> top_devices;      // busiest devices
    std::vector<std::string> top_indicators;   // most-hit IoCs

    // Compliance notes -- free-form text per control family
    std::map<std::string, std::string> compliance_notes;
};

// =============================================================================
// REPORT OUTPUT
// =============================================================================
struct Report {
    std::string title;
    std::string framework;
    std::string html;             // Full self-contained document
    int64_t     generated_ms = 0;
};

// =============================================================================
// REPORT GENERATOR
// =============================================================================
class ReportGenerator {
public:
    struct Config {
        bool enabled = true;
        std::string output_dir = "reports";
        std::string organization_name = "SecureSeaHorse Deployment";
    };

    explicit ReportGenerator(const Config& cfg) : config_(cfg) {
        init_framework_map();
    }

    Report render(const ReportInputs& in) const {
        Report r;
        r.framework = in.framework.empty() ? "generic" : in.framework;
        r.title = build_title(in, r.framework);
        r.generated_ms = now_ms();
        r.html = render_html(in, r);
        return r;
    }

    // Save to disk, returns file path.
    std::string save(const Report& r) const {
        try {
            if (!config_.output_dir.empty()) {
                std::filesystem::create_directories(config_.output_dir);
            }
        } catch (...) {}
        std::string filename = config_.output_dir + "/report_" + r.framework + "_"
            + std::to_string(r.generated_ms) + ".html";
        std::ofstream f(filename);
        if (f.is_open()) f << r.html;
        return filename;
    }

private:
    Config config_;
    std::map<std::string, std::vector<std::string>> framework_controls_;

    void init_framework_map() {
        framework_controls_["pci"] = {
            "1. Install and maintain network security controls",
            "2. Apply secure configurations to all system components",
            "3. Protect stored account data",
            "5. Protect all systems from malicious software",
            "6. Develop and maintain secure systems",
            "7. Restrict access to system components by need-to-know",
            "8. Identify users and authenticate access",
            "10. Log and monitor all access",
            "11. Test security of systems and networks regularly",
            "12. Support information security with organisational policies"
        };
        framework_controls_["hipaa"] = {
            "164.308(a)(1) -- Security management process",
            "164.308(a)(3) -- Workforce security",
            "164.308(a)(5) -- Security awareness & training",
            "164.308(a)(6) -- Security incident procedures",
            "164.310      -- Physical safeguards",
            "164.312(a)   -- Access control (technical)",
            "164.312(b)   -- Audit controls",
            "164.312(c)   -- Integrity",
            "164.312(e)   -- Transmission security"
        };
        framework_controls_["soc2"] = {
            "CC6.1  -- Logical access controls",
            "CC6.6  -- Boundary protection",
            "CC7.1  -- Detection of security events",
            "CC7.2  -- System monitoring",
            "CC7.3  -- Incident response evaluation",
            "CC7.4  -- Incident response plan",
            "CC8.1  -- Change management"
        };
        framework_controls_["iso27001"] = {
            "A.8 Asset management",
            "A.9 Access control",
            "A.12 Operations security -- logging & monitoring",
            "A.13 Communications security",
            "A.16 Information security incident management",
            "A.17 Business continuity"
        };
    }

    std::string build_title(const ReportInputs& in, const std::string& fw) const {
        std::string fw_label = fw;
        std::transform(fw_label.begin(), fw_label.end(), fw_label.begin(), ::toupper);
        if (fw_label == "GENERIC") fw_label = "Security";
        return fw_label + " " + in.report_period + " Report -- " + config_.organization_name;
    }

    static std::string html_escape(const std::string& s) {
        std::string out; out.reserve(s.size() + 16);
        for (char c : s) {
            switch (c) {
                case '<': out += "&lt;"; break;
                case '>': out += "&gt;"; break;
                case '&': out += "&amp;"; break;
                case '"': out += "&quot;"; break;
                case '\'': out += "&#39;"; break;
                default: out += c;
            }
        }
        return out;
    }

    static std::string fmt_ts(int64_t ms) {
        if (ms == 0) return "n/a";
        std::time_t t = static_cast<std::time_t>(ms / 1000);
        std::tm* tm = std::gmtime(&t);
        if (!tm) return "n/a";
        char buf[64];
        std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S UTC", tm);
        return buf;
    }

    static int64_t now_ms() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }

    std::string render_html(const ReportInputs& in, const Report& r) const {
        std::ostringstream h;
        h << R"(<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">)"
          << "<title>" << html_escape(r.title) << "</title>"
          << R"(<style>
body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#f4f6f8;color:#1a1f2e}
.container{max-width:1000px;margin:0 auto;padding:32px;background:#fff}
h1{border-bottom:3px solid #1f6feb;padding-bottom:12px;color:#0d1117}
h2{color:#1f6feb;margin-top:32px;padding-bottom:6px;border-bottom:1px solid #e1e4e8}
h3{color:#444;margin-top:20px}
.meta{color:#586069;font-size:13px;margin-bottom:24px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:16px 0}
.card{background:#f6f8fa;border:1px solid #e1e4e8;border-radius:8px;padding:14px}
.card .label{font-size:11px;color:#586069;text-transform:uppercase;letter-spacing:0.5px}
.card .value{font-size:24px;font-weight:700;margin-top:4px}
.card.critical{border-left:4px solid #cf222e}.card.high{border-left:4px solid #d29922}
.card.ok{border-left:4px solid #3fb950}.card.info{border-left:4px solid #1f6feb}
table{width:100%;border-collapse:collapse;margin-top:12px;font-size:13px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #e1e4e8}
th{background:#f6f8fa;color:#444;text-transform:uppercase;font-size:11px;letter-spacing:0.5px}
.control{background:#f9fafb;border-left:4px solid #1f6feb;padding:10px 14px;margin:8px 0;border-radius:4px}
.control .title{font-weight:600;color:#1a1f2e}
.control .note{font-size:13px;color:#586069;margin-top:4px}
.footer{margin-top:40px;padding-top:14px;border-top:1px solid #e1e4e8;font-size:11px;color:#959da5}
</style></head><body><div class="container">)";

        // Header
        h << "<h1>" << html_escape(r.title) << "</h1>";
        h << "<div class=\"meta\">";
        h << "Generated " << fmt_ts(r.generated_ms) << " | ";
        h << "Reporting window: " << fmt_ts(in.period_start_ms)
          << " &rarr; " << fmt_ts(in.period_end_ms);
        h << "</div>";

        // Executive summary cards
        h << "<h2>Executive Summary</h2><div class=\"grid\">";
        h << "<div class=\"card info\"><div class=\"label\">Devices Monitored</div><div class=\"value\">"
          << in.devices_total << "</div></div>";
        h << "<div class=\"card ok\"><div class=\"label\">Online</div><div class=\"value\">"
          << in.devices_online << "</div></div>";
        h << "<div class=\"card " << (in.threats_critical > 0 ? "critical" : "ok")
          << "\"><div class=\"label\">Critical Threats</div><div class=\"value\">"
          << in.threats_critical << "</div></div>";
        h << "<div class=\"card " << (in.threats_high > 0 ? "high" : "ok")
          << "\"><div class=\"label\">High Threats</div><div class=\"value\">"
          << in.threats_high << "</div></div>";
        h << "<div class=\"card info\"><div class=\"label\">IoC Hits</div><div class=\"value\">"
          << in.ioc_hits_total << "</div></div>";
        h << "<div class=\"card info\"><div class=\"label\">FIM Events</div><div class=\"value\">"
          << in.fim_events_total << "</div></div>";
        h << "<div class=\"card info\"><div class=\"label\">Correlated Incidents</div><div class=\"value\">"
          << in.correlated_incidents << "</div></div>";
        h << "<div class=\"card info\"><div class=\"label\">Blocked IPs</div><div class=\"value\">"
          << in.ir_blocked_ips << "</div></div>";
        h << "</div>";

        // Threat breakdown
        if (!in.threat_by_category.empty()) {
            h << "<h2>Threat Category Breakdown</h2><table><thead><tr>"
              << "<th>Category</th><th>Count</th></tr></thead><tbody>";
            for (const auto& kv : in.threat_by_category) {
                h << "<tr><td>" << html_escape(kv.first) << "</td><td>" << kv.second << "</td></tr>";
            }
            h << "</tbody></table>";
        }

        // Top threats / devices / IoCs
        auto dump_list = [&](const char* hdr, const std::vector<std::string>& items) {
            if (items.empty()) return;
            h << "<h3>" << hdr << "</h3><ol>";
            for (const auto& i : items) h << "<li>" << html_escape(i) << "</li>";
            h << "</ol>";
        };
        dump_list("Top Threats", in.top_threats);
        dump_list("Most Active Devices", in.top_devices);
        dump_list("Most Matched Indicators", in.top_indicators);

        // Framework controls
        std::string fw_key = r.framework;
        std::transform(fw_key.begin(), fw_key.end(), fw_key.begin(), ::tolower);
        auto ctrl_it = framework_controls_.find(fw_key);
        if (ctrl_it != framework_controls_.end()) {
            h << "<h2>Control Coverage</h2>";
            for (const auto& c : ctrl_it->second) {
                h << "<div class=\"control\"><div class=\"title\">" << html_escape(c) << "</div>";
                auto note_it = in.compliance_notes.find(c);
                if (note_it != in.compliance_notes.end()) {
                    h << "<div class=\"note\">" << html_escape(note_it->second) << "</div>";
                } else {
                    h << "<div class=\"note\">Monitored by SecureSeaHorse baseline controls "
                         "(see detection/telemetry rollups above).</div>";
                }
                h << "</div>";
            }
        }

        // IR summary
        h << "<h2>Incident Response Summary</h2><div class=\"grid\">";
        h << "<div class=\"card info\"><div class=\"label\">Incidents Raised</div><div class=\"value\">"
          << in.ir_incidents << "</div></div>";
        h << "<div class=\"card info\"><div class=\"label\">Actions Executed</div><div class=\"value\">"
          << in.ir_actions_executed << "</div></div>";
        h << "<div class=\"card info\"><div class=\"label\">Quarantines</div><div class=\"value\">"
          << in.ir_quarantines << "</div></div>";
        h << "</div>";

        h << "<div class=\"footer\">SecureSeaHorse SIEM -- automated compliance report. "
          << "This document summarises detection telemetry; it is not a replacement for a "
          << "formal audit performed by a qualified assessor.</div>";

        h << "</div></body></html>";
        return h.str();
    }
};

#endif
