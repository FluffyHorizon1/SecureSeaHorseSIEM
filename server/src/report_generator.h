// =============================================================================
// report_generator.h -- Phase 18 (v3.5.0)
// -----------------------------------------------------------------------------
// Scheduled compliance & exec-summary reports. No PDF dependencies — we emit
// self-contained HTML that prints cleanly to PDF via any headless browser or
// wkhtmltopdf. The three built-in templates cover the common ask:
//   - PCI-DSS quarterly (10 control families)
//   - HIPAA security rule (admin/physical/technical safeguards)
//   - SOC 2 (CC6.x common criteria)
//
// Reports are driven by cron-style schedules; generated files land under
// `reports/<template>/<yyyy-mm-dd>.html` and are served via the REST API at
// `/api/reports?limit=20` (Phase 20 RBAC: read-only requires "auditor" role).
// =============================================================================
#pragma once

#include <atomic>
#include <chrono>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace seahorse::reports {

enum class Template { Custom, PciDss, Hipaa, Soc2, ExecSummary };

struct ReportSpec {
    std::string    name;                // "pci-quarterly"
    Template       tmpl = Template::Custom;
    std::string    cron = "0 6 * * 1";  // minute hour dom month dow (default: Mon 06:00)
    std::string    output_dir = "reports";
    std::string    tenant_id;           // "" = global (pre-v4.0 installs)
    int            lookback_days = 7;
};

struct GeneratedReport {
    std::string id;                     // uuid
    std::string path;                   // path on disk
    std::string template_name;
    std::chrono::system_clock::time_point created_at;
    std::size_t size_bytes = 0;
    int events_included = 0;
    int threats_included = 0;
    int fim_changes_included = 0;
    int correlations_included = 0;
};

// Data provider callback — lets the generator stay decoupled from the DB layer.
using DataProvider = std::function<std::string(const std::string& /*sql_or_key*/,
                                               int /*lookback_days*/,
                                               const std::string& /*tenant_id*/)>;

class ReportGenerator {
public:
    explicit ReportGenerator(DataProvider p) : provider_(std::move(p)) {}

    void add_schedule(const ReportSpec& spec);
    void remove_schedule(const std::string& name);

    // Immediately render a report and return the on-disk path. Threading:
    // safe to call from the REST thread — rendering is synchronous but does
    // not block other report jobs.
    GeneratedReport render_now(const ReportSpec& spec);

    // Background scheduler thread. Wakes every 60 seconds, fires anything due.
    void start_scheduler();
    void stop_scheduler();

    // Listing for the REST API. Cap `limit` at 500 (Phase 7 hardening pattern).
    std::vector<GeneratedReport> list(int limit = 50) const;

private:
    DataProvider              provider_;
    std::vector<ReportSpec>   schedules_;
    std::vector<GeneratedReport> history_;
    mutable std::mutex        mtx_;
    std::thread               sched_thread_;
    std::atomic<bool>         running_{false};

    std::string render_html(const ReportSpec& spec) const;
};

} // namespace seahorse::reports
