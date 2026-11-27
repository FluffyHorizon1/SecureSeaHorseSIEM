// End-to-end: SigmaPipeline + AlertEngine, the same hook server.cpp uses.
// Feeds log lines through evaluate_and_alert and checks the alert log.
#include "test_util.h"
#include "sigma_ingest.h"
#include "alert_engine.h"

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

static std::filesystem::path temp_dir(const std::string& name) {
    auto dir = std::filesystem::temp_directory_path() / name;
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
    std::filesystem::create_directories(dir);
    return dir;
}

static void write_file(const std::filesystem::path& p, const std::string& body) {
    std::ofstream out(p, std::ios::binary | std::ios::trunc);
    out << body;
}

static std::string slurp(const std::filesystem::path& p) {
    std::ifstream in(p, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(in)),
                       std::istreambuf_iterator<char>());
}

int main() {
    std::printf("test_sigma_ingest\n");

    auto work = temp_dir("seahorse_sigma_ingest");
    auto rules = work / "rules";
    std::filesystem::create_directories(rules);

    write_file(rules / "ssh_fail.yml",
        "title: SSH failed password\n"
        "id: e2e-ssh-fail\n"
        "level: high\n"
        "detection:\n"
        "  selection:\n"
        "    - 'Failed password'\n"
        "  condition: selection\n");
    write_file(rules / "ps_enc.yml",
        "title: Encoded PowerShell\n"
        "id: e2e-ps-enc\n"
        "level: high\n"
        "detection:\n"
        "  selection_img:\n"
        "    Image|endswith: '\\powershell.exe'\n"
        "  selection_cmd:\n"
        "    CommandLine|contains: '-EncodedCommand'\n"
        "  condition: selection_img and selection_cmd\n");
    // Malformed: unsupported modifier, must be skipped, must not crash load.
    write_file(rules / "bad_cidr.yml",
        "title: Bad modifier\n"
        "id: e2e-bad\n"
        "detection:\n"
        "  s:\n"
        "    SourceIp|cidr: 10.0.0.0/8\n"
        "  condition: s\n");
    // Malformed YAML
    write_file(rules / "bad_yaml.yml",
        "title: tabs\n"
        "\tdetection: nope\n");

    const auto ssh_line =
        "sshd[10]: Failed password for root from 203.0.113.9 port 22 ssh2";
    const auto benign =
        "sshd[10]: Accepted publickey for alice from 192.0.2.10 port 22 ssh2";

    // Flag on: matching raw line fires an alert with id, title, level.
    {
        auto alert_path = work / "alerts_on.log";
        AlertConfig cfg;
        cfg.enabled = true;
        cfg.alert_log_path = alert_path.string();
        AlertEngine alerts(cfg);

        seahorse::sigma::SigmaPipeline pipe;
        seahorse::sigma::SigmaPipeline::Config sc;
        sc.enabled = true;
        sc.rules_dir = rules;
        std::vector<std::string> logs;
        size_t loaded = pipe.load(sc, [&](const std::string& m) { logs.push_back(m); });

        CHECK(pipe.enabled());
        CHECK(loaded == 2);                 // two good rules, two skipped
        CHECK(pipe.rule_count() == 2);
        CHECK(pipe.errors().size() >= 2);

        bool saw_skip = false;
        for (const auto& m : logs)
            if (m.find("sigma rule skipped") != std::string::npos) saw_skip = true;
        CHECK(saw_skip);

        auto hits = pipe.evaluate_and_alert(ssh_line, 7001, "10.0.0.5", &alerts);
        CHECK(hits.size() == 1);
        CHECK(hits.size() == 1 && hits[0].rule_id == "e2e-ssh-fail");
        CHECK(hits.size() == 1 && hits[0].title == "SSH failed password");
        CHECK(hits.size() == 1 && hits[0].level == "high");
        CHECK(hits.size() == 1 && hits[0].device_id == 7001);
        CHECK(alerts.total_alerts_fired() == 1);

        // Benign SSH line does not fire the failed-password rule.
        auto more = pipe.evaluate_and_alert(benign, 7001, "10.0.0.5", &alerts);
        CHECK(more.empty());
        CHECK(alerts.total_alerts_fired() == 1);
    }
    {
        std::string body = slurp(work / "alerts_on.log");
        CHECK(body.find("[ALERT]") != std::string::npos);
        CHECK(body.find("device=7001") != std::string::npos);
        CHECK(body.find("rule=e2e-ssh-fail") != std::string::npos);
        CHECK(body.find("title=SSH failed password") != std::string::npos);
        CHECK(body.find("level=high") != std::string::npos);
        CHECK(body.find("category=sigma") != std::string::npos);
        CHECK(body.find("Failed password") != std::string::npos);
        CHECK(body.find("e2e-bad") == std::string::npos); // skipped rule never fires
    }

    // Flag off: same matching line produces no alerts and loads no rules.
    {
        auto alert_path = work / "alerts_off.log";
        AlertConfig cfg;
        cfg.enabled = true;
        cfg.alert_log_path = alert_path.string();
        AlertEngine alerts(cfg);

        seahorse::sigma::SigmaPipeline pipe;
        seahorse::sigma::SigmaPipeline::Config sc;
        sc.enabled = false;
        sc.rules_dir = rules;
        size_t loaded = pipe.load(sc);
        CHECK(loaded == 0);
        CHECK(!pipe.enabled());
        CHECK(pipe.rule_count() == 0);

        auto hits = pipe.evaluate_and_alert(ssh_line, 7001, "10.0.0.5", &alerts);
        CHECK(hits.empty());
        CHECK(alerts.total_alerts_fired() == 0);
        std::string body = slurp(alert_path);
        CHECK(body.empty());
    }

    // Default Config (enabled=false) also fires nothing, even if a previous
    // mental model expected the shipped server.conf "true".
    {
        seahorse::sigma::SigmaPipeline pipe;
        CHECK(pipe.load(seahorse::sigma::SigmaPipeline::Config{}) == 0);
        CHECK(!pipe.enabled());
    }

    // Structured field-map event still works when the caller supplies fields
    // (process_report does not, today).
    {
        auto alert_path = work / "alerts_fields.log";
        AlertConfig cfg;
        cfg.enabled = true;
        cfg.alert_log_path = alert_path.string();
        AlertEngine alerts(cfg);

        seahorse::sigma::SigmaPipeline pipe;
        seahorse::sigma::SigmaPipeline::Config sc;
        sc.enabled = true;
        sc.rules_dir = rules;
        CHECK(pipe.load(sc) == 2);

        seahorse::sigma::SigmaEvent ev;
        ev.fields["Image"] = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
        ev.fields["CommandLine"] = "powershell.exe -EncodedCommand SQBFAFgA";
        auto hits = pipe.evaluate_and_alert(ev, 42, "192.0.2.1", &alerts);
        CHECK(hits.size() == 1);
        CHECK(hits.size() == 1 && hits[0].rule_id == "e2e-ps-enc");
        std::string body = slurp(alert_path);
        CHECK(body.find("rule=e2e-ps-enc") != std::string::npos);
        CHECK(body.find("title=Encoded PowerShell") != std::string::npos);
        CHECK(body.find("level=high") != std::string::npos);
        CHECK(body.find("device=42") != std::string::npos);
    }

    // Missing directory: no crash, zero rules, error logged, ingest stays quiet.
    {
        seahorse::sigma::SigmaPipeline pipe;
        seahorse::sigma::SigmaPipeline::Config sc;
        sc.enabled = true;
        sc.rules_dir = work / "no_such_rules";
        std::vector<std::string> logs;
        size_t n = 0;
        CHECK_NOTHROW(n = pipe.load(sc, [&](const std::string& m) { logs.push_back(m); }));
        CHECK(n == 0);
        CHECK(!logs.empty());
        auto hits = pipe.evaluate_and_alert(ssh_line, 1, "1.2.3.4", nullptr);
        CHECK(hits.empty());
    }

    // Load errors must not throw even with a mixed directory.
    {
        seahorse::sigma::SigmaPipeline pipe;
        seahorse::sigma::SigmaPipeline::Config sc;
        sc.enabled = true;
        sc.rules_dir = rules;
        CHECK_NOTHROW(pipe.load(sc));
        CHECK(pipe.rule_count() == 2);
    }

    TEST_MAIN_RETURN();
}
