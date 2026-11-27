// Parser coverage: syslog (RFC 5424/3164 + CEF/LEEF), Windows Event Log text
// and Linux auth parsers in session_tracker, and RegexEngine rules/lines.
#include "test_util.h"

#include "syslog_ingestor.h"
#include "session_tracker.h"
#include "regex_engine.h"

#include <filesystem>
#include <fstream>
#include <string>

using seahorse::syslog::SyslogEvent;
using seahorse::syslog::SyslogIngestor;
using seahorse::syslog::SyslogForwarder;

static std::filesystem::path write_temp(const std::string& name, const std::string& body) {
    auto dir = std::filesystem::temp_directory_path() / "seahorse_parser_tests";
    std::filesystem::create_directories(dir);
    auto p = dir / name;
    std::ofstream out(p, std::ios::binary | std::ios::trunc);
    out << body;
    return p;
}

int main() {
    std::printf("test_parsers\n");

    // ---- Syslog: RFC 5424 -------------------------------------------------
    {
        auto ev = SyslogIngestor::parse(
            "<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - "
            "'su root' failed for lonvick on /dev/pts/8");
        CHECK(ev.facility == 4);   // 34 / 8
        CHECK(ev.severity == 2);   // 34 % 8
        CHECK(ev.timestamp == "2003-10-11T22:14:15.003Z");
        CHECK(ev.hostname == "mymachine.example.com");
        CHECK(ev.appname == "su");
        CHECK(ev.procid.empty());  // NILVALUE
        CHECK(ev.msgid == "ID47");
        CHECK(ev.message.find("su root") != std::string::npos);
        CHECK(ev.raw.find("<34>1 ") == 0);
    }

    // RFC 5424 with structured data, then a message.
    {
        auto ev = SyslogIngestor::parse(
            "<165>1 2003-10-11T22:14:15.003Z host app 1234 ID47 "
            "[exampleSDID@32473 iut=\"3\" eventSource=\"App\"] "
            "[more@32473 foo=\"ba]r\"] hello world");
        CHECK(ev.facility == 20);
        CHECK(ev.severity == 5);
        CHECK(ev.appname == "app");
        CHECK(ev.procid == "1234");
        CHECK(ev.message == "hello world");
    }

    // RFC 5424 NILVALUE fields and empty message.
    {
        auto ev = SyslogIngestor::parse("<13>1 - - - - - -");
        CHECK(ev.facility == 1);
        CHECK(ev.severity == 5);
        CHECK(ev.timestamp.empty());
        CHECK(ev.hostname.empty());
        CHECK(ev.appname.empty());
        CHECK(ev.message.empty());
    }

    // ---- Syslog: RFC 3164 -------------------------------------------------
    {
        auto ev = SyslogIngestor::parse(
            "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick");
        CHECK(ev.facility == 4);
        CHECK(ev.severity == 2);
        CHECK(ev.timestamp == "Oct 11 22:14:15");
        CHECK(ev.hostname == "mymachine");
        CHECK(ev.appname == "su");
        CHECK(ev.message.find("su root") != std::string::npos);
    }

    // Single-digit day (space padded) and TAG[pid]:
    {
        auto ev = SyslogIngestor::parse(
            "<13>Jan  7 01:02:03 host sshd[4242]: Failed password for root from 1.2.3.4");
        CHECK(ev.timestamp == "Jan  7 01:02:03");
        CHECK(ev.hostname == "host");
        CHECK(ev.appname == "sshd");
        CHECK(ev.procid == "4242");
        CHECK(ev.message.find("Failed password") != std::string::npos);
    }

    // ---- Syslog: malformed / edge -----------------------------------------
    {
        auto ev = SyslogIngestor::parse("");
        CHECK(ev.raw.empty());
        CHECK(ev.message.empty());
        CHECK(ev.facility == 0);
    }
    {
        auto ev = SyslogIngestor::parse("<");
        CHECK(ev.message == "<" || ev.message.empty()); // no valid PRI, rest is message
        CHECK(ev.raw == "<");
    }
    {
        auto ev = SyslogIngestor::parse("<>");
        CHECK(ev.facility == 0);
    }
    {
        auto ev = SyslogIngestor::parse("<abc>");
        CHECK(ev.facility == 0);
        CHECK(ev.message.find("<abc>") != std::string::npos || ev.message == "<abc>");
    }
    {
        // PRI 192 is illegal (max 191); treat as no PRI.
        auto ev = SyslogIngestor::parse("<192>Oct 11 22:14:15 host app: x");
        CHECK(ev.facility == 0);
        CHECK(ev.message.find("host") != std::string::npos || ev.raw.find("<192>") == 0);
    }
    {
        auto ev = SyslogIngestor::parse("<34>");
        CHECK(ev.facility == 4);
        CHECK(ev.severity == 2);
        CHECK(ev.message.empty());
    }
    {
        // Unclosed PRI -- message is the raw remainder, no crash.
        auto ev = SyslogIngestor::parse("<34 Oct 11 22:14:15 host app: x");
        CHECK_NOTHROW((void)ev.raw.size());
        CHECK(ev.facility == 0);
    }
    {
        // No PRI, free text.
        auto ev = SyslogIngestor::parse("just a log line with no header");
        CHECK(ev.message == "just a log line with no header");
    }
    {
        // Oversized input is truncated to 64 KiB and still parses.
        std::string big = "<13>1 2003-10-11T22:14:15.003Z host app - ID47 - ";
        big.append(80 * 1024, 'A');
        auto ev = SyslogIngestor::parse(big);
        CHECK(ev.raw.size() == 64 * 1024);
        CHECK(ev.hostname == "host");
        CHECK(ev.appname == "app");
        CHECK(ev.message.size() <= 64 * 1024);
        CHECK(!ev.message.empty() && ev.message[0] == 'A');
    }
    {
        // Oversized hostname is capped at 255.
        std::string host(400, 'h');
        auto ev = SyslogIngestor::parse("<13>1 2003-10-11T22:14:15.003Z " + host + " app - ID47 - hi");
        CHECK(ev.hostname.size() == 255);
        CHECK(ev.appname == "app");
        CHECK(ev.message == "hi");
    }
    {
        // Unclosed structured data does not throw.
        CHECK_NOTHROW(SyslogIngestor::parse(
            "<13>1 2003-10-11T22:14:15.003Z host app - ID47 [open@1 foo=\"bar\""));
    }

    // ---- CEF / LEEF serializers -------------------------------------------
    {
        SyslogForwarder::UpstreamConfig cfg;
        cfg.vendor_tag = "SecureSeaHorse";
        cfg.product_tag = "SIEM";
        cfg.product_version = "5.1.1";
        auto ev = SyslogIngestor::parse(
            "<34>1 2003-10-11T22:14:15.003Z host su - ID47 - msg with | pipe = and \\ slash");
        std::string cef = SyslogForwarder::to_cef(ev, cfg);
        CHECK(cef.find("CEF:0|SecureSeaHorse|SIEM|5.1.1|ID47|") == 0);
        CHECK(cef.find("\\|") != std::string::npos);   // pipe escaped
        CHECK(cef.find("\\=") != std::string::npos);
        CHECK(cef.find("\\\\") != std::string::npos);
        CHECK(cef.find("syslogFacility=4") != std::string::npos);

        std::string leef = SyslogForwarder::to_leef(ev, cfg);
        CHECK(leef.find("LEEF:2.0|SecureSeaHorse|SIEM|5.1.1|ID47|") == 0);
        CHECK(leef.find("dhost=host") != std::string::npos);
        CHECK(leef.find('\t') != std::string::npos);
    }

    // ---- Linux auth parser ------------------------------------------------
    {
        SessionScanner scanner;
        scanner.parse_linux_auth_text(
            "sshd[10]: Failed password for root from 203.0.113.9 port 22 ssh2", 1000);
        auto evs = scanner.collect_auth_events();
        CHECK(evs.size() == 1);
        CHECK(evs.size() == 1 && evs[0].type == AuthEventType::AUTH_LOGIN_FAILED);
        CHECK(evs.size() == 1 && evs[0].username == "root");
        CHECK(evs.size() == 1 && evs[0].source_ip == "203.0.113.9");
        CHECK(evs.size() == 1 && evs[0].timestamp_ms == 1000);
    }
    {
        SessionScanner scanner;
        scanner.parse_linux_auth_text(
            "sshd[10]: Failed password for invalid user admin from 10.0.0.8 port 22 ssh2", 1);
        auto evs = scanner.collect_auth_events();
        CHECK(evs.size() == 1 && evs[0].username == "admin");
        CHECK(evs.size() == 1 && evs[0].source_ip == "10.0.0.8");
    }
    {
        SessionScanner scanner;
        scanner.parse_linux_auth_text(
            "sshd[10]: Accepted publickey for alice from 192.0.2.10 port 22 ssh2", 2);
        auto evs = scanner.collect_auth_events();
        CHECK(evs.size() == 1 && evs[0].type == AuthEventType::AUTH_LOGIN_SUCCESS);
        CHECK(evs.size() == 1 && evs[0].username == "alice");
        CHECK(evs.size() == 1 && evs[0].source_ip == "192.0.2.10");
    }
    {
        // Bare "Accepted" + "password" in unrelated text must not fire (bug fix).
        SessionScanner scanner;
        scanner.parse_linux_auth_text(
            "app: Request Accepted, please reset password at next login", 3);
        CHECK(scanner.collect_auth_events().empty());
    }
    {
        // sudo: username is the account after "sudo:", not the token "sudo".
        SessionScanner scanner;
        scanner.parse_linux_auth_text(
            "Nov 26 10:00:00 host sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/ls",
            4);
        auto evs = scanner.collect_auth_events();
        CHECK(evs.size() == 1 && evs[0].type == AuthEventType::AUTH_PRIVILEGE_ESCALATION);
        CHECK(evs.size() == 1 && evs[0].username == "alice");
        CHECK(evs.size() == 1 && evs[0].detail.find("/bin/ls") != std::string::npos);
    }
    {
        SessionScanner scanner;
        scanner.parse_linux_auth_text(
            "su[99]: Successful su for root by alice; session opened", 5);
        auto evs = scanner.collect_auth_events();
        CHECK(evs.size() == 1 && evs[0].session_type == "su");
    }
    {
        SessionScanner scanner;
        scanner.parse_linux_auth_text("", 6);
        CHECK(scanner.collect_auth_events().empty());
        scanner.parse_linux_auth_text("cron: ran job", 7);
        CHECK(scanner.collect_auth_events().empty());
    }
    {
        // Oversized line is truncated and must not throw.
        std::string line = "sshd[10]: Failed password for root from 1.2.3.4 ";
        line.append(20 * 1024, 'X');
        SessionScanner scanner;
        CHECK_NOTHROW(scanner.parse_linux_auth_text(line, 8));
        auto evs = scanner.collect_auth_events();
        CHECK(evs.size() == 1 && evs[0].username == "root");
    }

    // ---- Windows Event Log text parser ------------------------------------
    {
        SessionScanner scanner;
        scanner.parse_windows_auth_text(
            "<Event><System><EventID>4625</EventID></System></Event>", 10);
        auto evs = scanner.collect_auth_events();
        CHECK(evs.size() == 1 && evs[0].type == AuthEventType::AUTH_LOGIN_FAILED);
        CHECK(evs.size() == 1 && evs[0].detail.find("4625") != std::string::npos);
    }
    {
        SessionScanner scanner;
        scanner.parse_windows_auth_text("Event ID: 4624\nAccount Name: bob", 11);
        auto evs = scanner.collect_auth_events();
        CHECK(evs.size() == 1 && evs[0].type == AuthEventType::AUTH_LOGIN_SUCCESS);
    }
    {
        SessionScanner scanner;
        scanner.parse_windows_auth_text("event id 4648", 12);
        auto evs = scanner.collect_auth_events();
        CHECK(evs.size() == 1 && evs[0].detail.find("4648") != std::string::npos);
    }
    {
        SessionScanner scanner;
        scanner.parse_windows_auth_text("<EventID>4672</EventID>", 13);
        CHECK(scanner.collect_auth_events()[0].type == AuthEventType::AUTH_PRIVILEGE_ESCALATION);
    }
    {
        SessionScanner scanner;
        scanner.parse_windows_auth_text("Event ID: 4740", 14);
        auto evs = scanner.collect_auth_events();
        CHECK(evs.size() == 1 && evs[0].type == AuthEventType::AUTH_ACCOUNT_LOCKOUT);
    }
    {
        // Bare event-id numbers and the word "failed" must not fire (bug fix).
        SessionScanner scanner;
        scanner.parse_windows_auth_text("build 46250 failed to download package 46720", 15);
        CHECK(scanner.collect_auth_events().empty());
        scanner.parse_windows_auth_text("Event ID: 46250", 16);
        CHECK(scanner.collect_auth_events().empty());
        scanner.parse_windows_auth_text("<EventID>14625</EventID>", 17);
        CHECK(scanner.collect_auth_events().empty());
    }
    {
        std::string huge = "<EventID>4625</EventID> ";
        huge.append(20 * 1024, 'Z');
        SessionScanner scanner;
        CHECK_NOTHROW(scanner.parse_windows_auth_text(huge, 18));
        CHECK(scanner.collect_auth_events().size() == 1);
    }

    // ---- RegexEngine: built-in syslog + Windows Event Log lines -----------
    {
        RegexEngine eng;
        auto evs = eng.analyze(
            "sshd[1]: Failed password for root from 10.0.0.1 port 22 ssh2\n");
        bool found = false;
        for (const auto& e : evs)
            if (e.rule_name == "ssh_failed_password") found = true;
        CHECK(found);
        CHECK(eng.count_failed_logins(
            "sshd[1]: Failed password for root from 10.0.0.1 port 22 ssh2\n") >= 1);
    }
    {
        RegexEngine eng;
        auto evs = eng.analyze("<EventID>4625</EventID>\n");
        bool found = false;
        for (const auto& e : evs)
            if (e.rule_name == "win_logon_failure_4625") found = true;
        CHECK(found);
    }
    {
        // Event ID 46250 must not match the 4625 rule (bug fix: word boundary).
        RegexEngine eng;
        auto evs = eng.analyze("event id: 46250\n");
        bool found = false;
        for (const auto& e : evs)
            if (e.rule_name == "win_logon_failure_4625") found = true;
        CHECK(!found);
    }
    {
        RegexEngine eng;
        auto evs = eng.analyze("event id: 4625\n");
        bool found = false;
        for (const auto& e : evs)
            if (e.rule_name == "win_logon_failure_4625") found = true;
        CHECK(found);
    }
    {
        // Empty, blank, and CR-only lines produce no events and do not throw.
        RegexEngine eng;
        CHECK(eng.analyze("").empty());
        CHECK(eng.analyze("\n\n\r\n").empty());
        CHECK_NOTHROW(eng.analyze(std::string(1, '\0')));
    }
    {
        // Oversized line is truncated to 4 KiB before matching.
        RegexEngine eng;
        std::string line(5000, 'A');
        line = "Failed password for root from 1.2.3.4 " + line;
        auto evs = eng.analyze(line + "\n");
        bool found = false;
        for (const auto& e : evs)
            if (e.rule_name == "ssh_failed_password") found = true;
        CHECK(found);
        // Match is visible in the first 4 KiB; matched_text is capped at 512.
        CHECK(!evs.empty() && evs[0].matched_text.size() <= 512);
    }
    {
        // A needle only after the 4 KiB cap must not match.
        RegexEngine eng;
        std::string line(5000, 'A');
        line += "Failed password for root from 1.2.3.4\n";
        auto evs = eng.analyze(line);
        bool found = false;
        for (const auto& e : evs)
            if (e.rule_name == "ssh_failed_password") found = true;
        CHECK(!found);
    }

    // ---- RegexEngine: rules.conf parser edges -----------------------------
    {
        auto p = write_temp("rules_ok.conf",
            "# comment\n"
            "\n"
            "  custom_rule | high | auth_failure | custom-needle-xyz\n"
            "ssh_failed_password | critical | auth_failure | OVERRIDE_FAILED_TOKEN\n");
        RegexEngine eng(p.string());
        CHECK(eng.user_rules_loaded() == 2);
        // Override replaces the built-in name.
        auto evs = eng.analyze("sshd: Failed password for root from 1.2.3.4\n");
        bool builtin_hit = false, override_hit = false;
        for (const auto& e : evs) {
            if (e.rule_name == "ssh_failed_password") {
                if (e.matched_text.find("OVERRIDE") != std::string::npos) override_hit = true;
                builtin_hit = true;
            }
        }
        CHECK(!builtin_hit); // the built-in pattern no longer matches this line
        evs = eng.analyze("OVERRIDE_FAILED_TOKEN in a line\n");
        for (const auto& e : evs)
            if (e.rule_name == "ssh_failed_password") override_hit = true;
        CHECK(override_hit);
        evs = eng.analyze("custom-needle-xyz happened\n");
        bool custom = false;
        for (const auto& e : evs)
            if (e.rule_name == "custom_rule") custom = true;
        CHECK(custom);
    }
    {
        auto p = write_temp("rules_bad.conf",
            "only|three|fields\n"
            "empty_pat | high | auth_failure |\n"
            "badsev | bananas | auth_failure | needle\n"
            "ok_rule | medium | custom | a-valid-pattern\n"
            + std::string("toobig | high | custom | ") + std::string(5000, 'A') + "\n");
        RegexEngine eng(p.string());
        CHECK(eng.user_rules_loaded() == 1);
        bool found = false;
        for (const auto& e : eng.analyze("a-valid-pattern\n"))
            if (e.rule_name == "ok_rule") found = true;
        CHECK(found);
    }
    {
        // Missing file is not an error.
        RegexEngine eng("/no/such/seahorse/rules.conf");
        CHECK(eng.user_rules_loaded() == 0);
        CHECK(eng.builtin_count() > 0);
    }
    {
        // Over-long line in rules.conf is skipped, next line still loads.
        std::string body = std::string(9000, 'x') + "\nok2 | low | custom | visible-token\n";
        auto p = write_temp("rules_long.conf", body);
        RegexEngine eng(p.string());
        CHECK(eng.user_rules_loaded() == 1);
        bool found = false;
        for (const auto& e : eng.analyze("visible-token\n"))
            if (e.rule_name == "ok2") found = true;
        CHECK(found);
    }

    TEST_MAIN_RETURN();
}
