// Unit tests for SessionScanner auth parsers: EvtRender-style Windows XML
// (including EventID Qualifiers and EventData user/IP) and auth.log / secure
// lines (ssh failed/accepted, sudo). The Windows parser must run on Linux CI.
#include "test_util.h"
#include "session_tracker.h"

#include <string>

static std::string evtx(const char* id, const char* user, const char* ip,
                        bool qualifiers = false) {
    std::string ev = "<?xml version=\"1.0\"?>\n"
        "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">\n"
        "  <System>\n"
        "    <Provider Name=\"Microsoft-Windows-Security-Auditing\"/>\n";
    if (qualifiers)
        ev += std::string("    <EventID Qualifiers=\"0\">") + id + "</EventID>\n";
    else
        ev += std::string("    <EventID>") + id + "</EventID>\n";
    ev += "    <Level>0</Level>\n"
          "    <EventRecordID>4242</EventRecordID>\n"
          "  </System>\n"
          "  <EventData>\n";
    ev += std::string("    <Data Name=\"TargetUserName\">") + user + "</Data>\n";
    ev += std::string("    <Data Name=\"IpAddress\">") + ip + "</Data>\n";
    ev += "  </EventData>\n</Event>\n";
    return ev;
}

int main() {
    std::printf("test_auth_parsers\n");
    SessionScanner sc;

    // 4625 failed logon from EvtRender XML, Information-level (Level=0/4)
    sc.parse_windows_auth_text(evtx("4625", "alice", "10.0.0.8"), 1000);
    auto ev = sc.collect_auth_events();
    CHECK(ev.size() == 1);
    CHECK(ev[0].type == AuthEventType::AUTH_LOGIN_FAILED);
    CHECK(ev[0].username == "alice");
    CHECK(ev[0].source_ip == "10.0.0.8");
    CHECK(ev[0].detail.find("4625") != std::string::npos);

    // 4624 success, EventID with Qualifiers attribute
    sc.parse_windows_auth_text(evtx("4624", "bob", "10.0.0.9", true), 2000);
    ev = sc.collect_auth_events();
    CHECK(ev.size() == 1);
    CHECK(ev[0].type == AuthEventType::AUTH_LOGIN_SUCCESS);
    CHECK(ev[0].username == "bob");

    // 4634 logoff, 4648 explicit cred, 4672 priv, 4740 lockout
    sc.parse_windows_auth_text(evtx("4634", "carol", "-"), 3000);
    ev = sc.collect_auth_events();
    CHECK(ev.size() == 1);
    CHECK(ev[0].type == AuthEventType::AUTH_LOGOUT);

    sc.parse_windows_auth_text(evtx("4648", "dave", "10.1.2.3"), 4000);
    ev = sc.collect_auth_events();
    CHECK(ev.size() == 1);
    CHECK(ev[0].type == AuthEventType::AUTH_LOGIN_SUCCESS);

    sc.parse_windows_auth_text(evtx("4672", "admin", "-"), 5000);
    ev = sc.collect_auth_events();
    CHECK(ev.size() == 1);
    CHECK(ev[0].type == AuthEventType::AUTH_PRIVILEGE_ESCALATION);

    sc.parse_windows_auth_text(evtx("4740", "eve", "10.0.0.10"), 6000);
    ev = sc.collect_auth_events();
    CHECK(ev.size() == 1);
    CHECK(ev[0].type == AuthEventType::AUTH_ACCOUNT_LOCKOUT);
    CHECK(ev[0].username == "eve");

    // Must not fire on a bare "4625" or the word "failed"
    sc.parse_windows_auth_text("build 4625 failed to package", 7000);
    ev = sc.collect_auth_events();
    CHECK(ev.empty());

    // Linux auth.log / secure
    sc.parse_linux_auth_text(
        "Nov 27 09:01:00 box sshd[11]: Failed password for alice from 192.0.2.10 port 22 ssh2",
        8000);
    ev = sc.collect_auth_events();
    CHECK(ev.size() == 1);
    CHECK(ev[0].type == AuthEventType::AUTH_LOGIN_FAILED);
    CHECK(ev[0].username == "alice");
    CHECK(ev[0].source_ip == "192.0.2.10");

    sc.parse_linux_auth_text(
        "Nov 27 09:01:01 box sshd[11]: Failed password for invalid user root from 192.0.2.11 port 22 ssh2",
        8100);
    ev = sc.collect_auth_events();
    CHECK(ev.size() == 1);
    CHECK(ev[0].username == "root");
    CHECK(ev[0].source_ip == "192.0.2.11");

    sc.parse_linux_auth_text(
        "Nov 27 09:02:00 box sshd[12]: Accepted publickey for alice from 192.0.2.10 port 22 ssh2",
        8200);
    ev = sc.collect_auth_events();
    CHECK(ev.size() == 1);
    CHECK(ev[0].type == AuthEventType::AUTH_LOGIN_SUCCESS);
    CHECK(ev[0].username == "alice");

    // Broad "Accepted" + "password" must not be a success
    sc.parse_linux_auth_text("mailer: Accepted terms, password hint mailed", 8300);
    ev = sc.collect_auth_events();
    CHECK(ev.empty());

    sc.parse_linux_auth_text(
        "Nov 27 09:03:00 box sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id",
        8400);
    ev = sc.collect_auth_events();
    CHECK(ev.size() == 1);
    CHECK(ev[0].type == AuthEventType::AUTH_PRIVILEGE_ESCALATION);
    CHECK(ev[0].username == "alice");
    CHECK(ev[0].detail.find("/usr/bin/id") != std::string::npos);

    // Source-tag dispatch (server path)
    SessionScanner tagged;
    tagged.parse_auth_record("windows-security", evtx("4625", "mallory", "203.0.113.5"), 9000);
    ev = tagged.collect_auth_events();
    CHECK(ev.size() == 1);
    CHECK(ev[0].type == AuthEventType::AUTH_LOGIN_FAILED);
    CHECK(ev[0].username == "mallory");

    tagged.parse_auth_record("linux-auth",
        "Nov 27 09:04:00 box sshd[9]: Accepted password for bob from 198.51.100.7 port 22 ssh2",
        9100);
    ev = tagged.collect_auth_events();
    CHECK(ev.size() == 1);
    CHECK(ev[0].type == AuthEventType::AUTH_LOGIN_SUCCESS);
    CHECK(ev[0].username == "bob");

    TEST_MAIN_RETURN();
}
