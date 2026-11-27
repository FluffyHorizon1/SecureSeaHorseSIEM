// Integration / e2e: sample 4624/4625 XML plus auth.log/secure lines travel
// through the MSG_LOG_BATCH framing, the server ingest path, AlertEngine,
// and CorrelationEngine. Asserts parsed auth events plus a brute-force
// alert and the auth_brute_force correlation incident.
#include "test_util.h"
#include "log_batch.h"
#include "auth_log_ingest.h"

#include <chrono>
#include <string>
#include <cstdio>

static std::string evtx(const char* id, const char* user, const char* ip) {
    return std::string("<Event><System><EventID>") + id +
           "</EventID><Level>0</Level></System><EventData>"
           "<Data Name=\"TargetUserName\">" + user + "</Data>"
           "<Data Name=\"IpAddress\">" + ip + "</Data>"
           "</EventData></Event>";
}

static int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

int main() {
    std::printf("test_auth_log_ingest\n");

    // --- Framing round-trip, including a multi-line XML record ---
    LogBatch in;
    in.device_id = 7001;
    in.timestamp_ms = 42;
    in.records.push_back({kAuthSourceWindowsSecurity, 42, evtx("4625", "alice", "10.0.0.1")});
    in.records.push_back({kAuthSourceLinuxAuth, 42,
        "Nov 27 09:01:00 box sshd[1]: Failed password for alice from 192.0.2.10 port 22 ssh2"});
    std::string wire = serialize_log_batch(in);
    LogBatch out = deserialize_log_batch(wire);
    CHECK(out.device_id == 7001);
    CHECK(out.records.size() == 2);
    CHECK(out.records[0].source == kAuthSourceWindowsSecurity);
    CHECK(out.records[0].text.find("<EventID>4625</EventID>") != std::string::npos);
    CHECK(out.records[1].source == kAuthSourceLinuxAuth);
    CHECK(out.records[1].text.find("Failed password") != std::string::npos);

    LogBatch bad = deserialize_log_batch("NOT-A-BATCH\n");
    CHECK(bad.device_id == 0 && bad.records.empty());

    // XPath constant is the published Windows query (EventID, not Level<=3).
    std::string xpath = kWindowsAuthXPath;
    CHECK(xpath.find("EventID=4624") != std::string::npos);
    CHECK(xpath.find("EventID=4625") != std::string::npos);
    CHECK(xpath.find("EventID=4634") != std::string::npos);
    CHECK(xpath.find("EventID=4648") != std::string::npos);
    CHECK(xpath.find("EventID=4672") != std::string::npos);
    CHECK(xpath.find("EventID=4740") != std::string::npos);
    CHECK(xpath.find("Level") == std::string::npos);

    // --- e2e: 3 failed 4625 + 3 failed ssh + one accepted + sudo ---
    const int64_t ts = now_ms();
    LogBatch batch;
    batch.device_id = 42;
    batch.timestamp_ms = ts;
    for (int i = 0; i < 3; ++i) {
        LogRecord r;
        r.source = kAuthSourceWindowsSecurity;
        r.timestamp_ms = ts;
        r.text = evtx("4625", "alice", "203.0.113.10");
        batch.records.push_back(std::move(r));
    }
    for (int i = 0; i < 3; ++i) {
        LogRecord r;
        r.source = kAuthSourceLinuxAuth;
        r.timestamp_ms = ts;
        r.text = "Nov 27 09:10:0" + std::to_string(i) +
                 " box sshd[9]: Failed password for bob from 198.51.100.7 port 22 ssh2";
        batch.records.push_back(std::move(r));
    }
    {
        LogRecord r;
        r.source = kAuthSourceLinuxAuth;
        r.timestamp_ms = ts;
        r.text = "Nov 27 09:10:09 box sshd[9]: Accepted publickey for bob from 198.51.100.7 port 22 ssh2";
        batch.records.push_back(std::move(r));
    }
    {
        LogRecord r;
        r.source = kAuthSourceLinuxAuth;
        r.timestamp_ms = ts;
        r.text = "Nov 27 09:10:10 box sudo: bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/id";
        batch.records.push_back(std::move(r));
    }

    // Round-trip as the agent would send it, then ingest as the server would.
    LogBatch on_wire = deserialize_log_batch(serialize_log_batch(batch));
    CHECK(on_wire.records.size() == batch.records.size());

    AlertConfig ac;
    ac.enabled = true;
    ac.alert_log_path = ""; // no file; still counts
    ac.load_defaults();
    AlertEngine alerts(ac);
    CorrelationEngine corr;
    CHECK(corr.rule_count() >= 8); // includes auth_brute_force

    SessionScanner scanner;
    AuthIngestHooks hooks;
    hooks.alerts = &alerts;
    hooks.correlator = &corr;
    auto events = ingest_log_batch(scanner, on_wire, "198.51.100.7", hooks);

    int fails = 0, succ = 0, priv = 0;
    bool saw_alice = false, saw_bob = false;
    for (const auto& e : events) {
        if (e.type == AuthEventType::AUTH_LOGIN_FAILED) {
            ++fails;
            if (e.username == "alice") saw_alice = true;
            if (e.username == "bob") saw_bob = true;
        }
        if (e.type == AuthEventType::AUTH_LOGIN_SUCCESS) ++succ;
        if (e.type == AuthEventType::AUTH_PRIVILEGE_ESCALATION) ++priv;
    }
    CHECK(fails == 6);
    CHECK(succ == 1);
    CHECK(priv == 1);
    CHECK(saw_alice && saw_bob);

    // 6 failed logons, each also counted as brute_force: 3-in-60s fires.
    CHECK(alerts.total_alerts_fired() >= 1);

    bool saw_brute = false;
    for (const auto& inc : corr.get_recent_incidents(50)) {
        if (inc.rule_name == "auth_brute_force") saw_brute = true;
    }
    CHECK(saw_brute);
    CHECK(corr.total_incidents() >= 1);

    TEST_MAIN_RETURN();
}
