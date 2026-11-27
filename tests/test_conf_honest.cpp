// Assert shipped conf does not advertise unwired features as enabled.
#include "test_util.h"
#include <fstream>
#include <map>
#include <string>
#include <cctype>

#ifndef SEAHORSE_SOURCE_DIR
#define SEAHORSE_SOURCE_DIR "."
#endif

static std::string trim(std::string s) {
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.erase(s.begin());
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.pop_back();
    return s;
}

static std::map<std::string, std::string> load_conf(const std::string& path) {
    std::map<std::string, std::string> out;
    std::ifstream f(path);
    CHECK(f.good());
    std::string line;
    while (std::getline(f, line)) {
        auto hash = line.find('#');
        if (hash != std::string::npos) line = line.substr(0, hash);
        line = trim(line);
        if (line.empty()) continue;
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        out[trim(line.substr(0, eq))] = trim(line.substr(eq + 1));
    }
    return out;
}

static bool is_false(const std::string& v) {
    return v == "false" || v == "0" || v == "no" || v == "off";
}

int main() {
    std::printf("test_conf_honest\n");
    const std::string root = SEAHORSE_SOURCE_DIR;
    auto server = load_conf(root + "/server/config/server.conf");
    auto client = load_conf(root + "/client/config/client.conf");

    // These keys are not read by the v5.1.1-prep server/client. They must not
    // default to true in the shipped files.
    const char* server_false[] = {
        "sigma_enabled", "sigma_auto_reload",
        "reports_enabled", "usb_enabled", "ws_enabled",
        "updates_enabled", "soar_enabled",
        "syslog_listener_enabled", "syslog_forwarder_enabled"
    };
    for (const char* k : server_false) {
        CHECK(server.count(k) == 1);
        CHECK(is_false(server[k]));
    }
    const char* client_false[] = {
        "selfprotect_enabled", "selfprotect_watchdog",
        "selfprotect_accept_updates", "usb_monitor_enabled"
    };
    for (const char* k : client_false) {
        CHECK(client.count(k) == 1);
        CHECK(is_false(client[k]));
    }
    TEST_MAIN_RETURN();
}
