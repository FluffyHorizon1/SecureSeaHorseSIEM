// Phase 29: tests for HttpResponse::json_escape -- the server builds JSON by
// hand, so correct escaping of attacker-influenced fields (log lines, paths)
// is a security property, not a nicety.
#include <iomanip>
#include <cstdio>
#include <cctype>
#include "test_util.h"
#include "rest_server.h"

int main() {
    std::printf("test_json_escape\n");

    CHECK(HttpResponse::json_escape("plain") == "plain");
    CHECK(HttpResponse::json_escape("a\"b") == "a\\\"b");
    CHECK(HttpResponse::json_escape("a\\b") == "a\\\\b");
    CHECK(HttpResponse::json_escape("line1\nline2") == "line1\\nline2");
    CHECK(HttpResponse::json_escape("tab\there") == "tab\\there");
    CHECK(HttpResponse::json_escape("cr\r") == "cr\\r");

    // A quote-injection attempt in a value cannot break out of the JSON string:
    // every embedded quote is emitted as \" so the value stays one JSON string.
    std::string evil = "x\",\"admin\":true";             // x","admin":true
    std::string esc  = HttpResponse::json_escape(evil);
    CHECK(esc == "x\\\",\\\"admin\\\":true");            // exact escaped form
    // No unescaped quote remains (every '"' is preceded by a backslash).
    bool unescaped_quote = false;
    for (size_t i = 0; i < esc.size(); ++i)
        if (esc[i] == '"' && (i == 0 || esc[i-1] != '\\')) unescaped_quote = true;
    CHECK(!unescaped_quote);

    TEST_MAIN_RETURN();
}
