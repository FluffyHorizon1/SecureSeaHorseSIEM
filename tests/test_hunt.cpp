// Phase 33: tests for the Hunt DSL compiler -- this is the injection boundary,
// so the field allowlist and parameterisation are the properties under test.
#include "test_util.h"
#include "hunt_query.h"

int main() {
    std::printf("test_hunt\n");

    // Valid query compiles, binds the literal as a parameter (not concatenated).
    {
        HuntResult r = compile_hunt("search threats | where severity=critical | head 5");
        CHECK(r.ok);
        CHECK(r.compiled.sql.find("$1") != std::string::npos);      // parameter placeholder
        CHECK(r.compiled.params.size() == 1);
        CHECK(r.compiled.params.size() == 1 && r.compiled.params[0] == "critical");
        CHECK(r.compiled.sql.find("threat_detections") != std::string::npos); // real table
    }

    // Unknown source is rejected.
    {
        HuntResult r = compile_hunt("search not_a_table | head 5");
        CHECK(!r.ok);
    }

    // Non-whitelisted field is rejected at compile time (allowlist).
    {
        HuntResult r = compile_hunt("search threats | where evil_col=1");
        CHECK(!r.ok);
    }

    // Injection attempt in a VALUE is bound as a parameter, never inlined.
    {
        HuntResult r = compile_hunt("search threats | where severity=\"x'; DROP TABLE threat_detections;--\"");
        CHECK(r.ok);
        // The dangerous text is a bound parameter, and does NOT appear inline in SQL.
        bool in_params = false;
        for (auto& p : r.compiled.params) if (p.find("DROP TABLE") != std::string::npos) in_params = true;
        CHECK(in_params);
        CHECK(r.compiled.sql.find("DROP TABLE") == std::string::npos);
    }

    // A sort field must also be on the allowlist.
    {
        HuntResult r = compile_hunt("search ioc | sort evil_col desc");
        CHECK(!r.ok);
    }

    TEST_MAIN_RETURN();
}
