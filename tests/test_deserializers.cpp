// Phase 29: regression tests for the wire deserializers -- the review 4.1 DoS.
// A malformed report from a connected agent must NEVER throw (an uncaught throw
// on the ingest path terminated the whole server). Malformed numeric fields
// degrade to defaults; a bad device_id becomes 0, which every handler treats as
// invalid/skip.
#include "test_util.h"
#include "process_monitor.h"
#include "connection_inventory.h"
#include "session_tracker.h"
#include "software_inventory.h"

int main() {
    std::printf("test_deserializers\n");

    // ---- The exact review crash input: valid device_id, non-numeric count ----
    CHECK_NOTHROW(deserialize_process_report("PROC|7001|123|notanumber\n"));
    {
        auto r = deserialize_process_report("PROC|7001|123|notanumber\n");
        CHECK(r.processes.empty());            // bad count -> 0 rows, no UB
    }

    // ---- Bad device_id field itself -> 0 (handler skips) ----
    {
        auto r = deserialize_process_report("PROC|notanumber|123|1\n");
        CHECK(r.device_id == 0);
    }

    // ---- Garbage headers on every report type: no throw, invalid (dev 0) ----
    CHECK_NOTHROW(deserialize_connection_report("CONN|x|y|z|w\n"));
    CHECK(deserialize_connection_report("CONN|x|y|z|w\n").device_id == 0);
    CHECK_NOTHROW(deserialize_session_report("SESS|bad|bad|bad|bad|bad\n"));
    CHECK(deserialize_session_report("SESS|bad|bad|bad|bad|bad\n").device_id == 0);
    CHECK_NOTHROW(deserialize_software_report("SWRPT|bad|bad|bad\n"));
    CHECK(deserialize_software_report("SWRPT|bad|bad|bad\n").device_id == 0);

    // ---- 64-bit overflow in a field must not throw ----
    CHECK_NOTHROW(deserialize_process_report("PROC|7001|999999999999999999999999|0\nPROC_END\n"));

    // ---- Truncated / empty / junk bodies ----
    CHECK_NOTHROW(deserialize_process_report(""));
    CHECK_NOTHROW(deserialize_process_report("PROC|"));
    CHECK_NOTHROW(deserialize_connection_report("not even a header"));
    CHECK_NOTHROW(deserialize_session_report(""));
    CHECK_NOTHROW(deserialize_software_report("SWRPT|1|2|999999999999999999999999\nX\n"));

    // ---- Happy paths still parse correctly ----
    {
        auto r = deserialize_process_report("PROC|7001|123|0\nPROC_CHANGES|0\nPROC_END\n");
        CHECK(r.device_id == 7001);
    }
    {
        auto r = deserialize_software_report("SWRPT|42|100|1\nnginx|1.24|nginx.org|2026-01-01|1048576\nSW_END\n");
        CHECK(r.device_id == 42);
        CHECK(r.software.size() == 1);
    }

    TEST_MAIN_RETURN();
}
