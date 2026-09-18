// Phase 29: tests for config parsing / clamping (server_protocol.h AppConfig).
#include "test_util.h"
#include "server_protocol.h"

int main() {
    std::printf("test_config\n");

    AppConfig c;
    c.set("port", "65432");
    c.set("flag_true", "true");
    c.set("flag_yes", "YES");
    c.set("flag_zero", "0");
    c.set("threads", "9999");
    c.set("bad_int", "not-an-int");

    CHECK(c.get("missing", "def") == "def");
    CHECK(c.get_int("port", 0) == 65432);
    CHECK(c.get_int("bad_int", 7) == 7);            // non-numeric -> default, no throw
    CHECK(c.get_bool("flag_true", false) == true);
    CHECK(c.get_bool("flag_yes", false) == true);
    CHECK(c.get_bool("flag_zero", true) == false);
    CHECK(c.get_bool("missing", true) == true);

    // Clamp guards resource-allocation keys
    CHECK(c.get_int_clamped("threads", 2, 1, 32) == 32);   // above max -> max
    CHECK(c.get_int_clamped("missing", 4, 1, 32) == 4);    // default within range
    CHECK(c.get_int_clamped("bad_int", 50, 1, 32) == 32);  // default itself clamped

    TEST_MAIN_RETURN();
}
