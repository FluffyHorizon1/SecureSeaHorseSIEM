// Phase 29: unit tests for the safe wire-field parsers (wire_parse.h).
#include "test_util.h"
#include "wire_parse.h"

using namespace seahorse::wire;

int main() {
    std::printf("test_wire_parse\n");

    // Happy path
    CHECK(to_i32("42") == 42);
    CHECK(to_i64("-9000000000") == -9000000000LL);
    CHECK(to_u32("7001") == 7001u);
    CHECK(to_u64("18000000000") == 18000000000ULL);

    // Malformed -> default, never throws
    CHECK(to_i32("notanumber") == 0);
    CHECK(to_i32("notanumber", -1) == -1);
    CHECK(to_u32("") == 0u);
    CHECK(to_u64("   ") == 0u);
    CHECK(to_i64("abc123") == 0);          // leading non-digit -> default

    // Out-of-range -> default, never throws (this is the crash class)
    CHECK(to_i32("999999999999999999999999") == 0);
    CHECK(to_u64("999999999999999999999999999999") == 0u);

    // Prefix numeric (std::stol semantics) is accepted
    CHECK(to_i32("123abc") == 123);

    TEST_MAIN_RETURN();
}
