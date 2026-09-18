#ifndef SEAHORSE_TEST_UTIL_H
#define SEAHORSE_TEST_UTIL_H
// Dependency-free micro test harness (Phase 29). No gtest, no external libs --
// the project's whole point is a minimal dependency surface, and the tests
// honour that. Each test file has its own main() and returns the failure count;
// CTest treats non-zero as failure.
#include <cstdio>
#include <string>

namespace seahorse_test {
inline int& fail_count() { static int n = 0; return n; }

inline void check(bool ok, const char* expr, const char* file, int line) {
    if (ok) {
        std::printf("  [PASS] %s\n", expr);
    } else {
        std::printf("  [FAIL] %s  (%s:%d)\n", expr, file, line);
        ++fail_count();
    }
}
} // namespace seahorse_test

#define CHECK(cond) ::seahorse_test::check((cond), #cond, __FILE__, __LINE__)

// Wrap a body that must not throw; a throw is a failure, not a crash.
#define CHECK_NOTHROW(stmt) do { \
    try { stmt; ::seahorse_test::check(true, "no throw: " #stmt, __FILE__, __LINE__); } \
    catch (...) { ::seahorse_test::check(false, "threw: " #stmt, __FILE__, __LINE__); } \
} while (0)

#define TEST_MAIN_RETURN() do { \
    int f = ::seahorse_test::fail_count(); \
    std::printf("%s (%d failure%s)\n", f ? "FAILURES" : "ALL GREEN", f, f==1?"":"s"); \
    return f; \
} while (0)

#endif
