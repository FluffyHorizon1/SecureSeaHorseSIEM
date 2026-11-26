// Tests for FailureThrottle (login brute-force protection). The clock is
// injected, so no sleeping.
#include <cstdio>
#include "test_util.h"
#include "rate_limiter.h"

int main() {
    std::printf("test_rate_limiter\n");

    FailureThrottle::Config c;
    c.max_failures = 3; c.window_ms = 1000; c.lockout_ms = 5000; c.max_keys = 4;

    // ---- threshold & lockout ------------------------------------------------
    {
        FailureThrottle t(c);
        CHECK(t.retry_after_ms("a", 0) == 0);
        t.record_failure("a", 0);
        t.record_failure("a", 10);
        CHECK(t.retry_after_ms("a", 20) == 0);          // 2 < 3: still allowed
        t.record_failure("a", 20);                      // 3rd failure -> lock
        CHECK(t.retry_after_ms("a", 21) == 5000 - 1);   // locked until 20+5000
        CHECK(t.retry_after_ms("a", 4999) == 21);
        CHECK(t.retry_after_ms("a", 5020) == 0);        // expired exactly at lock end
        CHECK(t.retry_after_ms("a", 99999) == 0);
        // other keys unaffected
        CHECK(t.retry_after_ms("b", 21) == 0);
    }
    // ---- failures outside the window do not accumulate ---------------------------
    {
        FailureThrottle t(c);
        t.record_failure("a", 0);
        t.record_failure("a", 100);
        t.record_failure("a", 1200);   // first two aged out (window 1000)
        CHECK(t.retry_after_ms("a", 1201) == 0);
        t.record_failure("a", 1300);
        t.record_failure("a", 1400);   // 3 within window: 1200,1300,1400
        CHECK(t.retry_after_ms("a", 1401) > 0);
    }
    // ---- failures while locked do not extend the lock --------------------------------
    {
        FailureThrottle t(c);
        t.record_failure("a", 0); t.record_failure("a", 1); t.record_failure("a", 2);   // locked until 5002
        for (int i = 0; i < 50; ++i) t.record_failure("a", 100 + i);
        CHECK(t.retry_after_ms("a", 5002) == 0);
    }
    // ---- success clears history --------------------------------------------------------
    {
        FailureThrottle t(c);
        t.record_failure("a", 0); t.record_failure("a", 1);
        t.record_success("a");
        t.record_failure("a", 2); t.record_failure("a", 3);
        CHECK(t.retry_after_ms("a", 4) == 0);           // only 2 since the reset
        CHECK(t.tracked_keys() == 1);
        t.record_success("a");
        CHECK(t.tracked_keys() == 0);
    }
    // ---- after a lock expires the key gets a fresh budget ----------------------------------
    {
        FailureThrottle t(c);
        t.record_failure("a", 0); t.record_failure("a", 1); t.record_failure("a", 2);
        CHECK(t.retry_after_ms("a", 10) > 0);
        t.record_failure("a", 6000); t.record_failure("a", 6001);
        CHECK(t.retry_after_ms("a", 6002) == 0);
        t.record_failure("a", 6002);
        CHECK(t.retry_after_ms("a", 6003) > 0);
    }
    // ---- disabled (max_failures == 0) -----------------------------------------------------------
    {
        FailureThrottle::Config d = c; d.max_failures = 0;
        FailureThrottle t(d);
        for (int i = 0; i < 100; ++i) t.record_failure("a", i);
        CHECK(t.retry_after_ms("a", 101) == 0);
        CHECK(t.tracked_keys() == 0);
    }
    // ---- memory bound (max_keys) -------------------------------------------------------------------
    {
        FailureThrottle t(c);   // max_keys = 4
        for (int i = 0; i < 1000; ++i) t.record_failure("k" + std::to_string(i), i);
        CHECK(t.tracked_keys() <= 4);
        // expired entries are swept before live ones are evicted: a locked key
        // survives a flood of fresh single-failure keys only if it is the most recent;
        // at minimum the bound holds and the API keeps working.
        CHECK_NOTHROW(t.record_failure("zzz", 5000));
    }
    {   // dead entries are swept first, so a LIVE locked key is not evicted when stale ones exist
        FailureThrottle t(c);
        t.record_failure("stale1", 0); t.record_failure("stale2", 0); t.record_failure("stale3", 0);
        t.record_failure("locked", 9000); t.record_failure("locked", 9001); t.record_failure("locked", 9002);
        t.record_failure("new", 9003);    // map full (4) -> sweep stale1..3 -> room
        CHECK(t.retry_after_ms("locked", 9004) > 0);
        CHECK(t.tracked_keys() == 2);
    }
    // ---- key normalisation ---------------------------------------------------------------------------------
    CHECK(FailureThrottle::normalize_key("Alice@Example.COM") == "alice@example.com");
    CHECK(FailureThrottle::normalize_key(std::string(500, 'A')).size() == 128);
    CHECK(FailureThrottle::normalize_key("") == "");

    TEST_MAIN_RETURN();
}
