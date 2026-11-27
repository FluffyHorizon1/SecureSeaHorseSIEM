// REST auth is the front door of the hosted service. These tests pin the
// fail-closed contract: no credential configured => deny (never "open"), a
// shipped default token is never accepted, and the unauthenticated dev escape
// hatch only works on loopback with no other credential configured.
// Pure functions only -- no sockets.
#include <cstdio>
#include "test_util.h"
#include "rest_server.h"

static HttpRequest req_with(const std::string& authz) {
    HttpRequest r;
    r.method = "GET";
    r.path = "/api/stats";
    if (!authz.empty()) r.headers["authorization"] = authz;
    return r;
}

int main() {
    std::printf("test_rest_auth\n");

    // ---- constant_time_equals ------------------------------------------
    CHECK(constant_time_equals("", ""));
    CHECK(constant_time_equals("abc", "abc"));
    CHECK(!constant_time_equals("abc", "abd"));
    CHECK(!constant_time_equals("abc", "abcd"));
    CHECK(!constant_time_equals("abcd", "abc"));
    CHECK(!constant_time_equals("", "x"));
    CHECK(constant_time_equals(std::string("a\0b", 3), std::string("a\0b", 3)));
    CHECK(!constant_time_equals(std::string("a\0b", 3), std::string("a\0c", 3)));

    // ---- rest_authorize: static token ----------------------------------
    {
        RestConfig c; c.api_token = "s3cr3t-token-value";
        CHECK(rest_authorize(c, req_with("Bearer s3cr3t-token-value")) == AuthDecision::ALLOWED);
        CHECK(rest_authorize(c, req_with("Bearer wrong")) == AuthDecision::DENIED);
        CHECK(rest_authorize(c, req_with("Bearer s3cr3t-token-valu")) == AuthDecision::DENIED);   // prefix
        CHECK(rest_authorize(c, req_with("Bearer s3cr3t-token-value2")) == AuthDecision::DENIED); // extension
        CHECK(rest_authorize(c, req_with("")) == AuthDecision::DENIED);
        CHECK(rest_authorize(c, req_with("Basic s3cr3t-token-value")) == AuthDecision::DENIED);
        CHECK(rest_authorize(c, req_with("Bearer ")) == AuthDecision::DENIED);
        // dev flag must NOT open a server that has a token configured
        c.allow_unauthenticated = true;
        CHECK(rest_authorize(c, req_with("")) == AuthDecision::DENIED);
        CHECK(rest_authorize(c, req_with("Bearer wrong")) == AuthDecision::DENIED);
    }

    // ---- rest_authorize: nothing configured => fail closed -------------
    {
        RestConfig c;  // api_token empty, no alt_auth, allow_unauthenticated=false
        CHECK(rest_authorize(c, req_with("")) == AuthDecision::DENIED_NO_AUTH_CONFIGURED);
        CHECK(rest_authorize(c, req_with("Bearer anything")) == AuthDecision::DENIED_NO_AUTH_CONFIGURED);
        // an empty presented token must never equal an empty configured token
        CHECK(rest_authorize(c, req_with("Bearer ")) == AuthDecision::DENIED_NO_AUTH_CONFIGURED);
        c.allow_unauthenticated = true;   // explicit dev opt-in
        CHECK(rest_authorize(c, req_with("")) == AuthDecision::ALLOWED);
    }

    // ---- rest_authorize: RBAC / alt_auth ---------------------------------
    {
        RestConfig c;
        c.alt_auth = [](const HttpRequest& r) { return r.bearer_token() == "valid.jwt.sig"; };
        CHECK(rest_authorize(c, req_with("Bearer valid.jwt.sig")) == AuthDecision::ALLOWED);
        CHECK(rest_authorize(c, req_with("Bearer forged.jwt.sig")) == AuthDecision::DENIED);
        CHECK(rest_authorize(c, req_with("")) == AuthDecision::DENIED);
        // dev flag is ignored once a real mechanism exists
        c.allow_unauthenticated = true;
        CHECK(rest_authorize(c, req_with("")) == AuthDecision::DENIED);

        // token + alt_auth: the static token is IGNORED (it would bypass tenant
        // scoping). Only a credential accepted by alt_auth is allowed.
        c.api_token = "legacy-token-123456";
        CHECK(rest_authorize(c, req_with("Bearer legacy-token-123456")) == AuthDecision::DENIED);
        CHECK(rest_authorize(c, req_with("Bearer valid.jwt.sig")) == AuthDecision::ALLOWED);
        CHECK(rest_authorize(c, req_with("Bearer nope")) == AuthDecision::DENIED);
        c.allow_unauthenticated = true;
        CHECK(rest_authorize(c, req_with("Bearer legacy-token-123456")) == AuthDecision::DENIED);
        CHECK(rest_authorize(c, req_with("")) == AuthDecision::DENIED);

        // alt_auth is not even consulted without a presented token
        int calls = 0;
        c.alt_auth = [&calls](const HttpRequest&) { ++calls; return true; };
        CHECK(rest_authorize(c, req_with("")) == AuthDecision::DENIED);
        CHECK(calls == 0);
    }

    // ---- is_loopback_bind -------------------------------------------------
    CHECK(is_loopback_bind("127.0.0.1"));
    CHECK(is_loopback_bind("127.0.0.2"));
    CHECK(is_loopback_bind("::1"));
    CHECK(is_loopback_bind("localhost"));
    CHECK(!is_loopback_bind("0.0.0.0"));
    CHECK(!is_loopback_bind("::"));
    CHECK(!is_loopback_bind("10.0.0.5"));
    CHECK(!is_loopback_bind("192.168.1.10"));
    CHECK(!is_loopback_bind(""));
    CHECK(!is_loopback_bind("1127.0.0.1"));

    // ---- rest_exposure_decision (startup policy) ---------------------------
    const std::string strong = "k9Fq2Lm7Zx4Vb8Nc1Rt6Yw3Hd5Js0Pa";
    {   // disabled stays disabled
        auto d = rest_exposure_decision(false, "127.0.0.1", strong, false, false);
        CHECK(!d.enable);
    }
    {   // the old hole: empty token on loopback no longer starts implicitly
        auto d = rest_exposure_decision(true, "127.0.0.1", "", false, false);
        CHECK(!d.enable);
        CHECK(!d.message.empty());
    }
    {   // empty token, non-loopback: refused
        CHECK(!rest_exposure_decision(true, "0.0.0.0", "", false, false).enable);
    }
    {   // explicit dev opt-in: loopback only, with a warning
        auto d = rest_exposure_decision(true, "127.0.0.1", "", false, true);
        CHECK(d.enable); CHECK(d.warn);
        CHECK(!rest_exposure_decision(true, "0.0.0.0", "", false, true).enable);
        CHECK(!rest_exposure_decision(true, "10.1.2.3", "", false, true).enable);
    }
    {   // shipped default token is refused on every bind (even loopback, even with RBAC)
        CHECK(!rest_exposure_decision(true, "127.0.0.1", "changeme-rest-token", false, false).enable);
        CHECK(!rest_exposure_decision(true, "0.0.0.0", "changeme-rest-token", false, false).enable);
        CHECK(!rest_exposure_decision(true, "0.0.0.0", "changeme-rest-token", true, false).enable);
        CHECK(!rest_exposure_decision(true, "127.0.0.1", "changeme", false, true).enable);
    }
    {   // strong token: any bind
        auto a = rest_exposure_decision(true, "0.0.0.0", strong, false, false);
        CHECK(a.enable); CHECK(!a.warn);
        CHECK(rest_exposure_decision(true, "127.0.0.1", strong, false, false).enable);
    }
    {   // RBAC with no static token: any bind (JWT is the credential)
        auto a = rest_exposure_decision(true, "0.0.0.0", "", true, false);
        CHECK(a.enable); CHECK(!a.warn);
        CHECK(a.message.empty());
    }
    {   // RBAC + a strong static token: start is allowed, but the token is
        // ignored (warning). The message must not echo the token.
        auto a = rest_exposure_decision(true, "0.0.0.0", strong, true, false);
        CHECK(a.enable); CHECK(a.warn);
        CHECK(a.message.find("ignored") != std::string::npos);
        CHECK(a.message.find(strong) == std::string::npos);
        // allow_noauth does not change this
        auto b = rest_exposure_decision(true, "127.0.0.1", strong, true, true);
        CHECK(b.enable); CHECK(b.warn);
    }
    {   // messages never echo the token
        auto d = rest_exposure_decision(true, "0.0.0.0", "changeme-hunter2", false, false);
        CHECK(d.message.find("hunter2") == std::string::npos);
    }

    TEST_MAIN_RETURN();
}
