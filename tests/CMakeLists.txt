# =============================================================================
# SecureSeaHorse SIEM -- test suite (Phase 29)
# Dependency-free C++17 tests. Enable with -DBUILD_TESTS=ON (default ON at the
# root), then run with `ctest --test-dir <build>` or `ctest` from the build dir.
#
# Each test is registered only if its .cpp exists. This lets feature branches
# add tests without editing the same lines of this file, so they merge in any
# order. Add new tests to the list below.
# =============================================================================
set(SERVER_SRC "${CMAKE_SOURCE_DIR}/server/src")

set(CLIENT_SRC "${CMAKE_SOURCE_DIR}/client/src")

set(SEAHORSE_TESTS
    test_wire_parse
    test_deserializers
    test_config
    test_json_escape
    test_hunt
    test_rate_limiter
    test_ml
    test_auth_parsers
    test_auth_log_ingest
    test_log_tail
    test_parsers
    test_conf_honest
    test_sigma
    test_sigma_ingest
    test_rest_auth
)

foreach(t ${SEAHORSE_TESTS})
    if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${t}.cpp")
        continue()
    endif()
    add_executable(${t} ${t}.cpp)
    target_compile_features(${t} PRIVATE cxx_std_17)
    target_include_directories(${t} PRIVATE ${SERVER_SRC} ${CLIENT_SRC} ${CMAKE_CURRENT_SOURCE_DIR})
    if(MSVC)
        target_compile_definitions(${t} PRIVATE NOMINMAX _CRT_SECURE_NO_WARNINGS WIN32_LEAN_AND_MEAN)
    endif()
    add_test(NAME ${t} COMMAND ${t})
endforeach()

# test_conf_honest opens the shipped conf files from the source tree.
if(TARGET test_conf_honest)
    target_compile_definitions(test_conf_honest PRIVATE
        "SEAHORSE_SOURCE_DIR=\"${CMAKE_SOURCE_DIR}\"")
endif()

# test_sigma loads the sample packs from the source tree (cwd may be the build dir).
if(TARGET test_sigma)
    target_compile_definitions(test_sigma PRIVATE
        "SEAHORSE_SOURCE_DIR=\"${CMAKE_SOURCE_DIR}\"")
endif()

# Optional: full unread-key audit (lists every shipped key the code never
# conf.get-s). Skipped if Python is not on PATH or the script is absent.
find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_Interpreter_FOUND AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/check_conf_keys.py")
    add_test(NAME check_conf_keys
        COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/check_conf_keys.py"
                --root "${CMAKE_SOURCE_DIR}")
endif()
