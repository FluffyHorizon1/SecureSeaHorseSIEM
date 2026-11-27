# =============================================================================
# SecureSeaHorse SIEM -- test suite (Phase 29)
# Dependency-free C++17 tests. Enable with -DBUILD_TESTS=ON (default ON at the
# root), then run with `ctest --test-dir <build>` or `ctest` from the build dir.
# =============================================================================
set(SERVER_SRC "${CMAKE_SOURCE_DIR}/server/src")

set(SEAHORSE_TESTS
    test_wire_parse
    test_deserializers
    test_config
    test_json_escape
    test_hunt
    test_ml
    test_conf_honest
)

foreach(t ${SEAHORSE_TESTS})
    add_executable(${t} ${t}.cpp)
    target_compile_features(${t} PRIVATE cxx_std_17)
    target_include_directories(${t} PRIVATE ${SERVER_SRC} ${CMAKE_CURRENT_SOURCE_DIR})
    if(MSVC)
        target_compile_definitions(${t} PRIVATE NOMINMAX _CRT_SECURE_NO_WARNINGS WIN32_LEAN_AND_MEAN)
    endif()
    add_test(NAME ${t} COMMAND ${t})
endforeach()

# test_conf_honest opens the shipped conf files from the source tree.
target_compile_definitions(test_conf_honest PRIVATE
    "SEAHORSE_SOURCE_DIR=\"${CMAKE_SOURCE_DIR}\"")

# Optional: full unread-key audit (lists every shipped key the code never
# conf.get-s). Skipped if Python is not on PATH.
find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_Interpreter_FOUND)
    add_test(NAME check_conf_keys
        COMMAND ${Python3_EXECUTABLE} "${CMAKE_SOURCE_DIR}/tests/check_conf_keys.py"
                --root "${CMAKE_SOURCE_DIR}")
endif()
