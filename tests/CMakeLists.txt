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
)

foreach(t ${SEAHORSE_TESTS})
    add_executable(${t} ${t}.cpp)
    target_include_directories(${t} PRIVATE ${SERVER_SRC} ${CMAKE_CURRENT_SOURCE_DIR})
    if(MSVC)
        target_compile_definitions(${t} PRIVATE NOMINMAX _CRT_SECURE_NO_WARNINGS)
    endif()
    add_test(NAME ${t} COMMAND ${t})
endforeach()
