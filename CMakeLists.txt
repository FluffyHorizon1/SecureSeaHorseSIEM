cmake_minimum_required(VERSION 3.15)
project(SecureSeaHorseSIEM VERSION 5.0.0 LANGUAGES CXX)

# ==============================================================================
# 1. Project Settings
# ==============================================================================
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(SERVER_SRC "${CMAKE_CURRENT_SOURCE_DIR}/src/server")
set(CLIENT_SRC "${CMAKE_CURRENT_SOURCE_DIR}/src/client")
set(WEBUI_SRC  "${CMAKE_CURRENT_SOURCE_DIR}/src/webui")
set(CONFIG_DIR "${CMAKE_CURRENT_SOURCE_DIR}/config")

# ==============================================================================
# 2. Find Dependencies
# ==============================================================================
find_package(OpenSSL REQUIRED)

find_package(libpq CONFIG QUIET)
if(libpq_FOUND)
    message(STATUS "Found libpq via vcpkg config")
    set(PG_LIBS libpq::libpq)
    set(PG_INCLUDES "")
else()
    message(STATUS "Searching for system PostgreSQL...")
    find_package(PostgreSQL REQUIRED)
    set(PG_LIBS ${PostgreSQL_LIBRARIES})
    set(PG_INCLUDES ${PostgreSQL_INCLUDE_DIRS})
endif()

if(NOT PG_INCLUDES)
    find_path(PG_INCLUDE_DIR libpq-fe.h
        PATHS /usr/include /usr/include/postgresql /usr/local/include
        PATH_SUFFIXES postgresql
    )
    if(PG_INCLUDE_DIR)
        set(PG_INCLUDES ${PG_INCLUDE_DIR})
    endif()
endif()

# ==============================================================================
# 3. Global Compiler Flags
# ==============================================================================
if(MSVC)
    add_compile_definitions(NOMINMAX _CRT_SECURE_NO_WARNINGS)
    add_compile_options(/W3)
else()
    add_compile_options(-Wall -Wextra)
endif()

# ==============================================================================
# 4. Target: SeaHorseServer              (all files from src/server/)
# ==============================================================================
add_executable(SeaHorseServer
    ${SERVER_SRC}/server.cpp

    # --- Shared headers (duplicated from client) ---
    ${SERVER_SRC}/crypto_utils.h
    ${SERVER_SRC}/fim_common.h
    ${SERVER_SRC}/process_monitor.h
    ${SERVER_SRC}/connection_inventory.h
    ${SERVER_SRC}/session_tracker.h
    ${SERVER_SRC}/software_inventory.h

    # --- Core server (phases 1-15) ---
    ${SERVER_SRC}/server_protocol.h
    ${SERVER_SRC}/regex_engine.h
    ${SERVER_SRC}/alert_engine.h
    ${SERVER_SRC}/db_layer.h
    ${SERVER_SRC}/traffic_classifier.h
    ${SERVER_SRC}/baseline_tracker.h
    ${SERVER_SRC}/mitre_map.h
    ${SERVER_SRC}/threat_intel.h
    ${SERVER_SRC}/fim_monitor.h
    ${SERVER_SRC}/fim_scanner.h
    ${SERVER_SRC}/rest_server.h
    ${SERVER_SRC}/dashboard_html.h
    ${SERVER_SRC}/incident_response.h
    ${SERVER_SRC}/fleet_manager.h
    ${SERVER_SRC}/network_inspector.h
    ${SERVER_SRC}/correlation_engine.h

    # --- New in phases 16-25 ---
    ${SERVER_SRC}/sigma_engine.h        # Phase 16
    ${SERVER_SRC}/report_generator.h    # Phase 18
    ${SERVER_SRC}/usb_monitor.h         # Phase 19 (shared struct / deserializer)
    ${SERVER_SRC}/rbac.h                # Phase 20
    ${SERVER_SRC}/soar_connector.h      # Phase 21
    ${SERVER_SRC}/syslog_io.h           # Phase 22
    ${SERVER_SRC}/hunt_query.h          # Phase 23
    ${SERVER_SRC}/ml_anomaly.h          # Phase 24
)

target_include_directories(SeaHorseServer PRIVATE ${SERVER_SRC} ${PG_INCLUDES})
target_link_libraries(SeaHorseServer PRIVATE OpenSSL::SSL OpenSSL::Crypto ${PG_LIBS})
if(WIN32)
    target_link_libraries(SeaHorseServer PRIVATE ws2_32 wsock32)
endif()

# ==============================================================================
# 5. Target: SeaHorseClient              (all files from src/client/)
# ==============================================================================
add_executable(SeaHorseClient
    ${CLIENT_SRC}/client.cpp

    # --- Shared headers (duplicated from server) ---
    ${CLIENT_SRC}/crypto_utils.h
    ${CLIENT_SRC}/fim_common.h
    ${CLIENT_SRC}/process_monitor.h
    ${CLIENT_SRC}/connection_inventory.h
    ${CLIENT_SRC}/session_tracker.h
    ${CLIENT_SRC}/software_inventory.h

    # --- Client-only (phases 1-15) ---
    ${CLIENT_SRC}/client_protocol.h
    ${CLIENT_SRC}/fim_scanner.h

    # --- New in phases 16-25 ---
    ${CLIENT_SRC}/self_protection.h     # Phase 17
    ${CLIENT_SRC}/usb_monitor.h         # Phase 19
)

target_include_directories(SeaHorseClient PRIVATE ${CLIENT_SRC})
target_link_libraries(SeaHorseClient PRIVATE OpenSSL::SSL OpenSSL::Crypto)
if(WIN32)
    target_link_libraries(SeaHorseClient PRIVATE
        ws2_32 iphlpapi wevtapi wtsapi32 psapi
        setupapi cfgmgr32              # Phase 19: USB enumeration on Windows
    )
endif()

# ==============================================================================
# 6. Post-Build: Copy Config, Data, and Web UI
# ==============================================================================
file(COPY "${CONFIG_DIR}/server.conf" DESTINATION "${CMAKE_BINARY_DIR}")
file(COPY "${CONFIG_DIR}/client.conf" DESTINATION "${CMAKE_BINARY_DIR}")
file(COPY "${CONFIG_DIR}/rules.conf"  DESTINATION "${CMAKE_BINARY_DIR}")

if(EXISTS "${CONFIG_DIR}/feeds")
    file(COPY "${CONFIG_DIR}/feeds" DESTINATION "${CMAKE_BINARY_DIR}")
    message(STATUS "Copied threat intel feeds directory")
endif()

if(EXISTS "${CONFIG_DIR}/sigma_rules")
    file(COPY "${CONFIG_DIR}/sigma_rules" DESTINATION "${CMAKE_BINARY_DIR}")
    message(STATUS "Copied Sigma rules directory")
endif()

if(EXISTS "${WEBUI_SRC}/index.html")
    file(COPY "${WEBUI_SRC}" DESTINATION "${CMAKE_BINARY_DIR}")
    message(STATUS "Copied Phase 25 Web UI scaffold to build/webui/")
endif()

message(STATUS "Build configuration complete. Version ${PROJECT_VERSION}")
message(STATUS "  Phases 1-15:  core platform")
message(STATUS "  Phase 16:     Sigma rule engine")
message(STATUS "  Phase 17:     Agent self-protection")
message(STATUS "  Phase 18:     Compliance reporting")
message(STATUS "  Phase 19:     USB monitor (client)")
message(STATUS "  Phase 20:     Multi-tenancy + RBAC")
message(STATUS "  Phase 21:     SOAR integration")
message(STATUS "  Phase 22:     Syslog I/O")
message(STATUS "  Phase 23:     Hunt query DSL")
message(STATUS "  Phase 24:     ML anomaly detection")
message(STATUS "  Phase 25:     React Web UI scaffold")
