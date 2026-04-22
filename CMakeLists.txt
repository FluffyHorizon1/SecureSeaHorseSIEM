cmake_minimum_required(VERSION 3.15)
project(SecureSeaHorseSIEM VERSION 3.0.0 LANGUAGES CXX)

# ==============================================================================
# 1. Project Settings
# ==============================================================================
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Source directories (split server / client)
set(SERVER_SRC "${CMAKE_CURRENT_SOURCE_DIR}/src/server")
set(CLIENT_SRC "${CMAKE_CURRENT_SOURCE_DIR}/src/client")
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

# Fallback: add common PostgreSQL include paths if not found
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
# 4. Target: SeaHorseServer               (all files from src/server/)
# ==============================================================================
#
#   Server-only:
#     server.cpp, server_protocol.h, regex_engine.h, alert_engine.h, db_layer.h,
#     traffic_classifier.h, baseline_tracker.h, mitre_map.h, threat_intel.h,
#     fim_monitor.h, rest_server.h, dashboard_html.h, incident_response.h,
#     fleet_manager.h, network_inspector.h, correlation_engine.h
#
#   Shared (duplicated from client):
#     crypto_utils.h, fim_common.h, process_monitor.h,
#     connection_inventory.h, session_tracker.h, software_inventory.h
#
add_executable(SeaHorseServer
    ${SERVER_SRC}/server.cpp
    # --- Shared headers ---
    ${SERVER_SRC}/crypto_utils.h
    ${SERVER_SRC}/fim_common.h
    ${SERVER_SRC}/process_monitor.h
    ${SERVER_SRC}/connection_inventory.h
    ${SERVER_SRC}/session_tracker.h
    ${SERVER_SRC}/software_inventory.h
    # --- Server-only headers ---
    ${SERVER_SRC}/server_protocol.h
    ${SERVER_SRC}/regex_engine.h
    ${SERVER_SRC}/alert_engine.h
    ${SERVER_SRC}/db_layer.h
    ${SERVER_SRC}/traffic_classifier.h
    ${SERVER_SRC}/baseline_tracker.h
    ${SERVER_SRC}/mitre_map.h
    ${SERVER_SRC}/threat_intel.h
    ${SERVER_SRC}/fim_monitor.h
    ${SERVER_SRC}/rest_server.h
    ${SERVER_SRC}/dashboard_html.h
    ${SERVER_SRC}/incident_response.h
    ${SERVER_SRC}/fleet_manager.h
    ${SERVER_SRC}/network_inspector.h
    ${SERVER_SRC}/correlation_engine.h
)

target_include_directories(SeaHorseServer PRIVATE ${SERVER_SRC} ${PG_INCLUDES})
target_link_libraries(SeaHorseServer PRIVATE OpenSSL::SSL OpenSSL::Crypto ${PG_LIBS})
if(WIN32)
    target_link_libraries(SeaHorseServer PRIVATE ws2_32 wsock32)
endif()

# ==============================================================================
# 5. Target: SeaHorseClient               (all files from src/client/)
# ==============================================================================
#
#   Client-only:
#     client.cpp, client_protocol.h, fim_scanner.h
#
#   Shared (duplicated from server):
#     crypto_utils.h, fim_common.h, process_monitor.h,
#     connection_inventory.h, session_tracker.h, software_inventory.h
#
add_executable(SeaHorseClient
    ${CLIENT_SRC}/client.cpp
    # --- Shared headers ---
    ${CLIENT_SRC}/crypto_utils.h
    ${CLIENT_SRC}/fim_common.h
    ${CLIENT_SRC}/process_monitor.h
    ${CLIENT_SRC}/connection_inventory.h
    ${CLIENT_SRC}/session_tracker.h
    ${CLIENT_SRC}/software_inventory.h
    # --- Client-only headers ---
    ${CLIENT_SRC}/client_protocol.h
    ${CLIENT_SRC}/fim_scanner.h
)

target_include_directories(SeaHorseClient PRIVATE ${CLIENT_SRC})
target_link_libraries(SeaHorseClient PRIVATE OpenSSL::SSL OpenSSL::Crypto)
if(WIN32)
    target_link_libraries(SeaHorseClient PRIVATE ws2_32 iphlpapi wevtapi wtsapi32 psapi)
endif()

# ==============================================================================
# 6. Post-Build: Copy Config & Data Files
# ==============================================================================
file(COPY "${CONFIG_DIR}/server.conf" DESTINATION "${CMAKE_BINARY_DIR}")
file(COPY "${CONFIG_DIR}/client.conf" DESTINATION "${CMAKE_BINARY_DIR}")
file(COPY "${CONFIG_DIR}/rules.conf"  DESTINATION "${CMAKE_BINARY_DIR}")

if(EXISTS "${CONFIG_DIR}/feeds")
    file(COPY "${CONFIG_DIR}/feeds" DESTINATION "${CMAKE_BINARY_DIR}")
    message(STATUS "Copied threat intel feeds directory")
endif()

message(STATUS "Build configuration complete. Version ${PROJECT_VERSION}")
