cmake_minimum_required(VERSION 3.15)
project(SeaHorseServer VERSION 5.0.0 LANGUAGES CXX)

# ==============================================================================
# SecureSeaHorse SIEM -- SERVER (standalone build)
# Build:  mkdir build && cd build && cmake .. && cmake --build . --config Release
# ==============================================================================
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(SRC "${CMAKE_CURRENT_SOURCE_DIR}/src")
set(CONFIG_DIR "${CMAKE_CURRENT_SOURCE_DIR}/config")

# ==============================================================================
# Dependencies: OpenSSL (required), PostgreSQL client (required for server)
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
# Compiler flags
# ==============================================================================
if(MSVC)
    add_compile_definitions(NOMINMAX _CRT_SECURE_NO_WARNINGS)
    add_compile_options(/W3)
else()
    add_compile_options(-Wall -Wextra)
endif()

# ==============================================================================
# Target
# ==============================================================================
file(GLOB SERVER_HEADERS "${SRC}/*.h")
add_executable(SeaHorseServer
    ${SRC}/server.cpp
    ${SERVER_HEADERS}
)

target_include_directories(SeaHorseServer PRIVATE ${SRC} ${PG_INCLUDES})
target_link_libraries(SeaHorseServer PRIVATE OpenSSL::SSL OpenSSL::Crypto ${PG_LIBS})
if(WIN32)
    target_link_libraries(SeaHorseServer PRIVATE ws2_32 wsock32)
endif()

# ==============================================================================
# Post-configure: stage runtime files next to the binary
# ==============================================================================
file(COPY "${CONFIG_DIR}/server.conf"        DESTINATION "${CMAKE_BINARY_DIR}")
file(COPY "${CONFIG_DIR}/rules.conf"         DESTINATION "${CMAKE_BINARY_DIR}")
file(COPY "${CONFIG_DIR}/usb_whitelist.csv"  DESTINATION "${CMAKE_BINARY_DIR}")
file(COPY "${CONFIG_DIR}/sigma"              DESTINATION "${CMAKE_BINARY_DIR}")

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/feeds")
    file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/feeds" DESTINATION "${CMAKE_BINARY_DIR}")
    message(STATUS "Copied threat intel feeds directory")
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/updates")
    file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/updates" DESTINATION "${CMAKE_BINARY_DIR}")
endif()

message(STATUS "SeaHorseServer configuration complete. Version ${PROJECT_VERSION}")
