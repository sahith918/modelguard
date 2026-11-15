cmake_minimum_required(VERSION 3.20)
project(modelguard VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
  add_compile_options(/W4 /utf-8)
else()
  add_compile_options(-Wall -Wextra)
endif()

find_package(nlohmann_json CONFIG REQUIRED)
find_package(spdlog CONFIG REQUIRED)
find_package(CLI11 CONFIG REQUIRED)
find_package(GTest CONFIG REQUIRED)
find_package(unofficial-sodium CONFIG REQUIRED)

# Core library: shared types used by every module
add_library(mg_core src/core/report.cpp)
target_include_directories(mg_core PUBLIC include)
target_link_libraries(mg_core PUBLIC nlohmann_json::nlohmann_json)

# Integrity module: signing and tamper detection
add_library(mg_integrity src/integrity/signer.cpp)
target_link_libraries(mg_integrity PUBLIC mg_core unofficial-sodium::sodium)
if(TARGET unofficial-sodium::sodium_config_public)
  target_link_libraries(mg_integrity PUBLIC unofficial-sodium::sodium_config_public)
endif()

# Poison module: .npy loader + spectral-signature detector
add_library(mg_poison src/poison/npy_loader.cpp src/poison/spectral.cpp)
target_link_libraries(mg_poison PUBLIC mg_core)

# Monitor module: query-log analysis for extraction attempts
add_library(mg_monitor src/monitor/monitor.cpp)
target_link_libraries(mg_monitor PUBLIC mg_core)

# Command line tool
add_executable(modelguard cli/main.cpp)
target_link_libraries(modelguard PRIVATE mg_core mg_integrity mg_poison mg_monitor
                      spdlog::spdlog CLI11::CLI11)

# Tests
enable_testing()
add_executable(mg_tests
  tests/test_report.cpp
  tests/test_integrity.cpp
  tests/test_poison.cpp
  tests/test_monitor.cpp)
target_link_libraries(mg_tests PRIVATE mg_core mg_integrity mg_poison mg_monitor
                      GTest::gtest GTest::gtest_main)
add_test(NAME mg_tests COMMAND mg_tests)
