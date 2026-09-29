cmake_minimum_required(VERSION 3.16)
project(NetScope VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(netscope_core src/parser.cpp)
target_include_directories(netscope_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_options(netscope_core PRIVATE $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall;-Wextra;-Wpedantic>)

include(CTest)
if(BUILD_TESTING)
  add_executable(netscope_tests tests/parser_tests.cpp)
  target_link_libraries(netscope_tests PRIVATE netscope_core)
  add_test(NAME parser_tests COMMAND netscope_tests)
endif()
