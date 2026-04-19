cmake_minimum_required(VERSION 3.16)
project(MCE_Core LANGUAGES CXX)

# MCE is header-only
add_library(MCE INTERFACE)
target_include_directories(MCE INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

option(MCE_BUILD_EXAMPLES "Build MCE example programs" ON)
option(MCE_BUILD_TESTS    "Build MCE test programs"    ON)

if(MCE_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

if(MCE_BUILD_TESTS)
    add_subdirectory(tests)
endif()
