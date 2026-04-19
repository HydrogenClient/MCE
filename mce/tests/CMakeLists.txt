cmake_minimum_required(VERSION 3.16)

add_executable(test_emitter test_emitter.cpp)
target_link_libraries(test_emitter PRIVATE MCE)

if(MSVC)
    target_compile_options(test_emitter PRIVATE /W4)
else()
    target_compile_options(test_emitter PRIVATE -Wall -Wextra -Wno-unused-function)
endif()

# Register with CTest
enable_testing()
add_test(NAME EncoderTests COMMAND test_emitter)
