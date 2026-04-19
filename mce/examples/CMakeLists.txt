cmake_minimum_required(VERSION 3.16)

foreach(ex
    hello_world
    fibonacci
    float_demo
    call_import
)
    add_executable(${ex} ${ex}.cpp)
    target_link_libraries(${ex} PRIVATE MCE)
    # On MSVC enable /W4; on GCC/Clang -Wall -Wextra
    if(MSVC)
        target_compile_options(${ex} PRIVATE /W4)
    else()
        target_compile_options(${ex} PRIVATE -Wall -Wextra)
    endif()
endforeach()
