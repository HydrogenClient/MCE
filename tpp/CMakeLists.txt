cmake_minimum_required(VERSION 3.16)
project(tpp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# T++ Compiler (Tiny++)

add_executable(tpp 
    main.cpp
    lexer.cpp
    parser.cpp
    codegen.cpp
)

target_link_libraries(tpp PRIVATE MCE)
