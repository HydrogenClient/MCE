cmake_minimum_required(VERSION 3.16)
project(Tiny_Plus_Plus LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Organize sub-projects
add_subdirectory(mce)
add_subdirectory(tpp)
