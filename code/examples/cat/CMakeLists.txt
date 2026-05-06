cmake_minimum_required(VERSION 3.14)

project(cat_example LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory(
    ../../library/cpp
    ${CMAKE_BINARY_DIR}/mylib-build
)

add_executable(cat main.cpp)

target_link_libraries(cat PRIVATE mylib)
