cmake_minimum_required(VERSION 3.14)
project(MyProject LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)

add_compile_options(-Wall -Wextra)

enable_testing()

add_subdirectory(src)
add_subdirectory(tests)
