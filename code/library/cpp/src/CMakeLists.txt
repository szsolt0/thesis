add_library(mylib
    landlock.cpp
    seccomp.cpp
)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

target_include_directories(mylib PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)
