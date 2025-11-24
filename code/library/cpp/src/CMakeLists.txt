add_library(mylib
    landlock.cpp
	seccomp.cpp
)

target_include_directories(mylib PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)
