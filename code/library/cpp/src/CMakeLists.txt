add_library(mylib
    landlock.cpp
    seccomp.cpp
)

target_compile_features(mylib PUBLIC cxx_std_23)

target_include_directories(mylib
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>
        $<INSTALL_INTERFACE:include>
)
