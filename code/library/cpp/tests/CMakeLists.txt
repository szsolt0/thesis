include(FetchContent)

FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/heads/main.zip
)

FetchContent_MakeAvailable(googletest)

add_executable(unit_tests
    test_mylib.cpp
    test_seccomp.cpp
    test_landlock.cpp
)

target_link_libraries(unit_tests
    PRIVATE
        GTest::gtest_main
        mylib
)

include(GoogleTest)

gtest_discover_tests(unit_tests)
