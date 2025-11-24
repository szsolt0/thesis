# Download and configure GoogleTest (modern recommended way)
include(FetchContent)

FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/heads/main.zip
)

FetchContent_MakeAvailable(googletest)

enable_testing()

# Create the test executable
add_executable(unit_tests
    test_mylib.cpp
	test_seccomp.cpp
    test_landlock.cpp
)

# Link GoogleTest
target_link_libraries(unit_tests
    gtest_main
    mylib
)

include(GoogleTest)
gtest_discover_tests(unit_tests)
