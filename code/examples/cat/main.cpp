#include <mylib/seccomp.h>
#include <mylib/landlock.h>
#include <mylib/no_new_privs.h>

#include <string_view>
#include <iostream>
#include <fstream>

#include <cerrno>
#include <cstring>

[[noreturn]] void die(int why) noexcept
{
	std::cerr << "error: " << std::strerror(why) << '\n';
	std::exit(1);
}

template <class T>
T unwrap_or_die(std::expected<T, int>&& result)
{
    if (!result) {
        die(result.error());
    }

    return std::move(result).value();
}

inline void unwrap_or_die(std::expected<void, int>&& result)
{
    if (!result) {
        die(result.error());
    }
}

int main(int argc, char* argv[])
{
	unwrap_or_die(mylib::set_no_new_privs());

	auto seccomp = unwrap_or_die(mylib::SeccompBuilder::init());

	unwrap_or_die(seccomp.allow("io"));
	unwrap_or_die(seccomp.allow("file_system"));
	unwrap_or_die(unwrap_or_die(seccomp.build()).view().apply());

	auto landlock = unwrap_or_die(mylib::LandlockRuleSet::init());

	for (int i = 1; i < argc; ++i) {
		unwrap_or_die(landlock.add_rule(argv[i], mylib::LandlockAccess::Read));
	}

	unwrap_or_die(landlock.apply());

    for (int i = 1; i < argc; ++i) {
        std::ifstream file(argv[i], std::ios::binary);

        if (!file) {
            std::cerr << "cat: cannot open " << argv[i] << '\n';
            return 1;
        }

        std::cout << file.rdbuf();
    }

    return 0;
}
