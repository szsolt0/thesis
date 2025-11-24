#pragma once
#include <mylib/detail/common_syscall.h>

#include <expected>

namespace mylib {

static inline __attribute__((always_inline))
std::expected<void, int> set_no_new_privs() noexcept
{
	auto const err = detail::sys_prctl_set_no_new_privs();

	if (err != 0) [[unlikely]] {
		return std::unexpected {-err};
	}

	return {};
}

} // namespace mylib
