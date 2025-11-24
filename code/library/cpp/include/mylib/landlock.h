// landlock.h
// The Landlock class
// Author: Zsolt Sebe

#pragma once
#include <mylib/detail/landlock_syscall.h>
#include <mylib/detail/common_syscall.h>
#include <mylib/detail/util.h>

#include <expected>
#include <span>

#include <sys/prctl.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <stddef.h>
#include <iostream>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/syscall.h>

#pragma push_macro("TRY_EXPECTED")
#include <mylib/detail/expected_macro.h>

namespace mylib
{

enum class LandlockAccess: __u64
{
	None = LANDLOCK_ACCESS_FS_EXECUTE,

	Write   = LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_TRUNCATE,
	Read    = LANDLOCK_ACCESS_FS_READ_FILE,
	Execute = LANDLOCK_ACCESS_FS_EXECUTE,

	ReadWrite    = Read | Write,
	ReadExecute  = Read | Execute,
	WriteExecute = Write | Execute,

	All = Read | Write | Execute,
};

namespace detail {
	extern const std::span<const std::pair<char const*, LandlockAccess>> landlock_default_paths;
}

class LandlockRuleSet
{
	detail::OwnedFd m_ruleset_fd;

	__attribute__((always_inline))
	LandlockRuleSet(int ruleset_fd) noexcept : m_ruleset_fd{ruleset_fd}
	{}

	__attribute__((always_inline))
	std::expected<void, int> add_defaults() noexcept
	{
		for (auto const& [path, access] : detail::landlock_default_paths) {
			auto const fd = TRY_EXPECTED(detail::OwnedFd::openat(AT_FDCWD, path, O_PATH|O_CLOEXEC, 0));
			return add_rule(fd, access);
		}
	}

	public:

	[[nodiscard]] static std::expected<LandlockRuleSet, int> init() noexcept
	{
		struct landlock_ruleset_attr ruleset_attr {};
		ruleset_attr.handled_access_fs = 0
			| LANDLOCK_ACCESS_FS_EXECUTE
			| LANDLOCK_ACCESS_FS_WRITE_FILE
			| LANDLOCK_ACCESS_FS_READ_FILE
			| LANDLOCK_ACCESS_FS_TRUNCATE
		;

		const int ruleset_fd = detail::landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);

		if (ruleset_fd < 0) {
			return std::unexpected {-ruleset_fd};
		}

		return LandlockRuleSet {ruleset_fd};
	}

	[[nodiscard]] std::expected<void, int> add_rule(int fd, LandlockAccess access) noexcept
	{
		landlock_path_beneath_attr attr {};
		attr.allowed_access = static_cast<__u64>(access);
		attr.parent_fd = fd;
		const int ret = detail::landlock_add_rule(m_ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &attr, 0);

		if (ret != 0) {
			return std::unexpected {-ret};
		}

		return {};
	}

	[[nodiscard]] std::expected<void, int> add_rule(char const* const path, LandlockAccess access) noexcept
	{
		auto const fd = TRY_EXPECTED(detail::OwnedFd::openat(AT_FDCWD, path, O_PATH|O_CLOEXEC, 0));
		return add_rule(fd, access);
	}

	[[nodiscard]] std::expected<void, int> apply() noexcept
	{
		int const ret = detail::landlock_restrict_self(m_ruleset_fd, 0);

		if (ret != 0) {
			return std::unexpected {-ret};
		}

		return {};
	}
};

} // namespace mylib

#pragma pop_macro("TRY_EXPECTED")
