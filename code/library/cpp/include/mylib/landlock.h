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
	Write   = LANDLOCK_ACCESS_FS_WRITE_FILE
	        | LANDLOCK_ACCESS_FS_TRUNCATE
	        | LANDLOCK_ACCESS_FS_MAKE_BLOCK
			| LANDLOCK_ACCESS_FS_MAKE_CHAR
			| LANDLOCK_ACCESS_FS_MAKE_DIR
			| LANDLOCK_ACCESS_FS_MAKE_FIFO
			| LANDLOCK_ACCESS_FS_MAKE_REG
			| LANDLOCK_ACCESS_FS_MAKE_SOCK
			| LANDLOCK_ACCESS_FS_MAKE_SYM,
	Read    = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR,
	Execute = LANDLOCK_ACCESS_FS_EXECUTE,

	ReadWrite    = Read | Write,
	ReadExecute  = Read | Execute,
	WriteExecute = Write | Execute,

	All = Read | Write | Execute,
};

namespace detail {
extern const std::span<const std::pair<char const*, LandlockAccess>> landlock_default_paths;

static constexpr __u64 file_only_access =
    LANDLOCK_ACCESS_FS_EXECUTE |
    LANDLOCK_ACCESS_FS_WRITE_FILE |
    LANDLOCK_ACCESS_FS_READ_FILE |
    LANDLOCK_ACCESS_FS_TRUNCATE;

static constexpr __u64 dir_allowed_access =
    LANDLOCK_ACCESS_FS_EXECUTE |
    LANDLOCK_ACCESS_FS_WRITE_FILE |
    LANDLOCK_ACCESS_FS_READ_FILE |
    LANDLOCK_ACCESS_FS_READ_DIR |
    LANDLOCK_ACCESS_FS_MAKE_CHAR |
    LANDLOCK_ACCESS_FS_MAKE_DIR |
    LANDLOCK_ACCESS_FS_MAKE_REG |
    LANDLOCK_ACCESS_FS_MAKE_SOCK |
    LANDLOCK_ACCESS_FS_MAKE_FIFO |
    LANDLOCK_ACCESS_FS_MAKE_BLOCK |
    LANDLOCK_ACCESS_FS_MAKE_SYM |
    LANDLOCK_ACCESS_FS_TRUNCATE;

} // namespace detail

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
			TRY_EXPECTED(add_rule(fd, access));
		}

		return {};
	}

	public:

	[[nodiscard]] static std::expected<LandlockRuleSet, int> init() noexcept
	{
		struct landlock_ruleset_attr ruleset_attr {};
		ruleset_attr.handled_access_fs = static_cast<__u64>(LandlockAccess::All);

		const int ruleset_fd = detail::landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);

		if (ruleset_fd < 0) {
			return std::unexpected {-ruleset_fd};
		}

		LandlockRuleSet self {ruleset_fd};
		TRY_EXPECTED(self.add_defaults());
		return self;
	}

	[[nodiscard]] std::expected<void, int>
	add_rule(int fd, LandlockAccess access) noexcept
	{
		struct stat st {};

		if (fstat(fd, &st) < 0) {
			return std::unexpected {errno};
		}

		__u64 allowed = static_cast<__u64>(access);

		if (S_ISDIR(st.st_mode)) {
			allowed &= detail::dir_allowed_access;
		} else {
			allowed &= detail::file_only_access;
		}

		if (allowed == 0) {
			return std::unexpected {ENOMSG};
		}

		landlock_path_beneath_attr attr {};
		attr.allowed_access = allowed;
		attr.parent_fd = fd;

		const int ret = detail::landlock_add_rule(
			m_ruleset_fd,
			LANDLOCK_RULE_PATH_BENEATH,
			&attr,
			0
		);

		if (ret < 0) {
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
