// util.h
// Usefull stuff that don't have a better place to be
// Author: Zsolt Sebe

#pragma once
#include <mylib/detail/common_syscall.h>

#include <expected>
#include <string_view>
#include <utility>

#include <sys/uio.h>

namespace mylib::detail {

class OwnedFd
{
	int inner;

	public:

	__attribute__((always_inline))
	OwnedFd(int const fd) noexcept : inner{fd} {}

	OwnedFd(OwnedFd const&) = delete;
	OwnedFd& operator=(OwnedFd const&) = delete;

	__attribute__((always_inline))
	void destroy() noexcept
	{
		if (inner >= 0) {
			sys_close(inner);
		}
	}

	__attribute__((always_inline))
	operator int() const noexcept
	{
		return inner;
	}

	__attribute__((always_inline))
	OwnedFd(OwnedFd&& other) noexcept : inner(other.inner)
	{
		other.inner = -1;
	}

	__attribute__((always_inline))
	OwnedFd& operator=(OwnedFd&& other) noexcept
	{
		if (this == &other) {
			return *this;
		}

		destroy();
		inner = other.inner;
		other.inner = -1;

		return *this;
	}

	__attribute__((always_inline))
	int disown() noexcept
	{
		int const x = inner;
		inner = -1;
		return x;
	}

	__attribute__((always_inline))
	~OwnedFd() noexcept
	{
		destroy();
	}


	__attribute__((always_inline))
	static std::expected<int, int> openat(int dirfd, char const* const path, int const flags, mode_t mode) noexcept
	{
		int const fd = sys_openat(dirfd, path, flags, mode);

		if (fd < 0) {
			return std::unexpected {-fd};
		}

		return {fd};
	}

	__attribute__((always_inline))
	static std::expected<int, int> openat_restart(int dirfd, char const* const path, int const flags, mode_t mode) noexcept
	{
		int const fd = sys_openat_restart(dirfd, path, flags, mode);

		if (fd < 0) {
			return std::unexpected {-fd};
		}

		return {fd};
	}
};

static inline __attribute__((always_inline))
iovec make_iovec(char const* const base, std::size_t const len) noexcept
{
	struct iovec iov {};
	iov.iov_base = const_cast<char*>(base);
	iov.iov_len = len;
	return iov;
}

static inline __attribute__((always_inline))
iovec make_iovec(std::string_view const str) noexcept
{
	return make_iovec(str.begin(), str.size());
}

} // namespace mylib::detail

/// Returns true if x is in range [a, b]
template <typename T, typename A, typename B>
static inline __attribute__((always_inline))
bool is_between(T const& x, A const& a, B const& b) noexcept
{
	return a <= x && x <= b;
}
