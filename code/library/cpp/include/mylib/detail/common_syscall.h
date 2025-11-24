// common_syscall.h
// Some common syscalls and their "restart" variants
// Author: Zsolt Sebe
//
// Syscalls here begin with `sys_` to avoid colliding with the C library wrappers.
// As raw syscalls, they return negative error codes instead of setting `errno`,
// which is arguably a cleaner API.
//
// Syscalls ending with `_restart` will silently retry if interrupted by EINTR,
// but otherwise behave the same as the normal versions. This is because EINTR
// is not the fault of the syscall.
//
// Syscalls ending in `_restartblock` handle EINTR fully transparently, but
// require more complex logic than a simple restart.


#pragma once
#include <mylib/detail/raw_syscall.h>

#include <utility>

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/uio.h>
#include <sys/prctl.h>

namespace mylib::detail {

/// silently restart syscall on EINTR (interruption by signal).
/// easyer than writong this loop manually all the time
template <typename F, typename... Args>
static inline __attribute__((always_inline))
auto restart_syscall(F f, Args const... args) noexcept -> decltype(f(args...))
{
	decltype(f(args...)) ret;

	// EINTR is rare and not a real error, just a signal interrupt.
	// Retry to make the call behave as if uninterrupted.
	do {
		ret = f(args...);
	} while (ret == -EINTR);

	return ret;
}



static inline __attribute__((always_inline))
int sys_open(char const* const path, int const flags, mode_t const mode) noexcept
{
	return raw_syscall3<int>(__NR_open, path, flags, mode);
}

static inline __attribute__((always_inline))
int sys_open_restart(char const* const path, int const flags, mode_t const mode) noexcept
{
	return restart_syscall(sys_open, path, flags, mode);
}



static inline __attribute__((always_inline))
int sys_openat(int const dirfd, char const* const path, int const flags, mode_t const mode) noexcept
{
	return raw_syscall4<int>(__NR_openat, dirfd, path, flags, mode);
}

static inline __attribute__((always_inline))
int sys_openat_restart(int const dirfd, char const* const path, int const flags, mode_t const mode) noexcept
{
	return restart_syscall(sys_openat, dirfd, path, flags, mode);
}



static inline __attribute__((always_inline))
ssize_t sys_write(int const fd, void const* const buf, std::size_t const len) noexcept
{
	return raw_syscall3<ssize_t>(__NR_write, fd, buf, len);
}

static inline __attribute__((always_inline))
ssize_t sys_write_restart(int const fd, void const* const buf, std::size_t const len) noexcept
{
	return restart_syscall(sys_write, fd, buf, len);
}



static inline __attribute__((always_inline))
ssize_t sys_writev(int const fd, struct iovec const* const iov, int const iovcnt) noexcept
{
	return raw_syscall3<ssize_t>(__NR_writev, fd, iov, iovcnt);
}

static inline __attribute__((always_inline))
ssize_t sys_writev_restart(int const fd, struct iovec const* const iov, int const iovcnt) noexcept
{
	return restart_syscall(sys_writev, fd, iov, iovcnt);
}

static inline __attribute__((always_inline))
int sys_close(int const fd) noexcept
{
	return raw_syscall1<int>(__NR_close, fd);
}




static inline __attribute__((always_inline))
int sys_prctl_set_no_new_privs() noexcept
{
	return raw_syscall5<int>(__NR_prctl, PR_SET_NO_NEW_PRIVS, 1L, 0L, 0L, 0L);
}



static inline __attribute__((always_inline))
void* sys_mmap(
	void* const addr,
	size_t const length,
	int const prot,
	int const flags,
	int const fd,
	off_t const offset
) noexcept
{
	return raw_syscall6<void*>(__NR_mmap, addr, length, prot, flags, fd, offset);
}




static inline __attribute__((always_inline))
int sys_munmap(void* const addr, std::size_t const len) noexcept
{
	return raw_syscall2<int>(__NR_munmap, addr, len);
}



static inline __attribute__((always_inline))
int sys_seccomp(unsigned int const operation, unsigned int const flags, void *const args) noexcept
{
	return raw_syscall3<int>(SYS_seccomp, operation, flags, args);
}


} // namespace mylib::detail
