// Example program demonstrating seccomp strict mode.
// Strict mode is very restricted and thus reraly usefull in practice.

#include <cstddef>

#include <unistd.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>

#include "raw_syscall.h"

static inline
int seccomp(unsigned int operation, unsigned int flags, void *args)
{
	return raw_syscall3<int>(SYS_seccomp, operation, flags, args);
}

template <std::size_t N>
static inline
iovec static_iov(const char (&str)[N]) noexcept
{
	iovec iov;
	iov.iov_base = const_cast<void*>(reinterpret_cast<const void*>(str));
	iov.iov_len = N - 1;
	return iov;
}

int main()
{
	prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	const int fd = open("a.txt", O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0666);

	// only read(), write(), and exit() (but not exit_group()) syscalls are allowed
	seccomp(SECCOMP_SET_MODE_STRICT, 0, nullptr);

	write(fd, "Hello, World!\n", 14);

	// NOTE: every bad syscall will kill the program, so comment out each line
	// to see what happens otherwise

	// attemting to open a different file will fail
	//open("b.txt", O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC);

	// deleting a file will fail
	//unlink("a.txt");

	// even just getting our own pid will fail
	//getpid();

	// even "alternative" versions of write() will fail
	const iovec hello[] = {
		static_iov("Hello,"),
		static_iov(" World!"),
	};
	writev(fd, hello, 2);

	// even exiting normally (via exit_group()) will fail...
}
