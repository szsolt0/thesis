#include <mylib/seccomp.h>

#include <linux/audit.h>
#include <linux/bpf_common.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#include <stddef.h>

#include <span>
#include <string_view>

#if !defined __x86_64__
#error "this is for x86_64 only"
#endif

namespace mylib {


// every bpf program begins with this
#define PREAMPLE() \
	/* only x86_64 */ \
	BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, arch)), \
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, AUDIT_ARCH_X86_64, 1, 0), \
	BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL_PROCESS), \
	/* k = syscall number */ \
	BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, nr))


// allow syscalls in the [min, max] range
#define ALLOW_SYSCALL_RANGE(min, max) \
	BPF_JUMP(BPF_JMP + BPF_JGE + BPF_K, min, 0, 2), \
	BPF_JUMP(BPF_JMP + BPF_JGT + BPF_K, max, 1, 0), \
	BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW)

// allow only a single sysall
#define ALLOW_SYSCALL(nr) \
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, nr, 0, 1), \
	BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW)

// put at end of rules to kill process
#define END_KILL_PROCESS() BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL_PROCESS)

// put at end of rules to kill thread
#define END_KILL_THREAD() BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL_THREAD)

// better strict mode filter
static constexpr sock_filter better_strict_filter[] = {
	PREAMPLE(),
	// syscall order available here: https://filippo.io/linux-syscall-table/

	// read/write
	ALLOW_SYSCALL_RANGE(0, 1),

	// stat and close
	ALLOW_SYSCALL_RANGE(3, 6),

	// rt_sigreturn
	ALLOW_SYSCALL(15),

	// pread, pwrite, readv, writev
	ALLOW_SYSCALL_RANGE(17, 20),

	// sendfile
	ALLOW_SYSCALL(40),

	// close_range, but only if 3rd arg is 0
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_close_range, 0, 3),
	BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, args[2])),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0, 0, 1),
	BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
	BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, nr)),

	// exit
	ALLOW_SYSCALL(60),

	// exit_group
	ALLOW_SYSCALL(231),

	// strict seccomp always kills the entire process
	END_KILL_PROCESS(),
};

// better strict mode program
static constexpr sock_fprog better_strict_prog = {
	.len = std::size(better_strict_filter),
	.filter = const_cast<sock_filter*>(better_strict_filter),
};

std::expected<void, int> seccomp_better_strict() noexcept
{
	int const ret = detail::sys_seccomp(SECCOMP_SET_MODE_FILTER, 0, const_cast<sock_fprog*>(&better_strict_prog));

	if (ret != 0) {
		return std::unexpected {-ret};
	}

	return {};
}


// filter for I/O syscalls
static constexpr sock_filter io_filter[] = {
	BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, nr)),

	ALLOW_SYSCALL_RANGE(0, 0),
};

// TODO: maybe create a template helper for this?
static constexpr sock_fprog io_prog = {
	.len = std::size(io_filter),
	.filter = const_cast<sock_filter*>(io_filter),
};

// filter for sandbox related calls
static constexpr sock_filter sandbox_filter[] = {
	PREAMPLE(),

	// landlock
	ALLOW_SYSCALL_RANGE(444, 446),

	// seccomp
	ALLOW_SYSCALL(SYS_seccomp),
};

static constexpr sock_fprog sandbox_prog = {
	.len = std::size(sandbox_filter),
	.filter = const_cast<sock_filter*>(sandbox_filter),
};

#define ENTRY(name, prog) std::pair<std::string_view, sock_fprog> {name, prog}

constexpr std::pair<std::string_view, sock_fprog> filter_categories_arr[] = {
	ENTRY("io", io_prog),
	ENTRY("sandbox", sandbox_prog),
};

} // namespace mylib
