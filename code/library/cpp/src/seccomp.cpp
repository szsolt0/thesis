#include <mylib/seccomp.h>
#include <mylib/detail/common_syscall.h>

#include <linux/audit.h>
#include <linux/bpf_common.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/mman.h>

#include <cstddef>
#include <cstdint>
#include <cstring>

#include <span>
#include <array>
#include <string_view>
#include <limits>
#include <expected>

#if !defined __x86_64__
#error "this is for x86_64 only"
#endif

#pragma push_macro("TRY_EXPECTED")
#include <mylib/detail/expected_macro.h>

namespace mylib {


// every bpf program begins with this
#define PREAMBLE() \
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


// === syscall categories ===

struct SyscallCategory
{
	std::string_view name;
	std::span<const long> nrs;
	std::span<const std::string_view> inherit = {};
};

static constexpr auto cat_sandbox = std::to_array<long>({
	SYS_landlock_create_ruleset,
	SYS_landlock_add_rule,
	SYS_landlock_restrict_self,
	SYS_seccomp,
});

static constexpr auto cat_basic = std::to_array<long>({
    SYS_arch_prctl,
    SYS_brk,
    SYS_clock_getres,
    SYS_clock_gettime,
    SYS_clock_nanosleep,
    SYS_execve,
    SYS_exit,
    SYS_exit_group,
    SYS_futex,
    SYS_futex_waitv,
    SYS_get_robust_list,
    SYS_get_thread_area,
    SYS_getegid,
    SYS_geteuid,
    SYS_getgid,
    SYS_getgroups,
    SYS_getpgid,
    SYS_getpgrp,
    SYS_getpid,
    SYS_getppid,
    SYS_getrandom,
    SYS_getresgid,
    SYS_getresuid,
    SYS_getrlimit,
    SYS_getsid,
    SYS_gettid,
    SYS_gettimeofday,
    SYS_getuid,
    SYS_lsm_get_self_attr,
    SYS_lsm_list_modules,
    SYS_membarrier,
    SYS_mmap,
    SYS_mprotect,
    SYS_mseal,
    SYS_munmap,
    SYS_nanosleep,
    SYS_pause,
    SYS_prlimit64,
    SYS_restart_syscall,
    SYS_rseq,
    SYS_rt_sigreturn,
    SYS_sched_getaffinity,
    SYS_sched_yield,
    SYS_set_robust_list,
    SYS_set_thread_area,
    SYS_set_tid_address,
    SYS_time,
    SYS_uretprobe,
});

static constexpr auto cat_basic_inherit = std::to_array<std::string_view>({
	"sandbox",
});

static constexpr auto cat_network_io = std::to_array<long>({
    SYS_accept,
    SYS_accept4,
    SYS_bind,
    SYS_connect,
    SYS_getpeername,
    SYS_getsockname,
    SYS_getsockopt,
    SYS_listen,
    SYS_recvfrom,
    SYS_recvmmsg,
    SYS_recvmsg,
    SYS_sendmmsg,
    SYS_sendmsg,
    SYS_sendto,
    SYS_setsockopt,
    SYS_shutdown,
    SYS_socket,
    SYS_socketpair,
});

static constexpr auto cat_file_system = std::to_array<long>({
    SYS_access,
    SYS_chdir,
    SYS_chmod,
    SYS_close,
    SYS_creat,
    SYS_faccessat,
    SYS_faccessat2,
    SYS_fallocate,
    SYS_fchdir,
    SYS_fchmod,
    SYS_fchmodat,
    SYS_fchmodat2,
    SYS_fcntl,
    SYS_fgetxattr,
    SYS_flistxattr,
    SYS_fremovexattr,
    SYS_fsetxattr,
    SYS_fstat,
    SYS_fstatfs,
    SYS_ftruncate,
    SYS_futimesat,
    SYS_getcwd,
    SYS_getdents,
    SYS_getdents64,
    SYS_getxattr,
    SYS_getxattrat,
    SYS_inotify_add_watch,
    SYS_inotify_init,
    SYS_inotify_init1,
    SYS_inotify_rm_watch,
    SYS_lgetxattr,
    SYS_link,
    SYS_linkat,
    SYS_listmount,
    SYS_listxattr,
    SYS_listxattrat,
    SYS_llistxattr,
    SYS_lremovexattr,
    SYS_lsetxattr,
    SYS_lstat,
    SYS_mkdir,
    SYS_mkdirat,
    SYS_mknod,
    SYS_mknodat,
    SYS_newfstatat,
    SYS_open,
    SYS_open_tree,
    SYS_openat,
    SYS_openat2,
    SYS_readlink,
    SYS_readlinkat,
    SYS_removexattr,
    SYS_removexattrat,
    SYS_rename,
    SYS_renameat,
    SYS_renameat2,
    SYS_rmdir,
    SYS_setxattr,
    SYS_setxattrat,
    SYS_stat,
    SYS_statfs,
    SYS_statmount,
    SYS_statx,
    SYS_symlink,
    SYS_symlinkat,
    SYS_truncate,
    SYS_unlink,
    SYS_unlinkat,
    SYS_utime,
    SYS_utimensat,
    SYS_utimes,
});

static constexpr auto cat_io = std::to_array<long>({
    SYS_close,
    SYS_close_range,
    SYS_dup,
    SYS_dup2,
    SYS_dup3,
    SYS_lseek,
    SYS_pread64,
    SYS_preadv,
    SYS_preadv2,
    SYS_pwrite64,
    SYS_pwritev,
    SYS_pwritev2,
    SYS_read,
    SYS_readv,
    SYS_write,
    SYS_writev,
});

static constexpr auto cat_list = std::to_array<SyscallCategory>({
	{"sandbox", cat_sandbox},
	{"basic", cat_basic, cat_basic_inherit},
	{"network_io", cat_network_io},
	{"file_system", cat_file_system},
	{"io", cat_io},
});


// === builder ===

std::expected<void, int> SeccompBuilder::append(std::span<sock_filter> filters)
{
	m_filter.append_range(filters);
	return {};
}

std::expected<void, int> SeccompBuilder::allow_syscall(long nr)
{
	std::array<sock_filter, 2> filters = {{ALLOW_SYSCALL(nr)}};
	return append(filters);
}

std::expected<void, int> SeccompBuilder::allow_syscall_range(long min, long max)
{
	std::array<sock_filter, 3> filters = {{ALLOW_SYSCALL_RANGE(min, max)}};
	return append(filters);
}

std::expected<void, int> SeccompBuilder::add_preamble()
{
	std::array<sock_filter, 4> filters = {{PREAMBLE()}};
	return append(filters);
}

std::expected<void, int> SeccompBuilder::allow(std::string_view what) noexcept
{
	if (finished) [[unlikely]] {
		return std::unexpected {EALREADY};
	}

	for (auto const& cat : cat_list) {
		if (cat.name == what) {
			m_syscalls.insert_range(cat.nrs);

			for (auto const& inherit : cat.inherit) {
				allow(inherit);
			}

			return {};
		}
	}

	return std::unexpected {ENOENT};
}

void SeccompBuilder::generate_filter_from_syscalls()
{
    if (m_syscalls.empty()) {
        return;
    }

    auto it = m_syscalls.begin();

    long range_start = *it;
    long previous = *it;
    ++it;

    auto flush_range = [&] {
        if (range_start == previous) {
            allow_syscall(range_start);
        } else {
            allow_syscall_range(range_start, previous);
        }
    };

    for (; it != m_syscalls.end(); ++it) {
        long current = *it;

        if (current == previous + 1) {
            previous = current;
            continue;
        }

        flush_range();

        range_start = current;
        previous = current;
    }

    flush_range();
}

std::expected<SeccompRuleView, int>
SeccompBuilder::build_static(bool const kill_entire_process) noexcept
{
    if (!finished) {
        generate_filter_from_syscalls();

        if (kill_entire_process) {
            m_filter.push_back(END_KILL_PROCESS());
        } else {
            m_filter.push_back(END_KILL_THREAD());
        }

        finished = true;
        m_filter.shrink_to_fit();

        if (m_filter.size() > std::numeric_limits<unsigned short>::max()) {
            return std::unexpected {E2BIG};
        }
    }

    auto const len_in_bytes = m_filter.size() * sizeof(m_filter[0]);

    auto const mem_ptr = static_cast<sock_filter*>(
        detail::sys_mmap(
            nullptr,
            len_in_bytes,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0
        )
    );

    auto const mem_ptr_as_num = std::bit_cast<std::intptr_t>(mem_ptr);

    if (is_between(mem_ptr_as_num, -4095, -1)) [[unlikely]] {
        return std::unexpected {-static_cast<int>(mem_ptr_as_num)};
    }

    std::memcpy(mem_ptr, m_filter.data(), len_in_bytes);

    auto const mprotect_ret =
        detail::sys_mprotect(mem_ptr, len_in_bytes, PROT_READ);

    if (mprotect_ret < 0) [[unlikely]] {
        return std::unexpected {-static_cast<int>(mprotect_ret)};
    }

    const sock_fprog prog = {
        .len = static_cast<unsigned short>(m_filter.size()),
        .filter = mem_ptr,
    };

    return SeccompRuleView {prog};
}

std::expected<SeccompRule, int> SeccompBuilder::build(bool const kill_entire_process) noexcept
{
	auto view = TRY_EXPECTED(build_static(kill_entire_process));
	return {SeccompRule {view}};
}

std::expected<SeccompBuilder, int> SeccompBuilder::init() noexcept
{
	SeccompBuilder builder {};

	TRY_EXPECTED(builder.add_preamble());
	TRY_EXPECTED(builder.allow("basic"));

	return builder;
}

std::expected<SeccompBuilder, int> SeccompBuilder::init_no_defaults() noexcept
{
	SeccompBuilder builder {};

	TRY_EXPECTED(builder.add_preamble());
	// no default rules
	//TRY_EXPECTED(builder.allow("basic"));

	return builder;
}


} // namespace mylib

#pragma pop_macro("TRY_EXPECTED")
