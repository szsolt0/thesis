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
#include <string_view>
#include <limits>

#if !defined __x86_64__
#error "this is for x86_64 only"
#endif

#pragma push_macro("TRY_EXPECTED")
#include <mylib/detail/expected_macro.h>

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
	// read/write
	ALLOW_SYSCALL_RANGE(0, 1),

	// pread, pwrite, readv, writev
	ALLOW_SYSCALL_RANGE(17, 20),

	// sendfile
	ALLOW_SYSCALL(40),
};

// TODO: maybe create a template helper for this?
static constexpr sock_fprog io_prog = {
	.len = std::size(io_filter),
	.filter = const_cast<sock_filter*>(io_filter),
};

// filter for sandbox related calls
static constexpr sock_filter sandbox_filter[] = {
	// landlock
	ALLOW_SYSCALL_RANGE(444, 446),

	// seccomp
	ALLOW_SYSCALL(SYS_seccomp),
};

static constexpr sock_fprog sandbox_prog = {
	.len = std::size(sandbox_filter),
	.filter = const_cast<sock_filter*>(sandbox_filter),
};

// filter for basic calls, these are enabled by default
static constexpr sock_filter basic_filter[] = {
	// memory
	ALLOW_SYSCALL_RANGE(9, 11),

	ALLOW_SYSCALL(__NR_rt_sigreturn),

	// sched_yield, memory related
	ALLOW_SYSCALL_RANGE(24, 28),

	// pause, nanosleep
	ALLOW_SYSCALL_RANGE(34, 35),

	ALLOW_SYSCALL(__NR_getpgid),
	ALLOW_SYSCALL(__NR_exit),
	ALLOW_SYSCALL(__NR_exit_group),

	// get*
	ALLOW_SYSCALL_RANGE(96, 100),
};

static constexpr sock_fprog basic_prog = {
	.len = std::size(basic_filter),
	.filter = const_cast<sock_filter*>(basic_filter),
};

#define ENTRY(name, prog) std::pair<std::string_view, sock_fprog> {name, prog}

constexpr std::pair<std::string_view, sock_fprog> filter_categories_arr[] = {
	ENTRY("basic", basic_prog),
	ENTRY("io", io_prog),
	ENTRY("sandbox", sandbox_prog),
};


// === builder ===

std::expected<void, int> SeccompBuilder::append(sock_fprog const* const prog)
{
	//auto const full_size = sizeof(prog->filter) * prog->len;
	this->m_filter.insert(this->m_filter.end(), prog->filter, prog->filter + prog->len);
	return {};
}

std::expected<void, int> SeccompBuilder::add_preample()
{
	constexpr sock_filter preample[] = {PREAMPLE()};
	const sock_fprog premple_prog = {
		.len = std::size(preample),
		.filter = const_cast<sock_filter*>(preample),
	};

	return append(&premple_prog);
}

std::expected<void, int> SeccompBuilder::allow(std::string_view what) noexcept
{
	if (finished) [[unlikely]] {
		return std::unexpected {EALREADY};
	}

	for (auto const& [name, prog] : filter_categories_arr) {
		if (name == what) {
			return append(&prog);
		}
	}

	return std::unexpected {ENOENT};
}

std::expected<SeccompRuleView, int> SeccompBuilder::build_static(bool const kill_entire_process) noexcept
{
	if (!finished) {
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
	auto const mem_ptr = static_cast<sock_filter*>(detail::sys_mmap(nullptr, len_in_bytes, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0));
	auto const mem_ptr_as_num = std::bit_cast<std::intptr_t>(mem_ptr);

	// raw mmap syscall signals error this way
	if (is_between(mem_ptr_as_num, -4095, -1)) [[unlikely]] {
		return std::unexpected {-static_cast<int>(mem_ptr_as_num)};
	}

	std::memcpy(mem_ptr, m_filter.data(), len_in_bytes);

	// prevent write access
	detail::sys_mprotect(mem_ptr, len_in_bytes, PROT_READ);

	const sock_fprog prog = {
		.len = m_filter.size(),
		.filter = mem_ptr,
	};

	return {SeccompRuleView {prog}};
}

std::expected<SeccompRule, int> SeccompBuilder::build(bool const kill_entire_process) noexcept
{
	auto view = TRY_EXPECTED(build_static(kill_entire_process));
	return {SeccompRule {view}};
}

std::expected<SeccompBuilder, int> SeccompBuilder::init() noexcept
{
	SeccompBuilder builder {};

	TRY_EXPECTED(builder.add_preample());
	TRY_EXPECTED(builder.allow("basic"));

	return builder;
}

std::expected<SeccompBuilder, int> SeccompBuilder::init_no_defaults() noexcept
{
	SeccompBuilder builder {};

	TRY_EXPECTED(builder.add_preample());
	// no default rules
	//TRY_EXPECTED(builder.allow("basic"));

	return builder;
}


} // namespace mylib

#pragma pop_macro("TRY_EXPECTED")
