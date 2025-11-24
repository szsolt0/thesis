// landlock_syscall.h
// Wrapper for Landlock syscalls
// Author: Zsolt Sebe

#pragma once

#pragma once
#include <mylib/detail/raw_syscall.h>

#include <linux/landlock.h>

#include <cstddef>

namespace mylib::detail {

static inline __attribute__((always_inline))
int landlock_create_ruleset(const struct landlock_ruleset_attr *attr, const size_t size, const __u32 flags) noexcept
{
	return mylib::detail::raw_syscall3<int>(__NR_landlock_create_ruleset, attr, size, flags);
}

static inline __attribute__((always_inline))
int landlock_add_rule(const int ruleset_fd, const enum landlock_rule_type rule_type, const void *rule_attr, const __u32 flags) noexcept
{
	return mylib::detail::raw_syscall4<int>(__NR_landlock_add_rule, ruleset_fd, rule_type, rule_attr, flags);
}

static inline __attribute__((always_inline))
int landlock_restrict_self(const int ruleset_fd, const __u32 flags) noexcept
{
	return mylib::detail::raw_syscall2<int>(__NR_landlock_restrict_self, ruleset_fd, flags);
}

} // namespace mylib::detail
