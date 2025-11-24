// raw_syscall.h
// Raw system calls
// Author: Zsolt Sebe
// WARN: Currently only for x86_64

#pragma once
#include <sys/syscall.h>

namespace mylib::detail {

template <typename R>
static inline __attribute__((always_inline))
R raw_syscall0(const long nr) noexcept
{
    register R ret __asm__("rax");

    __asm__ volatile (
        "syscall"
        : "=r"(ret)
        : "0"(nr)
        : "rcx", "r11", "memory"
    );

    return ret;
}

template <typename R, typename A1>
static inline __attribute__((always_inline))
R raw_syscall1(const long nr, const A1 a1) noexcept
{
    register R ret __asm__("rax");
    const register auto arg1 __asm__("rdi") = a1;

    __asm__ volatile (
        "syscall"
        : "=r"(ret)
        : "0"(nr), "r"(arg1)
        : "rcx", "r11", "memory"
    );

    return ret;
}

template <typename R, typename A1, typename A2>
static inline __attribute__((always_inline))
R raw_syscall2(const long nr, const A1 a1, const A2 a2) noexcept
{
    register R ret __asm__("rax");
    const register auto arg1 __asm__("rdi") = a1;
    const register auto arg2 __asm__("rsi") = a2;

    __asm__ volatile (
        "syscall"
        : "=r"(ret)
        : "0"(nr), "r"(arg1), "r"(arg2)
        : "rcx", "r11", "memory"
    );

    return ret;
}

template <typename R, typename A1, typename A2, typename A3>
static inline __attribute__((always_inline))
R raw_syscall3(const long nr, const A1 a1, const A2 a2, const A3 a3) noexcept
{
    register R ret __asm__("rax");
    const register auto arg1 __asm__("rdi") = a1;
    const register auto arg2 __asm__("rsi") = a2;
    const register auto arg3 __asm__("rdx") = a3;

    __asm__ volatile (
        "syscall"
        : "=r"(ret)
        : "0"(nr), "r"(arg1), "r"(arg2), "r"(arg3)
        : "rcx", "r11", "memory"
    );

    return ret;
}

template <typename R, typename A1, typename A2, typename A3, typename A4>
static inline __attribute__((always_inline))
R raw_syscall4(const long nr, const A1 a1, const A2 a2, const A3 a3, const A4 a4) noexcept
{
    register R ret __asm__("rax");
    const register auto arg1 __asm__("rdi") = a1;
    const register auto arg2 __asm__("rsi") = a2;
    const register auto arg3 __asm__("rdx") = a3;
    const register auto arg4 __asm__("r10") = a4;

    __asm__ volatile (
        "syscall"
        : "=r"(ret)
        : "0"(nr), "r"(arg1), "r"(arg2), "r"(arg3), "r"(arg4)
        : "rcx", "r11", "memory"
    );

    return ret;
}

template <typename R, typename A1, typename A2, typename A3, typename A4, typename A5>
static inline __attribute__((always_inline))
R raw_syscall5(const long nr, const A1 a1, const A2 a2, const A3 a3, const A4 a4, const A5 a5) noexcept
{
    register R ret __asm__("rax");
    const register auto arg1 __asm__("rdi") = a1;
    const register auto arg2 __asm__("rsi") = a2;
    const register auto arg3 __asm__("rdx") = a3;
    const register auto arg4 __asm__("r10") = a4;
    const register auto arg5 __asm__("r8")  = a5;

    __asm__ volatile (
        "syscall"
        : "=r"(ret)
        : "0"(nr), "r"(arg1), "r"(arg2), "r"(arg3), "r"(arg4), "r"(arg5)
        : "rcx", "r11", "memory"
    );

    return ret;
}

template <typename R, typename A1, typename A2, typename A3, typename A4, typename A5, typename A6>
static inline __attribute__((always_inline))
R raw_syscall6(const long nr, const A1 a1, const A2 a2, const A3 a3, const A4 a4, const A5 a5, const A6 a6) noexcept
{
    register R ret __asm__("rax");
    const register auto arg1 __asm__("rdi") = a1;
    const register auto arg2 __asm__("rsi") = a2;
    const register auto arg3 __asm__("rdx") = a3;
    const register auto arg4 __asm__("r10") = a4;
    const register auto arg5 __asm__("r8")  = a5;
    const register auto arg6 __asm__("r9")  = a6;

    __asm__ volatile (
        "syscall"
        : "=r"(ret)
        : "0"(nr), "r"(arg1), "r"(arg2), "r"(arg3), "r"(arg4), "r"(arg5), "r"(arg6)
        : "rcx", "r11", "memory"
    );

    return ret;
}

static inline __attribute__((always_inline))
void exit_group(const int status) noexcept
{
	constexpr register long nr __asm__("rax") = SYS_exit_group;
    const register auto arg1 __asm__("rdi") = status;

	__asm__ volatile (
        "syscall"
        :
        : "r"(nr), "r"(arg1)
        : "memory"
    );

	__builtin_unreachable();
}

} // namespace mylib
