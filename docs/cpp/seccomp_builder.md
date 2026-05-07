# `SeccompBuilder`

## Overview

`SeccompBuilder` builds seccomp BPF filters through a small, high-level rule
interface.

Instead of manually writing BPF instructions, the user enables predefined
syscall groups by name:

```cpp
builder.allow("io");
builder.allow("file_system");
```

The resulting filter is represented by a `SeccompRule`. The rule can then be
applied to the current process through `SeccompRuleView::apply()`.

## Synopsis

```cpp
class SeccompBuilder
{
public:
    [[nodiscard]] static std::expected<SeccompBuilder, int> init() noexcept;
    [[nodiscard]] static std::expected<SeccompBuilder, int> init_no_defaults() noexcept;

    [[nodiscard]] std::expected<void, int>
    allow(std::string_view what) noexcept;

    [[nodiscard]] std::expected<SeccompRule, int>
    build(bool kill_entire_process = true) noexcept;

    [[nodiscard]] std::expected<SeccompRuleView, int>
    build_static(bool kill_entire_process = true) noexcept;
};
```

## Initialization

```cpp
[[nodiscard]] static std::expected<SeccompBuilder, int> init() noexcept;
```

Creates a new builder with the library's default syscall groups enabled.

This is the recommended constructor for most programs, because dynamically
linked C++ programs usually require a small set of runtime-related syscalls
before application-specific operations are considered.

Returns a `SeccompBuilder` on success, or a positive `errno` value on failure.

```cpp
[[nodiscard]] static std::expected<SeccompBuilder, int> init_no_defaults() noexcept;
```

Creates a new builder without enabling any default syscall groups.

This is useful for stricter configurations or tests where every allowed syscall
group should be specified explicitly.

Returns a `SeccompBuilder` on success, or a positive `errno` value on failure.

## `allow`

```cpp
[[nodiscard]] std::expected<void, int>
allow(std::string_view what) noexcept;
```

Enables a predefined syscall group.

The exact groups are defined by the library. Typical examples include groups for
basic I/O, filesystem access, memory management, process control, or IPC-related
operations.

### Parameters

- `what` — name of the syscall group to enable.

### Returns

Returns an empty `std::expected` on success, or a positive `errno` value on
failure.

### Notes

Calling `allow()` does not apply any restrictions immediately. It only changes
the builder state. The seccomp filter is generated later by `build()` or
`build_static()`.

## `build`

```cpp
[[nodiscard]] std::expected<SeccompRule, int>
build(bool kill_entire_process = true) noexcept;
```

Builds an owning `SeccompRule` from the currently enabled syscall groups.

The returned rule owns the generated BPF program and can be applied through its
view:

```cpp
auto rule = unwrap_or_die(builder.build());
unwrap_or_die(rule.view().apply());
```

### Parameters

- `kill_entire_process` — controls the terminal seccomp action used when a
  disallowed syscall is reached. When `true`, the process is killed. When
  `false`, only the offending thread is killed.

### Returns

Returns a `SeccompRule` on success, or a positive `errno` value on failure.

## `build_static`

```cpp
[[nodiscard]] std::expected<SeccompRuleView, int>
build_static(bool kill_entire_process = true) noexcept;
```

Builds a non-owning `SeccompRuleView`.

This variant is intended for cases where the generated filter storage is managed
elsewhere or has static lifetime. For ordinary user code, prefer `build()`.

### Parameters

- `kill_entire_process` — controls the terminal seccomp action used when a
  disallowed syscall is reached. When `true`, the process is killed. When
  `false`, only the offending thread is killed.

### Returns

Returns a `SeccompRuleView` on success, or a positive `errno` value on failure.

## Example

The following example creates a seccomp filter, enables a small set of syscall
groups, builds the final rule, and applies it to the current process.

```cpp
#include <mylib/no_new_privs.h>
#include <mylib/seccomp.h>

#include <cstdlib>
#include <cstring>
#include <expected>
#include <iostream>
#include <utility>

[[noreturn]] void die(int why) noexcept
{
    std::cerr << "error: " << std::strerror(why) << '\n';
    std::exit(1);
}

template <class T>
T unwrap_or_die(std::expected<T, int>&& result)
{
    if (!result) {
        die(result.error());
    }

    return std::move(result).value();
}

inline void unwrap_or_die(std::expected<void, int>&& result)
{
    if (!result) {
        die(result.error());
    }
}

int main()
{
    unwrap_or_die(mylib::set_no_new_privs());

    auto builder = unwrap_or_die(mylib::SeccompBuilder::init());

    unwrap_or_die(builder.allow("io"));
    unwrap_or_die(builder.allow("file_system"));

    auto rule = unwrap_or_die(builder.build());

    unwrap_or_die(rule.view().apply());

    // Disallowed syscalls are blocked from this point onward.

    return 0;
}
```

## See Also

- [`SeccompRule`](seccomp_rule.md)
- [`SeccompRuleView`](seccomp_rule_view.md)
- [`set_no_new_privs`](no_new_privs.md)
