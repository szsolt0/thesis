# `LandlockRuleSet`

## Overview

`LandlockRuleSet` builds and applies Landlock filesystem access rules for the
current process.

It represents an allow-list of filesystem paths and permissions. Rules are added
before the ruleset is applied:

```cpp
landlock.add_rule("/etc/passwd", LandlockAccess::Read);
landlock.add_rule("output", LandlockAccess::ReadWrite);
```

After `apply()` succeeds, filesystem access is restricted to the paths and
permissions explicitly allowed by the ruleset. The restriction applies to the
current process and is inherited by child processes.

`LandlockRuleSet` is an RAII wrapper around the underlying Landlock ruleset file
descriptor.

## Synopsis

```cpp
class LandlockRuleSet
{
public:
    [[nodiscard]] static std::expected<LandlockRuleSet, int> init() noexcept;

    [[nodiscard]] std::expected<void, int>
    add_rule(int fd, LandlockAccess access) noexcept;

    [[nodiscard]] std::expected<void, int>
    add_rule(char const* path, LandlockAccess access) noexcept;

    [[nodiscard]] std::expected<void, int> apply() noexcept;
};
```

## Initialization

```cpp
[[nodiscard]] static std::expected<LandlockRuleSet, int> init() noexcept;
```

Creates a new Landlock ruleset.

On success, returns a `LandlockRuleSet` object that owns the underlying ruleset
file descriptor. On failure, returns a positive `errno` value.

The ruleset is created before any filesystem restrictions are applied. Paths are
made accessible with `add_rule()`, and the actual restriction only takes effect
after `apply()` succeeds.

### Requirements

- Landlock must be supported by the running kernel.
- The process must be able to create a Landlock ruleset.
- At least one file descriptor must be available.

## `add_rule`

```cpp
[[nodiscard]] std::expected<void, int>
add_rule(int fd, LandlockAccess access) noexcept;

[[nodiscard]] std::expected<void, int>
add_rule(char const* path, LandlockAccess access) noexcept;
```

Adds a filesystem access rule to the ruleset.

The `fd` overload adds a rule for an already-opened file descriptor. The file
descriptor should refer to the file or directory that should be made accessible
inside the sandbox.

The `path` overload opens the path internally and adds a rule for the referenced
file or directory. This is the preferred overload for most user code, because it
does not require manually opening an `O_PATH` file descriptor.

### Parameters

- `fd` — file descriptor referring to the file or directory.
- `path` — path to the file or directory to allow.
- `access` — access rights to grant for the path.

### Returns

Returns an empty `std::expected` on success, or a positive `errno` value on
failure.

### Notes

Rules are allow-list based. Adding a rule grants the selected access rights to
the given file or directory once the ruleset is applied.

Adding a rule does not immediately restrict the process. Restrictions only take
effect after `apply()` succeeds.

## `apply`

```cpp
[[nodiscard]] std::expected<void, int> apply() noexcept;
```

Applies the Landlock ruleset to the current process.

After this function succeeds:

- the current process is restricted by the ruleset;
- the restrictions are inherited by child processes;
- no more rules can be added to this ruleset;
- the operation cannot be undone by the process.

### Requirements

`no_new_privs` must be enabled before applying a Landlock ruleset, unless the
process has the required privileges. In typical unprivileged programs, call the
library's `set_no_new_privs()` helper before `apply()`.

### Returns

Returns an empty `std::expected` on success, or a positive `errno` value on
failure.

## Example

The following example demonstrates a simple sandboxed `cat`-like program. It
allows read access only to the files passed as command-line arguments, then
applies the Landlock ruleset before opening and printing them.

```cpp
#include <mylib/landlock.h>
#include <mylib/no_new_privs.h>
#include <mylib/seccomp.h>

#include <cstdlib>
#include <cstring>
#include <expected>
#include <fstream>
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

int main(int argc, char* argv[])
{
    unwrap_or_die(mylib::set_no_new_privs());

    auto seccomp = unwrap_or_die(mylib::SeccompBuilder::init());

    unwrap_or_die(seccomp.allow("io"));
    unwrap_or_die(seccomp.allow("file_system"));

    auto seccomp_rule = unwrap_or_die(seccomp.build());
    unwrap_or_die(seccomp_rule.view().apply());

    auto landlock = unwrap_or_die(mylib::LandlockRuleSet::init());

    for (int i = 1; i < argc; ++i) {
        unwrap_or_die(
            landlock.add_rule(argv[i], mylib::LandlockAccess::Read)
        );
    }

    unwrap_or_die(landlock.apply());

    for (int i = 1; i < argc; ++i) {
        std::ifstream file(argv[i], std::ios::binary);

        if (!file) {
            std::cerr << "cat: cannot open " << argv[i] << '\n';
            return 1;
        }

        std::cout << file.rdbuf();
    }

    return 0;
}
```

This example applies seccomp before Landlock. Therefore, the seccomp policy must
still allow the filesystem-related system calls needed by Landlock setup and by
the later file-reading code.

## See Also

- [`LandlockAccess`](landlock_access.md)
- [`SeccompBuilder`](seccomp_builder.md)
- [`set_no_new_privs`](no_new_privs.md)
