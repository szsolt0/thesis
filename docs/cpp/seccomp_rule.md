# `SeccompRule`

## Overview

`SeccompRule` is an owning wrapper around a generated seccomp BPF filter.

A `SeccompRule` is usually created by `SeccompBuilder::build()`:

```cpp
auto builder = unwrap_or_die(SeccompBuilder::init());

unwrap_or_die(builder.allow("io"));
unwrap_or_die(builder.allow("file_system"));

auto rule = unwrap_or_die(builder.build());
unwrap_or_die(rule.view().apply());
```

The rule owns the memory that stores the generated BPF program. To apply it, use
`view()` to obtain a non-owning `SeccompRuleView`, then call
`SeccompRuleView::apply()`.

## Synopsis

```cpp
class SeccompRule
{
public:
    SeccompRule(SeccompRule const&) = delete;
    SeccompRule& operator=(SeccompRule const&) = delete;

    SeccompRule(SeccompRule&& other) noexcept;
    SeccompRule& operator=(SeccompRule&& other) noexcept;

    [[nodiscard]] SeccompRuleView view() const noexcept;
};
```

## Construction

`SeccompRule` objects are not normally constructed directly by user code.
Instead, they are produced by `SeccompBuilder::build()`.

```cpp
[[nodiscard]] std::expected<SeccompRule, int>
SeccompBuilder::build(bool kill_entire_process = true) noexcept;
```

### Description

Builds an owning seccomp rule from the syscall groups enabled in the builder.

On success, the returned `SeccompRule` owns the generated BPF filter. On failure,
the function returns a positive `errno` value.

### Notes

`SeccompRule` is move-only. Copying is disabled because the object owns the
storage backing the generated seccomp filter.

## `view`

```cpp
[[nodiscard]] SeccompRuleView view() const noexcept;
```

Creates a non-owning view of the generated seccomp filter.

The returned `SeccompRuleView` can be used to apply the filter to the current
process:

```cpp
auto rule = unwrap_or_die(builder.build());
unwrap_or_die(rule.view().apply());
```

### Returns

Returns a `SeccompRuleView` referring to the BPF filter owned by this
`SeccompRule`.

### Lifetime

The returned `SeccompRuleView` does not own the filter storage. It must not
outlive the `SeccompRule` object it was created from.

This is safe for immediate use:

```cpp
unwrap_or_die(rule.view().apply());
```

Avoid storing the view after the owning `SeccompRule` has been destroyed or
moved from.

## Example

The following example creates a seccomp rule, obtains a view from it, and applies
the filter to the current process.

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

    // The seccomp filter is active from this point onward.

    return 0;
}
```

## See Also

- [`SeccompBuilder`](seccomp_builder.md)
- [`SeccompRuleView`](seccomp_rule_view.md)
- [`set_no_new_privs`](set_no_new_privs.md)
