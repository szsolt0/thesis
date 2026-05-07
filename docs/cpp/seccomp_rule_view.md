# `SeccompRuleView`

## Overview

`SeccompRuleView` is a non-owning view of a seccomp BPF filter.

It is usually obtained from an owning [`SeccompRule`](seccomp_rule.md):

```cpp
auto rule = unwrap_or_die(builder.build());
unwrap_or_die(rule.view().apply());
```

`SeccompRuleView` does not manage the lifetime of the filter storage. It only
refers to an existing filter and provides the `apply()` operation.

For details about ownership and lifetime, see [`SeccompRule`](seccomp_rule.md).

## Synopsis

```cpp
class SeccompRuleView
{
public:
    [[nodiscard]] std::expected<void, int> apply() noexcept;
};
```

## `apply`

```cpp
[[nodiscard]] std::expected<void, int> apply() noexcept;
```

Applies the referenced seccomp filter to the current process.

After this function succeeds, the filter is active and cannot be removed by the
process. Any syscall not allowed by the filter is handled according to the
terminal action chosen when the rule was built.

### Requirements

`no_new_privs` must be enabled before applying a seccomp filter, unless the
process has the required privileges. In typical unprivileged programs, call
`set_no_new_privs()` before `apply()`.

The referenced filter storage must remain valid for the duration of the call.
When the view is created from `SeccompRule::view()`, this means the owning
`SeccompRule` must still be alive.

### Returns

Returns an empty `std::expected` on success, or a positive `errno` value on
failure.

## Example

```cpp
auto rule = unwrap_or_die(builder.build());
unwrap_or_die(rule.view().apply());
```

## See Also

- [`SeccompRule`](seccomp_rule.md)
- [`SeccompBuilder`](seccomp_builder.md)
- [`set_no_new_privs`](set_no_new_privs.md)
