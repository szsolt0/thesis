# `set_no_new_privs`

## Overview

`set_no_new_privs()` enables the Linux `no_new_privs` attribute for the current
process.

This is commonly required before applying unprivileged seccomp or Landlock
restrictions.

## Synopsis

```cpp
[[nodiscard]] std::expected<void, int> set_no_new_privs() noexcept;
```

## Description

Sets `PR_SET_NO_NEW_PRIVS` for the current process using `prctl`.

After this succeeds, the current process and its child processes cannot gain new
privileges through operations such as `execve()` of set-user-ID or set-group-ID
programs.

The function is equivalent to:

```cpp
prctl(PR_SET_NO_NEW_PRIVS, 1L, 0L, 0L, 0L);
```

## Returns

Returns an empty `std::expected` on success, or a positive `errno` value on
failure.

## Example

```cpp
auto result = mylib::set_no_new_privs();

if (!result) {
    std::cerr << "set_no_new_privs failed: "
              << std::strerror(result.error()) << '\n';
    return 1;
}
```

or, using a helper such as `unwrap_or_die`:

```cpp
unwrap_or_die(mylib::set_no_new_privs());
```

## Notes

The `no_new_privs` attribute is inherited across `fork()` and `execve()`.

Once set, it cannot be unset by the process.

## See Also

- [`SeccompRuleView`](seccomp_rule_view.md)
- [`LandlockRuleSet`](landlock_rule_set.md)
- [`PR_SET_NO_NEW_PRIVS(2const)`](https://man7.org/linux/man-pages/man2/PR_SET_NO_NEW_PRIVS.2const.html)
