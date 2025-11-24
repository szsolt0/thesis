# `set_no_new_privs` Function

```cpp
std::expected<void, int> set_no_new_privs() noexcept;
```

## Description

Sets the `PR_SET_NO_NEW_PRIVS` flag for the current process using the `prctl`
syscall. Once enabled, this prevents the process and its children from gaining
new privileges via execve or set-user-ID binaries.

This is exectly equivalent to the folloving code:

```cpp
prctl(PR_SET_NO_NEW_PRIVS, 1L, 0L, 0L, 0L);
```

## Examples

```cpp
set_no_new_privs().or_else(/* handle error */);
```

```cpp
if (!set_no_new_privs()) {
	// handle error
}
```

## See Also

[PR_SET_NO_NEW_PRIVS(2const)](https://man7.org/linux/man-pages/man2/PR_SET_NO_NEW_PRIVS.2const.html)
