# SeccompRuleView

## Overview

`SeccompRuleView` is a lightweight, non-owning view of a compiled seccomp BPF filter (sock_fprog).
It provides a simple interface to apply the filter to the current process using the raw seccomp syscall.

## Synopsis

```cpp
class SeccompRuleView
{
public:
    std::expected<void, int> apply() noexcept;
};
```

| Method    | Description                                                                                                                                    |
| --------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `apply()` | Calls `seccomp(SECCOMP_SET_MODE_FILTER, ...)` to install the filter in the current process. Returns `expected<void, errno>` style error codes. |

## Example

```cpp
auto const r = view->apply();
if (!r) {
    std::cerr << "seccomp apply failed: " << r.error() << "\n";
}
```
