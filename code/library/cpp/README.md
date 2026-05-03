# mylib C++ Library

C++ implementation of a small Linux sandboxing/security helper library.

The library currently provides wrappers/utilities for:

- `seccomp`
- `Landlock`
- `PR_SET_NO_NEW_PRIVS`
- low-level syscall helpers

The public headers are located under:

```
include/mylib/
```

## Requirements

- Linux
- CMake 3.14 or newer
- A C++23-capable compiler
- Kernel support for the features being tested/used:
  - Landlock requires Linux 5.13+
  - newer Landlock access rights may require newer kernels
  - seccomp support must be enabled by the kernel

## Build

```sh
cmake -S . -B build
cmake --build build
```

## Run tests

```sh
ctest --test-dir build
```

## Debugging syscalls

`strace` is useful for checking whether Landlock or seccomp syscalls are reached.

For Landlock:

```sh
strace -f -e trace=landlock_create_ruleset,landlock_add_rule,landlock_restrict_self \
    ctest --test-dir build --output-on-failure
```

To include file opens as well:

```sh
strace -f -s 200 -o trace.txt \
    -e trace=landlock_create_ruleset,landlock_add_rule,landlock_restrict_self,openat,openat2 \
    ctest --test-dir build --output-on-failure

grep -E 'landlock|openat' trace.txt
```

Remember that `strace` writes to stderr, so this is needed when piping to `grep`:

```sh
strace -f ctest --test-dir build 2>&1 | grep landlock
```
