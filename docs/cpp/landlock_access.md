# `LandlockAccess`

## Overview

`LandlockAccess` describes the filesystem permissions that can be granted to a
path in a [`LandlockRuleSet`](landlock_rule_set.md).

Landlock rules are allow-list based. After a ruleset is applied, a process may
only perform filesystem operations that are explicitly allowed by the matching
rules.

For example:

```cpp
landlock.add_rule("input.txt", LandlockAccess::Read);
landlock.add_rule("output", LandlockAccess::ReadWrite);
```

## Synopsis

```cpp
enum class LandlockAccess
{
    Read,
    Write,
    Execute,

    ReadWrite,
    ReadExecute,
    WriteExecute,

    All,
};
```

## Values

### `Read`

Allows read-oriented access to the selected file or directory.

Use this for input files, configuration files, or directories that should be
visible but not modified.

```cpp
landlock.add_rule("input.txt", LandlockAccess::Read);
```

### `Write`

Allows write-oriented access to the selected file or directory.

Use this for output locations where the process should be able to create or
modify files, but does not need to read existing content.

```cpp
landlock.add_rule("output", LandlockAccess::Write);
```

### `Execute`

Allows executing files from the selected path.

Use this for binaries or directories containing programs that the sandboxed
process may execute.

```cpp
landlock.add_rule("/bin", LandlockAccess::Execute);
```

### `ReadWrite`

Allows both read and write access.

This is useful for working directories, temporary directories, or other paths
where the process needs to both inspect and modify files.

```cpp
landlock.add_rule("work", LandlockAccess::ReadWrite);
```

### `ReadExecute`

Allows reading and executing files.

This is commonly useful for directories containing programs or shared runtime
files that must be readable and executable, but should not be modified.

```cpp
landlock.add_rule("/usr/bin", LandlockAccess::ReadExecute);
```

### `WriteExecute`

Allows write and execute access.

This combination is included for completeness. It may be useful for specialized
cases where a process needs to create or modify executable files in a controlled
location, but does not need to read existing file contents.

```cpp
landlock.add_rule("generated-tools", LandlockAccess::WriteExecute);
```

### `All`

Allows all filesystem access rights represented by the library.

Use this only for paths that should remain fully accessible inside the sandbox.

```cpp
landlock.add_rule("trusted_dir", LandlockAccess::All);
```

## Notes

The exact Landlock access flags represented by each value are handled by the
library. The enum is intended to provide a simpler, higher-level interface than
using raw Landlock bitmasks directly.

Grant only the smallest access level needed by the program. For example, prefer
`Read` over `ReadWrite` for input files, and prefer `ReadExecute` over `All` for
system directories that only need to be read or executed.

`WriteExecute` should usually be avoided unless the program specifically needs
that combination. In many sandboxed programs, writable locations and executable
locations should be kept separate.

## Example

```cpp
auto landlock = unwrap_or_die(mylib::LandlockRuleSet::init());

unwrap_or_die(
    landlock.add_rule("input.txt", mylib::LandlockAccess::Read)
);

unwrap_or_die(
    landlock.add_rule("output", mylib::LandlockAccess::ReadWrite)
);

unwrap_or_die(landlock.apply());
```

## See Also

- [`LandlockRuleSet`](landlock_rule_set.md)
