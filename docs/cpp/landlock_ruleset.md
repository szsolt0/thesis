# `LandlockRuleSet` Class

## Contructor

```cpp
[[nodiscard]] static std::expected<LandlockRuleSet, int> init() noexcept
```

### Description

Constructs a new `LandlockRuleSet` instance. Returns a `std::expected` that
contains either a valid `LandlockRuleSet` or an error code
(`int`) if initialization fails.

### Requirements

At least one available file descriptor is needed for Landlock operations.

### Safety

MT-Safe | AS-Safe

## `add_rule`

```cpp
[[nodiscard]] std::expected<void, int> add_rule(int fd, LandlockAccess access) noexcept
[[nodiscard]] std::expected<void, int> add_rule(int dirfd, char const* path, LandlockAccess access) noexcept
```

### Description

Adds a rule to the Landlock ruleset.

If using the `fd` overload, the file descriptor **MUST** be opened with the `O_PATH`
flag.

Otherwise, use the (`dirfd`, `path`) overload, which handles path-based rules.
`AT_FDCWD` can be used for `dirfd` to specify relative paths from the current
working directory.

### Parameters

- `fd` – File descriptor opened with `O_PATH`.
- `dirfd` – Base directory file descriptor for the path.
- `path` – Path to the file or directory to apply the rule to.
- `access` – The type of access to allow ([`LandlockAccess`](landlock_access.md)).

### Requirements

One available file descriptor if the path-based overload is used.

## `apply`

```cpp
[[nodiscard]] std::expected<void, int> apply() noexcept;
```

### Description

Applies the rules in the `LandlockRuleSet`. After calling this function:

- The ruleset becomes immutable.
- No further rules can be added.
- Must be called exactly once for the ruleset to take effect.

### Safety

MT-Safe | AS-Safe

## Examples

The following example demonstrates how to use the `LandlockRuleSet` API with a
simple error-handling strategy. The example uses a helper function fail(int)
that terminates the program immediately on error. This style is convenient for
example code and scripts where you want the "happy path" to remain linear and
readable.

```cpp
// Example error handler for demonstration purposes.
// This function is marked [[noreturn]] and will terminate the program immediately.
[[noreturn]] void fail(int err) noexcept;

int main()
{
	using namespace mylib;

	auto rule_set = LandlockRuleSet::init().value_or(fail);

	rule_set.add_rule("/path/i/want/to/modify", LandlockAccess::Unlimited).or_else(fail);
	rule_set.add_rule("/path/i/want/to/read", LandlockAccess::ReadOnly).or_else(fail);
	rule_set.add_rule("/bin/possible/child", LandlockAccess::ExecuteOnly).or_else(fail);

	rule_set.apply().or_else(fail);
}
```

## See Also

[`LandlockAccess`](landlock_access.md)
