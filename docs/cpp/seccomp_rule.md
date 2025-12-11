## SeccompRule

## Overview

`SeccompRule` is an owning RAII wrapper around a compiled seccomp BPF filter.
It automatically unmaps the memory allocated for the BPF program.

It is returned by [`SeccompBuilder::build()`](seccomp_builder.md) and is designed to safely transfer ownership using move semantics.

## Synopsis

```cpp
class SeccompRule
{
public:
    SeccompRule(SeccompRule const&) = delete;
    SeccompRule& operator=(SeccompRule const&) = delete;

    SeccompRule(SeccompRule&& other) noexcept;
    SeccompRule& operator=(SeccompRule&& other) noexcept;

    SeccompRuleView view() const noexcept;
};
```

## Example

```cpp
auto const result = rule->view().apply();
if (!result) {
    std::cerr << "Failed to apply: " << result.error() << "\n";
}
```
