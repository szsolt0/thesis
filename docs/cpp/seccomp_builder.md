# SeccompBuilder

## Overview

`SeccompBuilder` constructs seccomp BPF programs using a high-level rule interface such as:

```cpp
builder->allow("read");
builder->allow("openat");
```

# Synopsis

```cpp
class SeccompBuilder
{
public:
    static std::expected<SeccompBuilder, int> init() noexcept;
    static std::expected<SeccompBuilder, int> init_no_defaults() noexcept;

    std::expected<void, int> allow(std::string_view what) noexcept;

    std::expected<SeccompRule, int> build(bool kill_entire_process = true) noexcept;
    std::expected<SeccompRuleView, int> build_static(bool kill_entire_process = true) noexcept;
};
```

# Example

```cpp
auto builder_ret = SeccompBuilder::init();
if (!builder_ret) {
    std::cerr << "init failed: " << builder_ret.error() << "\n";
    return 1;
}

auto builder = std::move(builder_ret.value());

// Allow basic syscalls
builder.allow("io"); // I/O
builder.allow("unix"); // UNIX sockets

// Produce final rule
auto rule_ret = builder.build();
if (!rule_ret) {
    std::cerr << "build failed: " << rule_ret.error() << "\n";
    return 1;
}

auto& rule = rule_ret.value();

// Apply seccomp
auto apply_ret = rule.view().apply();
if (!apply_ret) {
    std::cerr << "seccomp failed: " << apply_ret.error() << "\n";
}
```
