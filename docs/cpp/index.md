# C++ Library

This is the C++ implementation of the sandboxing library.

The library provides a small, high-level API for applying Linux process-level
sandboxing mechanisms from C++ code. It is built around three main components:

1. [`LandlockRuleSet`](landlock_rule_set.md) — builds and applies Landlock
   filesystem access rules.

2. [`SeccompBuilder`](seccomp_builder.md) — builds seccomp BPF filters from
   predefined syscall groups.

3. [`set_no_new_privs`](no_new_privs.md) — enables the Linux `no_new_privs`
   attribute, which is required before applying unprivileged seccomp or Landlock
   restrictions.

A typical sandbox setup first enables `no_new_privs`, then configures and
applies seccomp and/or Landlock rules:

```cpp
unwrap_or_die(mylib::set_no_new_privs());

auto seccomp = unwrap_or_die(mylib::SeccompBuilder::init());
unwrap_or_die(seccomp.allow("io"));
unwrap_or_die(seccomp.allow("file_system"));

auto rule = unwrap_or_die(seccomp.build());
unwrap_or_die(rule.view().apply());

auto landlock = unwrap_or_die(mylib::LandlockRuleSet::init());
unwrap_or_die(landlock.add_rule("input.txt", mylib::LandlockAccess::Read));
unwrap_or_die(landlock.apply());
```

## Components

- [`LandlockRuleSet`](landlock_rule_set.md)
- [`LandlockAccess`](landlock_access.md)
- [`SeccompBuilder`](seccomp_builder.md)
- [`SeccompRule`](seccomp_rule.md)
- [`SeccompRuleView`](seccomp_rule_view.md)
- [`set_no_new_privs`](no_new_privs.md)
