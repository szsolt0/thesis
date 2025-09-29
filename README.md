# Bachelor Thesis

This repository contains the materials for my BSc thesis, including both the
written thesis and supporting codes.

- **Title:** Alkalmazásfejlesztői szintű erőforrás-izoláció a Linux kernelben:
  Landlock és seccomp szerepe és alkalmazása
- **Description:** Az operációs rendszerek biztonsága kiemelt jelentőségű. A
  dolgozat azt vizsgálja meg, hogy a Landlock, az eBPF és az azokhoz hasonló
  megoldások hogyan segítik a rendszerek biztonságosabbá tételét. A dolgozatban
  szó esik a SELinux és az AppArmor szerepéről. Konkrét alkalmazások, és létező
  sebezhetőségek vizsgálata kapcsán bemutatásra kerül ezek működése,
  retrospektív jelleggel, hogy az újonnan bevezetett módszerek milyen régebbi
  sebezhetőségeket lettek volna képesek megakadályozni. A dolgozat bemutatja
  továbbá egy saját függvénykönyvtár készítését, amely API-jának kialakításánál
  kiemelt szempont, hogy egyszerűbbé, kényelmesebbé tegye a biztonságos
  szoftverek fejlesztését.
- **Supervisor:** Nehéz Károly

# Thesis Scope

The thesis explores:

- Integration of Landlock and seccomp into software that may not yet use them.
- Real-world usage: how existing applications (e.g., Chromium) leverage these technologies.
- Comparison with other security frameworks: OpenBSD (`pledge`/`unveil`), SELinux, AppArmor.
- CVE analysis: evaluation of past vulnerabilities that could have been mitigated.
- API design and usability: creating a library to simplify secure software development in C++ or Rust.
- Performance and portability considerations: evaluating potential downsides or trade-offs.

## Repository Overview

This repository contains both the **thesis** and the **code** supporting it:

- `thesis/` contains the LaTeX source files for the written thesis.
- `code/` contains the actual code.

Currently, there's only a minimal Landlock example in `code/examples/`. It can
be run with:

```sh
cd code/examples/
g++ -std='c++20' -Wall -Wextra -O2 landlock.cpp
./a.out
```

It should output something like this:

```
Trying to open a.txt (should succeed)…
Success!
Trying to open b.txt (should fail)…
failed to open b.txt: Permission denied
```

Additionally, we can see in the `strace` output that the syscalls worked:

```strace
landlock_create_ruleset({handled_access_fs=LANDLOCK_ACCESS_FS_EXECUTE|LANDLOCK_ACCESS_FS_READ_FILE, handled_access_net=0, scoped=0}, 24, 0) = 3
landlock_add_rule(3, LANDLOCK_RULE_PATH_BENEATH, {allowed_access=LANDLOCK_ACCESS_FS_EXECUTE|LANDLOCK_ACCESS_FS_READ_FILE, parent_fd=4}, 0) = 0
landlock_restrict_self(3, 0)            = 0
```
