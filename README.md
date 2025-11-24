# Bachelor Thesis

This repository contains the materials for my BSc thesis, including both the
written thesis and supporting codes.

- **Title:** Alkalmazásfejlesztői szintű erőforrás-izoláció a Linux kernelben:
  Landlock és seccomp szerepe és alkalmazása
- **Description:** The security of operating systems is of critical importance.
  This thesis examines how Landlock, BPF, and similar mechanisms contribute to
  making systems more secure. It also discusses the roles of SELinux and AppArmor.
  Through the study of specific applications and known vulnerabilities, the thesis
  demonstrates how these mechanisms work and, retrospectively, which past
  vulnerabilities could have been mitigated by their use. Additionally, the thesis
  presents the development of a custom library, designed with an API that
  prioritizes ease of use and convenience for secure software development.
- **Supervisor:** Károly Nehéz

# Thesis Scope

The thesis explores:

- Integration of Landlock and seccomp into software that may not yet use them.
- Real-world usage: how existing applications (e.g., Chromium) leverage these technologies.
- Comparison with other security frameworks: OpenBSD (`pledge`/`unveil`), SELinux, AppArmor.
- CVE analysis: evaluation of past vulnerabilities that could have been mitigated.
- API design and usability: creating a library to simplify secure software development in C++ or Rust.
- Performance and portability considerations: evaluating potential downsides or trade-offs.

## Repository Overview

This repository contains both the thesis and the supporting code:

- `thesis/` – LaTeX source files for the written thesis.
- `docs/` – Documentation related to the library and thesis.
- `code/` – All related code.
    - `examples/` – Various example programs.
    - `library/` – Implementation of the custom library.
        - `cpp/` – C++ version.
        - `rs/` – Rust version.
        - `common/` – Shared files used by both versions (e.g., list of syscall categories).
