# Validation

Validated on 2026-11-05 in the existing WSL Ubuntu 20.04 / Python 3.8 environment:

- Editable package and NTL C++ extension built successfully from this directory.
- Five commitment, parameter and recovery tests passed.
- Four-party local sharing reconstructed [17, 29] successfully.
- Runtime imports were checked to resolve to this clean source directory.

A fresh operating-system installation and comparison protocol execution were not
validated. The setup instructions use the pinned dependencies from the working
implementation. Test success does not constitute a security audit.

Vendored pypairing Rust wheel also built successfully with nightly-2023-12-01.
