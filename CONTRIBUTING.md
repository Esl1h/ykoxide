# Contributing

Issues and pull requests are welcome. Please read the [Code of Conduct](CODE_OF_CONDUCT.md) first, and report security problems through [SECURITY.md](SECURITY.md), not in a public issue.

## Build and test

Install the build dependencies listed in the [README](README.md#requirements), then:

```sh
cargo build
cargo test
```

Tests that need a real YubiKey are marked `#[ignore]`. Run them only with a key connected, and expect touch prompts:

```sh
YKOX_TEST_HW=1 cargo test -- --ignored
```

Some commands change the key: `age setup --generate` generates a key and `fido2 enroll` creates a credential. Never try them on a key you depend on; use a spare one.

## Quality gate

A pull request needs these to pass, and CI runs the same checks:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo audit
cargo deny check
```

## Conventions

- **Commits:** [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/), subject in the imperative mood and at most 50 characters. One logical change per commit, and refactors apart from behavior changes. Signed commits are preferred.
- **Comments:** explain why, not what.
- **Dependencies:** each new one needs a reason. `cargo deny` accepts only a closed list of licenses (see `deny.toml`), and the crate forbids `unsafe` code.
- **Secrets:** never commit real keys, PINs or private files. Test fixtures must be throwaway material, and public on purpose.
- **Behavior changes:** add or update a test. If a change can only be checked on hardware, say which key model and firmware you used.

## Pull requests

Keep them small and explain the why in the description. The maintainer lands accepted changes as a fast-forward of the branch, so rebase on `main` if asked.
