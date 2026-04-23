# Start Here

This file is the quick navigation guide for the `sphincs-rs` project.

Last updated: 2026-04-23.

## Project Snapshot

The repository contains a Rust SPHINCS+ / SLH-DSA implementation, benchmark
support, an interactive demo, and an experimental group-signature extension.

Current scope:

- Core SPHINCS+ implementation: present.
- Baseline and optimised XMSS paths: present.
- Rayon parallel benchmark path: present behind the `parallel` feature.
- Integration, KAT parser, and benchmark support: present.
- Full DGSP group signatures: not complete; the group module is experimental.
- Final report: maintained in the sibling `paper` directory.

## Quick Facts

```text
Source files:        12 Rust files under src/
Exported modules:    11 modules from src/lib.rs
Library tests:       54 discovered by cargo test --features test-utils --lib
Integration tests:   10 in tests/integration.rs
KAT tests:           5 in tests/kat.rs
Benchmark file:      benches/sphincs_bench.rs
Demo entry point:    demo/main.rs
Documentation files: 10 Markdown files under docs/
```

`src/group_impl_helpers.rs` also contains 6 legacy helper tests, but that file
is not currently included by `src/lib.rs`, so those tests are not exercised by
the normal Cargo commands.

## Read This First

- `README.md`: project overview, commands, scope, and limitations.
- `docs/introduction.md`: documentation index.
- `docs/PROJECT_DOCUMENTATION.md`: main technical write-up.
- `docs/ARCHITECTURE.md`: system layout and signing/verification data flow.
- `docs/DEVELOPER_GUIDE.md`: practical guide for running and modifying code.
- `docs/TEST_RESULTS.md`: recorded test outcomes and KAT notes.
- `docs/BENCHMARK_RESULTS.md`: recorded benchmark results.
- `docs/ALPHA_COMPARISON_REPORT.md`: parameter-comparison notes.
- `demo/README.md`: short live-demo instructions.

## Useful Commands

```sh
cargo check --features test-utils
cargo test --features test-utils --lib
cargo test --features test-utils --test integration
cargo test --test kat
cargo bench --features test-utils
cargo bench --features "test-utils parallel"
cargo run --release --example demo
```

The file-dependent KAT tests need the included `.rsp` file in the expected
subdirectory:

```sh
mkdir -p tests/kat
cp tests/PQCsignKAT_128.rsp tests/kat/sphincs-sha2-256s-simple.rsp
cargo test --test kat
```

## Demo Path

For marking, the most useful command is:

```sh
cargo run --release --example demo
```

Suggested live-demo choices:

- Press Enter for the default message.
- Select `1` for the faster `RawSha256` demo backend.
- Select `y` to run the experimental group-extension section.

The demo is designed to show more than a happy-path signature: it explains the
post-quantum motivation, prints parameters and concrete sizes, verifies a valid
signature, rejects a modified message, rejects a modified signature, checks raw
serialisation, and demonstrates the experimental group verification plus
manager-side opening and a minimal revocation-policy workflow.
