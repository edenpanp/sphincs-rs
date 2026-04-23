# sphincs-rs

Rust implementation of SPHINCS+ / SLH-DSA for the UNSW COMP3453 Applied
Cryptography term project. The main target is the
SPHINCS+-SHA2-256s-simple-style parameter set, with an optimised XMSS tree path,
Criterion benchmarks, and an experimental group-signature layer.

Last updated: 2026-04-23.

## Scope

Implemented core components:

- WOTS+ one-time signatures.
- FORS few-time signatures.
- XMSS tree construction and authentication paths.
- Hypertree signing and verification.
- Top-level SPHINCS+ key generation, signing, verification, and raw
  serialisation helpers.
- Experimental group-style signing, public verification, and manager-side
  member identification.

Important limitation: `src/group.rs` is an experimental extension. It is not a
complete DGSP implementation because it does not implement full join, revoke,
open, judge, or stateful certificate-lifecycle operations.

## Parameters

The primary constants are in `src/params.rs`.

| Constant | Value | Meaning |
|----------|-------|---------|
| `N` | 32 | Hash output length in bytes |
| `W` | 16 | Winternitz parameter |
| `H` | 64 | Total hypertree height |
| `D` | 8 | Number of hypertree layers |
| `HP` | 8 | XMSS height per layer |
| `K` | 22 | Number of FORS trees |
| `A` | 14 | Height of each FORS tree |
| `WOTS_LEN` | 67 | Number of WOTS+ chains |
| `SIG_BYTES` | 29,792 | Detached signature length |

## Optimisations

The project keeps baseline and optimised paths so correctness and performance
can be compared directly.

- Iterative bottom-up XMSS: avoids repeated recursive subtree work and gives
  about a 15% sequential improvement in the recorded XMSS/key-generation
  benchmarks.
- Rayon leaf parallelism: feature-gated behind `parallel`, with the largest
  recorded speedups in XMSS root generation and key generation.
- Parameter experiments: `src/params_alpha.rs` records SPHINCS-alpha-inspired
  size/runtime trade-offs.

See `docs/BENCHMARK_RESULTS.md` and `docs/ALPHA_COMPARISON_REPORT.md` for the
recorded benchmark data.

## Tests and Benchmarks

The repository currently contains:

- 54 library tests discovered by `cargo test --features test-utils --lib`.
- 10 integration tests in `tests/integration.rs`.
- 5 KAT-related tests in `tests/kat.rs`; the two file-dependent checks skip
  automatically unless the NIST `.rsp` file is copied into the expected path.
- 6 legacy helper tests in `src/group_impl_helpers.rs`; this file is not
  currently included by `src/lib.rs`, so those tests are not exercised by the
  normal Cargo commands.

Useful commands:

```sh
cargo check --features test-utils
cargo test --features test-utils --lib
cargo test --features test-utils --test integration
cargo test --test kat
cargo bench --features test-utils
cargo bench --features "test-utils parallel"
```

The NIST KAT file is stored at `tests/PQCsignKAT_128.rsp`. To run the
file-dependent KAT checks:

```sh
mkdir -p tests/kat
cp tests/PQCsignKAT_128.rsp tests/kat/sphincs-sha2-256s-simple.rsp
cargo test --test kat
```

## Demo

Run the marker-facing interactive demo:

```sh
cargo run --release --example demo
```

The demo prints the motivation for SPHINCS+ / SLH-DSA, selected parameters,
key/sign/verify timings, signature size, message tampering rejection,
signature-bit-flip rejection, raw-byte verification, and the experimental group
verification plus manager identification workflow.

For a live marking run, use the default message, choose `1` for the faster
`RawSha256` demo backend, and choose `y` for the group-extension section.

## Documentation

Start here:

- `START_HERE.md`: repository navigation.
- `docs/introduction.md`: documentation index.
- `docs/PROJECT_DOCUMENTATION.md`: main technical write-up.
- `docs/ARCHITECTURE.md`: module layering and data flow.
- `docs/TEST_RESULTS.md`: recorded correctness checks.
- `docs/BENCHMARK_RESULTS.md`: recorded benchmark results.
- `docs/API_REFERENCE.md`: public API summary.

The final project report is maintained separately in the sibling `paper`
directory.
