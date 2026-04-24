# sphincs-rs

This repository contains a Rust implementation of a SPHINCS+-style hash-based
signature scheme, together with an experimental certificate-backed group-signature
extension.

The main part of the project implements the SPHINCS+ signing workflow using
WOTS+, FORS, XMSS, and a hypertree. The group extension is built on top of the
SPHINCS+ code and is used to demonstrate manager-issued certificates, member
signing keys, public verification, manager-side signer identification, and simple
policy checks.

The main SPHINCS+ workflow is the primary implementation target. The group-signature layer is experimental DGSP implementation.

Last updated: 2026-04-24.

## Project Overview

The implementation is organised around the following goals:
- implement the main SPHINCS+ signing flow in Rust;
- keep WOTS+, FORS, XMSS, hypertree signing, hashing, and address handling in
  separate modules;
- support both a clearer baseline path and a faster XMSS path;
- provide raw-byte serialisation and deserialisation for signatures;
- include a hash abstraction so different hash backends can be tested;
- add a lightweight group-style extension on top of the main SPHINCS+ code.


## Scope

Implemented core components:

- WOTS+ one-time signatures.
- FORS few-time signatures.
- XMSS tree construction and authentication paths.
- Hypertree signing and verification.
- Top-level SPHINCS+ key generation, signing, verification, and raw
  serialisation helpers.
- Certificate-backed group-style signing built from manager-signed
  SPHINCS+ certificates and member-side WOTS+ one-time keys.

Scope note: `src/group.rs` is additional prototype work around manager-issued
certificates. The main evaluated implementation is the SPHINCS+ / SLH-DSA core.

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

- 52 library tests discovered by `cargo test --features test-utils --lib`.
- 8 integration tests in `tests/integration.rs`.
- 5 KAT-related tests in `tests/kat.rs`, covering parser/format checks and
  bundled reference-vector verification.
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

The bundled KAT file is stored at `tests/PQCsignKAT_128.rsp`. A compatibility
copy can still be placed at the legacy path expected by older notes:

```sh
mkdir -p tests/kat
cp tests/PQCsignKAT_128.rsp tests/kat/sphincs-sha2-256s-simple.rsp
cargo test --test kat
```

The current `Sha256Hasher` matches the bundled SPHINCS+-SHA2-256s-simple KAT
vectors, so `cargo test --test kat` now runs both parser checks and
reference-signature verification.

## Demo

Run the marker-facing interactive demo:

```sh
cargo run --release --example demo
```

The demo prints the motivation for SPHINCS+ / SLH-DSA, selected parameters,
key/sign/verify timings, signature size, message tampering rejection,
signature-bit-flip rejection, raw-byte verification, and the experimental group
workflow for member provisioning, public verification, manager-side signer
identification, and policy-based rejection.

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

## What Has Been Implemented
Implemented in the current version:

- WOTS+ key generation, signing, and public key recovery;
- FORS signing and public key reconstruction;
- XMSS signing and authentication path verification;
- hypertree signing and verification;
- top-level SPHINCS+ key generation, signing, and verification;
- SHA-256 hasher abstraction;
- simpler RawSha256 backend for testing and profiling;
- raw-byte signature serialisation and deserialisation;
- baseline and fast XMSS paths;
- optional Rayon-based leaf parallelism;
- parameter comparison module;
- experimental certificate-backed group extension;
- manager-issued member certificates;
- member WOTS+-based signing;
- public group verification;
- manager-side member identification;
- simple role and revocation policy checks.

## Current limitation

- the group extension is not a complete DGSP implementation;
- the group extension does not yet include a full join protocol;
- public certificate distribution is not fully implemented;
- there is no complete judge procedure;
- revocation is currently handled through simple policy lists;
- certificate lifecycle management is still minimal;
- group signing is very slow in the current demo.

## Repository Structure

```text
.
├── benches/                  # benchmarking code
│   └── sphincs_bench.rs
├── demo/                     # interactivity demo
│   ├── README.md
│   └── main.rs
├── docs/                     # project papers and references
│   └── ...
├── src-base/                 # baseline & alpha variants
│   └── ...
├── src/                      # Rust source code after encapsulating the module & group signature
│   └── ...
├── tests/                    # tests
│   ├── PQCsignKAT_128.rsp
│   ├── integration.rs
│   └── kat.rs
│   Cargo-base.toml
│   Cargo.lock
│   Cargo.toml
└── README.md
