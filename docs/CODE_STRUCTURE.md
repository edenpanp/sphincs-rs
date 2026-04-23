# Code Structure

This file is just a file-oriented map of the repository. If you want the design explanation instead, [ARCHITECTURE.md](./ARCHITECTURE.md) is the better one to read.

---

## Top level

```
sphincs-rs/
  src/             main implementation
  tests/           integration tests and KAT support
  benches/         Criterion benchmarks
  docs/            this documentation package
  src-base/        earlier/baseline development material (historical)
  Cargo.toml       crate manifest and feature definitions
  README.md        project overview
```

---

## `src/`

This is the core implementation. In rough dependency order:

| File | What it contains |
|------|-----------------|
| `src/params.rs` | SHA2-256s constants: N, W, H, D, HP, K, A, SIG\_BYTES, etc. |
| `src/params_alpha.rs` | Experimental parameter variants for comparison |
| `src/hash.rs` | `SphincsHasher` trait; `Sha256Hasher` (real); `RawSha256` (testing) |
| `src/adrs.rs` | 32-byte domain-separation address; field setters |
| `src/digest.rs` | Splits the 47-byte message digest into md / idx\_tree / idx\_leaf and builds FORS addresses |
| `src/wots.rs` | WOTS+ — keygen, sign, pk-from-sig |
| `src/fors.rs` | FORS — tree nodes, signing, pk recovery |
| `src/xmss.rs` | XMSS tree — baseline (recursive) and fast (iterative) implementations |
| `src/ht.rs` | Hypertree — baseline and fast signing, shared verification |
| `src/sphincs.rs` | Top-level SLH-DSA API — keygen, sign, verify, serialise |
| `src/lib.rs` | Crate root — re-exports, module structure, usage examples |
| `src/group.rs` | Experimental group-signature extension (not the core SPHINCS+ implementation) |
| `src/group_impl_helpers.rs` | Legacy supporting code for the group experiment; not currently included by `src/lib.rs` |

If you are not sure where to start reading, `src/lib.rs` and then `src/sphincs.rs` are probably the easiest entry points. `src/xmss.rs` is the important one if you care about the optimisation work.

---

## `tests/`

| File | Purpose |
|------|---------|
| `tests/integration.rs` | 10 end-to-end tests against the public API (needs `--features test-utils`) |
| `tests/kat.rs` | KAT parser, decoder, and partial interoperability checks |
| `tests/PQCsignKAT_128.rsp` | 100-record NIST reference file (SHA2-256s-simple) |

The file-dependent KAT tests expect the `.rsp` file in a slightly different location. See [TEST_RESULTS.md](./TEST_RESULTS.md) for the one-time fix if you want to run those.

---

## `benches/`

There is currently one benchmark file: `benches/sphincs_bench.rs`. It contains the Criterion benchmark groups used for the project measurements.

---

## `docs/`

| File | What it covers |
|------|---------------|
| `introduction.md` | Navigation index |
| `PROJECT_DOCUMENTATION.md` | Main technical write-up |
| `DEVELOPER_GUIDE.md` | How to build, run, and modify the code |
| `API_REFERENCE.md` | Function-level quick reference |
| `ARCHITECTURE.md` | Layered design and data flow |
| `CODE_STRUCTURE.md` | This file |
| `TESTING_AND_BENCHMARKS.md` | How to run tests and benchmarks |
| `TEST_RESULTS.md` | Actual test outcomes |
| `BENCHMARK_RESULTS.md` | Measured performance numbers |
| `ALPHA_COMPARISON_REPORT.md` | Parameter comparison and alpha-style experiment notes |

---

## Feature flags (from `Cargo.toml`)

| Feature | Effect |
|---------|--------|
| `test-utils` | Exposes `RawSha256` and related testing helpers to integration tests and benchmarks |
| `parallel` | Enables Rayon-based leaf parallelism in `xmss_node_fast` |

Neither feature is enabled by default.
