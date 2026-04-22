# Developer Guide

This file is the more practical companion to [PROJECT_DOCUMENTATION.md](./PROJECT_DOCUMENTATION.md). The main report explains the design and the results. This one is more like a working note for whoever has to read the code, run it, or modify it later.

---

## Reading order

If you are opening the repo for the first time, this is probably the least painful order to read things in:

1. `src/lib.rs` — crate root. Module layout, feature flags, a quick-start example.
2. `src/params.rs` — the parameter constants (N=32, H=64, D=8, etc.). Everything else derives from these, and looking at them first makes the rest of the code less mysterious.
3. `src/sphincs.rs` — the public API. If you only ever want to *use* the crate, you never need to go below this.
4. `src/xmss.rs` + `src/ht.rs` — where the performance work lives. These are also the most interesting files to read.
5. `tests/integration.rs` — the end-to-end tests. Reading them is often faster than reading the API docs, because they show what correct usage looks like in context.
6. `benches/sphincs_bench.rs` — how performance was evaluated. Good reference if you want to add a new measurement.

`src/group.rs` and `src/group_impl_helpers.rs` are more experimental. They are still worth looking at for context, but I would not treat them as stable reference files.

If you care more about understanding the cryptographic structure than the Rust API, then `params.rs` → `adrs.rs` → `wots.rs` → `fors.rs` → `xmss.rs` → `ht.rs` → `sphincs.rs` is a better order.

---

## File responsibilities

| File | What it does |
|------|--------------|
| `src/params.rs` | SHA2-256s constants (N, W, H, D, HP, K, A, SIG_BYTES, WOTS_LEN, M…) |
| `src/params_alpha.rs` | Experimental parameter variants used in the `alpha_comparison` benchmark |
| `src/hash.rs` | `SphincsHasher` trait, `Sha256Hasher` (real), `RawSha256` (stripped-down) |
| `src/adrs.rs` | 32-byte domain-separation address with typed field setters |
| `src/digest.rs` | Splits the 47-byte digest into `(md, idx_tree, idx_leaf)` |
| `src/wots.rs` | WOTS+ keygen, sign, public-key recovery |
| `src/fors.rs` | FORS tree nodes, signing, pk recovery |
| `src/xmss.rs` | XMSS — both recursive baseline and iterative fast path |
| `src/ht.rs` | Hypertree signing (baseline + fast) and shared verification |
| `src/sphincs.rs` | Top-level SLH-DSA API plus serialisation helpers |
| `tests/integration.rs` | 10 end-to-end public API tests |
| `tests/kat.rs` | NIST KAT `.rsp` parser and verification against the 100-record file |
| `benches/sphincs_bench.rs` | Criterion benchmark suite (8 groups) |

---

## Using the API

Example Usage:

```rust
use sphincs_rs::hash::Sha256Hasher;
use sphincs_rs::sphincs::{slh_keygen_fast, slh_sign_fast, slh_verify};

let (sk, pk) = slh_keygen_fast::<Sha256Hasher>();
let sig = slh_sign_fast::<Sha256Hasher>(b"message", &sk);
assert!(slh_verify::<Sha256Hasher>(b"message", &sig, &pk));
```

A few details that are easy to miss just from reading the type signatures:

- `slh_verify` accepts signatures from either signing path. The output format is the same, so verification does not care whether the signer used the baseline or fast version.
- `slh_sign_fast` is deterministic for the same `(sk, msg)` pair.
- At the serialisation layer, keys and signatures are just raw bytes. If you need framing or metadata, that has to be handled by your own format.

If you need raw bytes for storage, KAT comparison, or simple interop, use the raw helpers:

```rust
use sphincs_rs::sphincs::{slh_keygen_fast, slh_sign_raw_fast, slh_verify_raw};

let (sk, pk) = slh_keygen_fast::<Sha256Hasher>();
let sig_bytes = slh_sign_raw_fast::<Sha256Hasher>(b"message", &sk);
assert!(slh_verify_raw::<Sha256Hasher>(b"message", &sig_bytes, &pk));
```

Use `slh_keygen` and `slh_sign` without `_fast` only if you specifically want to compare against the baseline recursive implementation.

The `test-utils` feature is mainly there to expose `RawSha256` and similar testing helpers to integration tests and benchmarks. Lower-level functions such as `xmss_node`, `xmss_node_fast`, `fors_sign`, and `wots_pk_gen` are already public in the current codebase.

---

## Running tests

```bash
cargo test                                              # all tests
cargo test --lib                                        # unit tests only (fast)
cargo test --features test-utils --test integration    # integration suite
cargo test --test kat                                   # parser tests always run; file-based KAT tests run if the file is in place
```

The KAT file ships at `tests/PQCsignKAT_128.rsp` but the runner expects it at `tests/kat/sphincs-sha2-256s-simple.rsp`. One-time setup:

```bash
mkdir -p tests/kat && cp tests/PQCsignKAT_128.rsp tests/kat/sphincs-sha2-256s-simple.rsp
```

This is just a filename and location issue, not a conversion issue. The contents stay the same.

If you want a single `cargo test` that runs everything once the KAT file has been copied into place:

```bash
cargo test --features test-utils
```

---

## Running benchmarks

```bash
cargo bench --features test-utils                      # sequential baseline
cargo bench --features "test-utils parallel"           # with Rayon
```

Criterion writes HTML reports to `target/criterion/`. They are useful if you want the graphs rather than just terminal output.

To compare before and after a change:

```bash
cargo bench --features test-utils -- --save-baseline before
# make changes
cargo bench --features test-utils -- --baseline before
```

Criterion also reports relative change and a significance estimate. On a laptop, very small differences are often just noise.

A few practical notes from repeated runs:

- Close other heavy apps if possible, especially browsers.
- Run on AC power.
- The first run after a cold start can be slower than later runs.

---

## Where the optimisation work is

Most of the optimisation work is in XMSS tree construction. `src/xmss.rs` keeps two versions side by side:

- `xmss_node` / `xmss_sign` — recursive, follows the spec closely. This is the "is the math right" version.
- `xmss_node_fast` / `xmss_sign_fast` — iterative bottom-up, builds the tree in one pass. This is the "is it fast enough to actually use" version.

The recursive version is easier to follow, but it ends up recomputing subtrees while building authentication paths. The iterative version builds bottom-up and computes each node once, which is where the sequential speedup mainly comes from.

The `parallel` feature then adds Rayon-based leaf parallelism. This helps key generation a lot, and signing to a lesser degree, because the hypertree layers still have to be processed in order.

If you only want to isolate the XMSS change itself, the `xmss_root` benchmark is the cleanest one to look at.

See [TESTING_AND_BENCHMARKS.md](./TESTING_AND_BENCHMARKS.md) for the fuller explanation.
