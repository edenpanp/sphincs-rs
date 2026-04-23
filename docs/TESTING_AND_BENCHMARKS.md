# Testing and Benchmarks

This file is a short summary of how correctness was checked and how the performance numbers were collected.

---

## Test layers

The testing is split into three levels:

**Unit tests** live inside the source modules. They check the smaller pieces separately, like WOTS+, FORS, digest splitting, and serialisation. The most important one is the XMSS equivalence test, where the recursive and iterative versions must produce the same root.

**Integration tests** are in [`tests/integration.rs`](../tests/integration.rs). They check the public API from the outside: sign/verify, wrong-message rejection, raw-byte helpers, deterministic behaviour, cross-key rejection, cross-hasher rejection, empty and long messages, and tamper detection.

**KAT tests** are in [`tests/kat.rs`](../tests/kat.rs). They cover parser and
length checks plus reference-vector verification against the bundled
SPHINCS+-SHA2-256s-simple signatures.

---

## Running tests

```bash
cargo test                                              # everything
cargo test --lib                                        # unit tests only
cargo test --features test-utils --test integration    # integration suite
cargo test --test kat                                   # KAT parser + bundled-vector verification
```

If you only changed one area, these are the most relevant checks:
- Changed `xmss.rs` or `ht.rs` → run integration tests and look at `xmss_root`
- Changed serialisation → run integration tests and KAT-related tests
- Changed `adrs.rs` → run everything, because address bugs tend to show up indirectly

---

## Running benchmarks

```bash
cargo bench --features test-utils                   # baseline vs fast, two hashers
cargo bench --features "test-utils parallel"        # add Rayon parallelism
```

Criterion writes HTML output to `target/criterion/`. To compare before and after a change:

```bash
cargo bench --features test-utils -- --save-baseline before
# make the change
cargo bench --features test-utils -- --baseline before
```

The benchmark groups are `keygen`, `sign`, `verify`, `xmss_root`, `wots_keygen`, `fors_sign`, `alpha_comparison`, and `group`. If the goal is just to isolate the XMSS improvement, `xmss_root` is the cleanest one.

For the separate baseline-vs-alpha experiment, see [ALPHA_COMPARISON_REPORT.md](./ALPHA_COMPARISON_REPORT.md).

---

## KAT file layout

The bundled test vectors ship as `tests/PQCsignKAT_128.rsp`. Older notes refer
to the legacy path `tests/kat/sphincs-sha2-256s-simple.rsp`; if you want that
path present too, copy the file once:

```bash
mkdir -p tests/kat
cp tests/PQCsignKAT_128.rsp tests/kat/sphincs-sha2-256s-simple.rsp
```

This is only a compatibility copy for older notes. The active KAT runner reads
the bundled file directly from `tests/PQCsignKAT_128.rsp`.

---

## Current merge state

The previous unresolved merge-conflict markers have been cleaned from:

| File | Problem |
|------|---------|
| `src/group.rs` | group-signature API conflict resolved |
| `src/xmss.rs` | XMSS baseline/fast conflict resolved |
| `benches/sphincs_bench.rs` | benchmark duplicate/conflict blocks resolved |

The latest lightweight compile check was `cargo check --features test-utils`.
