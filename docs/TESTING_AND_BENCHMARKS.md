# Testing and Benchmarks

This file is a short summary of how correctness was checked and how the performance numbers were collected.

---

## Test layers

The testing is split into three levels:

**Unit tests** live inside the source modules. They check the smaller pieces separately, like WOTS+, FORS, digest splitting, and serialisation. The most important one is the XMSS equivalence test, where the recursive and iterative versions must produce the same root.

**Integration tests** are in [`tests/integration.rs`](../tests/integration.rs). They check the public API from the outside: sign/verify, wrong-message rejection, raw-byte helpers, deterministic behaviour, cross-key rejection, cross-hasher rejection, empty and long messages, and tamper detection.

**KAT tests** are in [`tests/kat.rs`](../tests/kat.rs). The parser tests run on their own, while the file-based checks run once the NIST `.rsp` file has been copied into the expected path.

---

## Running tests

```bash
cargo test                                              # everything
cargo test --lib                                        # unit tests only
cargo test --features test-utils --test integration    # integration suite
cargo test --test kat                                   # parser tests always run; file-based KAT tests run if the file is in place
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

---

## KAT path fix

The NIST test vectors ship as `tests/PQCsignKAT_128.rsp` (100 records, SPHINCS+-SHA2-256s-simple). The test runner looks for them at `tests/kat/sphincs-sha2-256s-simple.rsp`. Fix once with:

```bash
mkdir -p tests/kat
cp tests/PQCsignKAT_128.rsp tests/kat/sphincs-sha2-256s-simple.rsp
```

After that, the KAT verification and re-signing checks can run normally.

---

## Current build issue

There are currently unresolved merge conflicts blocking compilation:

| File | Problem |
|------|---------|
| `src/group.rs` | unresolved merge-conflict markers |
| `src/xmss.rs` | unresolved merge-conflict markers |
| `benches/sphincs_bench.rs` | unresolved merge-conflict markers in several benchmark functions |

These conflicts need to be fixed before the normal `cargo` commands work again.
