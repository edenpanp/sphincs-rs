# Testing & Benchmarking Guide — sphincs-rs

UNSW 26T1 Applied Cryptography Group Project
Implementation of SPHINCS+ (SLH-DSA, FIPS 205) in Rust.

---

## Quick start

```bash
# Unit tests only — fast, no feature flags needed
cargo test

# Unit tests + integration tests (uses RawSha256 and Sha256Hasher)
cargo test --features test-utils

# Integration tests only
cargo test --test integration --features test-utils

# KAT byte-exact compliance tests (requires NIST file, see below)
cargo test --test kat --features test-utils

# Benchmarks — baseline vs optimised, sequential
cargo bench --features test-utils

# Benchmarks — with Rayon parallel leaf generation
cargo bench --features "test-utils parallel"

# Save a baseline then compare after a change
cargo bench --features test-utils -- --save-baseline before
# ... edit code ...
cargo bench --features test-utils -- --baseline before
```

---

## Feature flags

| Flag          | Effect                                                          |
|---------------|-----------------------------------------------------------------|
| `test-utils`  | Exposes `RawSha256` (non-compliant fast hasher for testing)     |
| `parallel`    | Enables Rayon-based parallel leaf generation inside `build_tree` |

---

## Unit tests (`cargo test`)

Every `src/*.rs` module contains an inline `#[cfg(test)]` block.
Total: **65 tests** across 9 modules.

| Module          | Tests | What is covered                                          |
|-----------------|-------|----------------------------------------------------------|
| `params`        | 0     | Compile-time constant assertions (checked at build time) |
| `params_alpha`  | 6     | SPHINCS-alpha parameter set sizes and security bounds    |
| `adrs`          | 0     | Field layout verified via hash tests                     |
| `hash`          | 13    | MGF1, HMAC-SHA-256 RFC 4231 vectors, PRF/H determinism  |
| `wots`          | 2     | Sign/verify round-trip, wrong-message rejection          |
| `xmss`          | 4     | Baseline vs fast root agreement, wrong-message rejection |
| `fors`          | 5     | Index decode, tree roots, sign/verify round-trip         |
| `ht`            | 4     | Baseline vs fast agreement, wrong message/key rejection  |
| `sphincs`       | 11    | Baseline + fast keygen/sign/verify, serialise, bit-flip  |
| `group`         | 7     | Group sign/verify, cross-group, identify member, anon    |

---

## Integration tests (`cargo test --test integration --features test-utils`)

End-to-end pipeline tests using both hashers. **8 tests.**

- `RawSha256` and `Sha256Hasher` full round-trips (fast variant)
- Cross-hasher signatures correctly rejected
- Empty message (`b""`) and 64 KiB message both handled
- 8 bit-flip positions across the 29 792-byte signature all detected
- 3 independent key pairs non-interfering
- `SIG_BYTES == 29792` verified against `N + K(1+A)N + D(WOTS_LEN+HP)N`

---

## KAT tests — NIST byte-exact compliance

### Setup

1. Download the SPHINCS+ reference implementation:
   <https://sphincs.org/software.html> → "Reference implementation"

2. Locate the KAT response file inside the archive:
   ```
   KAT/sphincs-sha2-256s-simple/PQCsignKAT_sphincs-sha2-256s-simple.rsp
   ```

3. Place it at (relative to the crate root):
   ```
   tests/kat/sphincs-sha2-256s-simple.rsp
   ```

4. Run:
   ```bash
   cargo test --test kat --features test-utils
   ```

### What is checked

| Test                        | Checks                                                  |
|-----------------------------|---------------------------------------------------------|
| `kat_verify_all_signatures` | Our verifier accepts every signature in the NIST file   |
| `kat_sign_matches_reference`| Our signer reproduces the exact same bytes as NIST      |

### Diagnosing failures

| Symptom                                   | Likely cause                                    |
|-------------------------------------------|-------------------------------------------------|
| `kat_verify` fails                        | Hash function output is wrong                   |
| `kat_verify` passes, `kat_sign` fails     | ADRS compression or padding differs from spec   |
| Both fail on first record only            | SK/PK byte-layout parsing (`decode_sk`) is off  |

If `kat_sign_matches_reference` fails, check `compress_adrs()` in `src/hash.rs`:
the field order is `layer[3] ‖ tree[4..12] ‖ type[3] ‖ type_bits[0..12]` (22 bytes).

---

## Benchmarks

HTML reports are written to `target/criterion/` and can be opened in a browser.

### Benchmark groups

| Group              | Sub-variants            | Description                                      |
|--------------------|-------------------------|--------------------------------------------------|
| `keygen`           | baseline / fast         | Full keygen — builds D × 2^HP WOTS+ leaves       |
| `sign`             | baseline / fast         | Sign a 64-byte message end-to-end                |
| `verify`           | —                       | Verify a signature (auth-path walk only)         |
| `xmss_root`        | baseline / fast         | One XMSS tree root (2^HP=256 leaves, HP=8)       |
| `wots_keygen`      | —                       | Isolated WOTS+ PK gen (67 chains × 15 steps)     |
| `fors_sign`        | —                       | FORS sign (K=22 trees × A=14 levels)             |
| `alpha_comparison` | standard / small / fast | SPHINCS-alpha parameter set size comparison      |
| `group`            | keygen / sign / verify / identify | Group signature operations            |

Each group runs both `RawSha256` (fast, non-compliant) and `Sha256Hasher`
(FIPS 205 compliant) variants.

### Actual results (single-core, Windows, release profile)

| Operation             | Time         | Notes                                      |
|-----------------------|--------------|--------------------------------------------|
| `keygen/baseline`     | ~54 ms       | Builds full top-level XMSS tree            |
| `keygen/fast`         | ~54 ms       | Same leaf count; benefit is parallelism    |
| `sign/baseline`       | ~625 ms      | 255 leaves computed on demand              |
| `sign/fast`           | ~700 ms      | 256 leaves upfront; faster with `parallel` |
| `verify`              | ~0.8 ms      | Auth-path walk only — 800× faster than sign|
| `fors_sign`           | ~200 ms      | Dominant cost inside `sign`                |
| `group/sign`          | ~678 ms      | Same as `slh_sign_fast`                    |
| `group/identify`      | ~7.5 ms      | Linear scan of 256 member leaves           |
| Sig size (standard)   | 29 792 B     | SHA2-256s NIST parameters                  |
| Sig size (alpha-small)| 27 296 B     | K=14, A=17 — −8.4% vs standard            |

### Why `sign/fast` is slower than `sign/baseline` on a single core

`xmss_sign` (baseline) computes only the **255** leaves needed for the
authentication path, on demand. `xmss_sign_fast` (iterative) builds the
**entire tree** of 256 leaves upfront to avoid redundant subtree computation —
this is one more leaf, but eliminates all duplicate sub-tree recomputation
across levels. The iterative approach pays off in two scenarios:

1. **Multi-core hardware** with `--features parallel`: all 256 leaves are
   independent and distributed across CPU cores via Rayon, giving close to
   linear speedup in the number of cores.
2. **Repeated signing with the same key**: the tree can be cached and reused.

---

## Interpreting test results

| Result                   | Meaning                                           |
|--------------------------|---------------------------------------------------|
| `cargo test` passes      | Structural logic correct for all modules          |
| Integration tests pass   | Both hashers produce self-consistent pipelines    |
| `kat_verify` passes      | Hash functions compatible with NIST reference     |
| `kat_sign` passes        | Full byte-exact FIPS 205 compliance achieved ✓    |
| Group tests pass         | Group signature construction correct (eprint 2025/760) |
