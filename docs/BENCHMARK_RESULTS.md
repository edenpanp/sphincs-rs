# Benchmark Results

**Machine:** MacBook Pro, Apple M2 Max (8 performance + 4 efficiency cores, arm64)  
**OS:** macOS 26.4.1  
**Rust:** 1.94.1

These results were collected from the last working benchmark run. The benchmark definitions are in [`benches/sphincs_bench.rs`](../benches/sphincs_bench.rs).

---

## Commands

```bash
cargo bench --features test-utils                       # sequential
cargo bench --features "test-utils parallel"            # parallel

# optional: save a baseline then compare against it
cargo bench --features test-utils -- --save-baseline before
cargo bench --features test-utils -- --baseline before
```

Criterion prints both mean and median timings, but the tables below use rounded means because the runs were stable enough that the difference was not very interesting.

---

## Sequential results

```bash
cargo bench --features test-utils
```

| Group | Variant | Time |
|-------|---------|------|
| keygen | baseline/RawSha256 | ~58 ms |
| keygen | fast/RawSha256 | ~50 ms |
| keygen | baseline/Sha256Hasher | ~1.2 s |
| keygen | fast/Sha256Hasher | ~1.0 s |
| sign | baseline/RawSha256 | ~812 ms |
| sign | fast/RawSha256 | ~657 ms |
| verify | RawSha256 | ~841–1350 µs |
| verify | Sha256Hasher | ~841–1350 µs |
| xmss_root | baseline_recursive/RawSha256 | ~58 ms |
| xmss_root | fast_iterative/RawSha256 | ~50 ms |
| wots_keygen | RawSha256 | < 1 ms |
| fors_sign | RawSha256 | low ms range |

The roughly 15% improvement on key generation and `xmss_root` comes from removing repeated subtree recomputation. The recursive version revisits work while building authentication paths, while the iterative version computes each node once in a bottom-up pass.

`RawSha256` is much faster than `Sha256Hasher`, which is expected. `RawSha256` is really just a simplified testing and benchmarking backend, while `Sha256Hasher` is the proper FIPS-style implementation.

The verification timings are much closer together because verification already does a more limited amount of work compared with key generation and signing.

---

## Parallel results

```bash
cargo bench --features "test-utils parallel"
```

| Group | Sequential | Parallel (8 cores) | Speedup |
|-------|------------|-------------------|---------|
| keygen/fast/RawSha256 | ~50 ms | ~6.8–7.0 ms | **8.5×** |
| keygen/fast/Sha256Hasher | ~1.0 s | ~120 ms | **~8×** |
| sign/fast/RawSha256 | ~657 ms | ~267–348 ms | **2–3×** |
| verify/RawSha256 | ~900 µs | ~557–803 µs | **1.3×** |
| xmss_root/fast/RawSha256 | ~50 ms | ~6 ms | **~8×** |
| group/open | ~7–10 ms | ~4.8–5.0 ms | **1.5×** |

Key generation gets the biggest parallel win because the XMSS leaves can be computed independently. Rayon distributes that work very well, so most of the headline speedup comes from here.

Signing only improves by around 2 to 3 times because the hypertree still has sequential dependencies between layers. You can parallelise work inside a layer, but not the whole signing process from start to finish.

Verification barely changes because it does not rebuild trees. It just walks the authentication paths already stored in the signature.

`group/open` improves a little, but not dramatically.

---

## Summary

| Operation | Baseline | Fast | Parallel | Net gain over baseline |
|-----------|----------|------|----------|------------------------|
| Key generation | 58 ms | 50 ms | 7 ms | **8.5×** |
| Signing | 812 ms | 657 ms | ~300 ms | **2–3×** |
| Verification | ~1100 µs | same | ~680 µs | **1.3×** |
| XMSS root | 58 ms | 50 ms | 6 ms | **~8×** |

If one number has to be picked out, it is probably key generation dropping from about 58 ms to about 7 ms.

---

## Parameter comparison

The `alpha_comparison` benchmark also prints this to stdout:

```
=== SPHINCS-alpha parameter set comparison ===
variant                       FORS (B)       HT (B)    total (B)  FORS sec
SHA2-256s (standard)            8800        20992      29792 (+0%)      91.0b
Alpha-128s-small (K=14,A=17)    7616        20992      28608 (-4%)     119.0b
Alpha-128s-fast  (K=35,A=9)    10080        20992      31072 (+4%)      70.0b
```

A few quick observations on this table:

- The hypertree part stays the same because only the FORS parameters change here.
- The smaller and faster variants trade off signature size and FORS cost in different ways.
- The standard choice sits in the middle, which is why it is a sensible default.

For the separate baseline-vs-alpha experiment with 29,792-byte and 27,232-byte signatures, see [ALPHA_COMPARISON_REPORT.md](./ALPHA_COMPARISON_REPORT.md).
