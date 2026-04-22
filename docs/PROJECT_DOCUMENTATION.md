# sphincs-rs+

This project is a Rust implementation of SPHINCS+ (now standardised by NIST as SLH-DSA in FIPS 205), using the SPHINCS+-SHA2-256s-simple parameter set. It was built for UNSW COMP3453 Applied Cryptography, 26T1.

---

## Why SPHINCS+?

SPHINCS+ was selected by NIST as one of the post-quantum signature schemes, together with ML-DSA and Falcon. The reason it was interesting for this project is that it is fairly conservative compared with a lot of other PQC designs. It relies on hash functions rather than lattice assumptions, so the basic idea feels more familiar.

---

## Parameter set

The primary parameters are defined in `src/params.rs` and correspond to the `SPHINCS+-SHA2-256s-simple` variant:

| Constant | Value | Meaning |
|----------|-------|---------|
| `N` | 32 | hash output length in bytes |
| `W` | 16 | Winternitz parameter (chain length base) |
| `H` | 64 | total hypertree height |
| `D` | 8 | number of hypertree layers |
| `HP` | 8 | XMSS tree height per layer (HP = H/D) |
| `K` | 22 | number of FORS trees |
| `A` | 14 | height of each FORS tree |

Derived:

```
WOTS_LEN  = 67      // WOTS+ chain count (for len1=64, len2=3)
MD_BYTES  = 39      // FORS digest portion (ceil(K*A / 8))
M         = 47      // total message digest size
SIG_BYTES = 29792   // N + K*(1+A)*N + D*(WOTS_LEN+HP)*N
```

---

## Module layout

The file-by-file layering is described in **[ARCHITECTURE.md](./ARCHITECTURE.md#module-layout)**. That document is the canonical place for the code-structure overview, so this report does not repeat the full module map here.

---

## How a signature is built

The signing and verification flow is described in **[ARCHITECTURE.md](./ARCHITECTURE.md#key-data-flows)**. That section covers the digest split, the FORS-to-hypertree handoff, and why the scheme stays stateless.

---

## Key and signature layout

The concrete `SK` / `PK` / `SIG` layout is summarised in **[ARCHITECTURE.md](./ARCHITECTURE.md#key-and-signature-layout)**.

---

## Two implementations of the tree code

The baseline/fast split in `xmss.rs` and `ht.rs` is described in **[ARCHITECTURE.md](./ARCHITECTURE.md#the-optimisation-architecture)**. That is the main place where the recursive and iterative paths are compared.

---

## The hasher trait

The hashing abstraction is described in **[ARCHITECTURE.md](./ARCHITECTURE.md#hash-abstraction)**. That section explains the role of `SphincsHasher`, `Sha256Hasher`, and `RawSha256`, and why cross-hasher verification should fail.

---

## Testing

The project currently includes unit tests, integration tests, and KAT tests. They fall into three rough layers:

**Unit tests** live inside each module and check things in isolation. The XMSS equivalence test is probably the most important one. Without it, the optimisation story would be much harder to trust.

**Integration tests** (`tests/integration.rs`) exercise the public API from the outside. They cover round-trips for both hashers, wrong-message rejection, serialisation checks, the raw-byte API, deterministic `R`, cross-key rejection, cross-hasher rejection, empty messages, long messages, and sampled bit-flip tampering.

**KAT tests** (`tests/kat.rs`) use the NIST `.rsp` reference file included in the repo at `tests/PQCsignKAT_128.rsp`. The parser tests run without the file-dependent path, and the full file-based verification needs a one-time copy to `tests/kat/sphincs-sha2-256s-simple.rsp` first.

More detail is in [TEST_RESULTS.md](./TEST_RESULTS.md).

---

## Performance

In [BENCHMARK_RESULTS.md](./BENCHMARK_RESULTS.md).

The baseline-vs-alpha size and runtime comparison is documented in
[ALPHA_COMPARISON_REPORT.md](./ALPHA_COMPARISON_REPORT.md).

---

## Group signature extension

`src/group.rs` contains an experimental group-signature layer built on top of the SPHINCS+ implementation, based on [ePrint 2025/760](https://eprint.iacr.org/2025/760.pdf).

---

## Limitations

**Signature size.** The signature is still 29,792 bytes. That is not really an implementation bug; it is just a tradeoff of SPHINCS+ itself.

**Signing latency.** Even with the fast path and parallelism, signing is still relatively slow compared with traditional signature schemes.

**Build state.** The previous merge-conflict markers in `src/group.rs`, `src/xmss.rs`, and `benches/sphincs_bench.rs` have been cleaned up.

**Parameter coverage.** The main testing and benchmark results focus on the SHA2-256s variant. Other parameter files exist, but they were not explored to the same depth in this project.
