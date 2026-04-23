# API Reference

This file is mainly here as a quick lookup. If you want the bigger explanation of how the pieces fit together, [PROJECT_DOCUMENTATION.md](./PROJECT_DOCUMENTATION.md) is the better place to start.

---

## Top-level SPHINCS+ API (`src/sphincs.rs`)

These are the functions most people would actually call.

| Function | Returns | Notes |
|----------|---------|-------|
| `slh_keygen<S>()` | `(SphincsSK, SphincsPK)` | Baseline: recursive XMSS root |
| `slh_keygen_fast<S>()` | `(SphincsSK, SphincsPK)` | Fast: iterative XMSS root — use this by default |
| `slh_sign<S>(msg, sk)` | `SphincsSignature` | Baseline signing |
| `slh_sign_fast<S>(msg, sk)` | `SphincsSignature` | Fast signing — use this by default |
| `slh_verify<S>(msg, sig, pk)` | `bool` | Works for signatures from either path |
| `slh_sign_raw<S>(msg, sk)` | `Vec<u8>` | Baseline sign + serialise in one call |
| `slh_sign_raw_fast<S>(msg, sk)` | `Vec<u8>` | Fast sign + serialise |
| `slh_verify_raw<S>(msg, bytes, pk)` | `bool` | Deserialise then verify |
| `serialise_sig(sig)` | `Vec<u8>` | Structured → bytes |
| `deserialise_sig(bytes)` | `Option<SphincsSignature>` | Bytes → structured; `None` if the length is wrong |

**Key types:**

```
SphincsSK  = { sk_seed, sk_prf, pk_seed, pk_root }   (128 bytes)
SphincsPK  = { pk_seed, pk_root }                    (64 bytes)
SIG_BYTES  = 29 792
```

**Typical usage:**

```rust
use sphincs_rs::hash::Sha256Hasher;
use sphincs_rs::sphincs::{slh_keygen_fast, slh_sign_fast, slh_verify};

let (sk, pk) = slh_keygen_fast::<Sha256Hasher>();
let sig = slh_sign_fast::<Sha256Hasher>(b"message", &sk);
assert!(slh_verify::<Sha256Hasher>(b"message", &sig, &pk));
```

If you need raw bytes for storage, debugging, or KAT comparison:

```rust
use sphincs_rs::sphincs::{slh_keygen_fast, slh_sign_raw_fast, slh_verify_raw};

let (sk, pk) = slh_keygen_fast::<Sha256Hasher>();
let raw = slh_sign_raw_fast::<Sha256Hasher>(b"message", &sk);
assert!(slh_verify_raw::<Sha256Hasher>(b"message", &raw, &pk));
```

---

## Hashers (`src/hash.rs`)

All of the top-level functions are generic over `S: SphincsHasher`.

| Type | Use case |
|------|----------|
| `Sha256Hasher` | Real SHA-256-based implementation; use for anything compliance-sensitive |
| `RawSha256` | Stripped-down hasher; faster, no compliance, good for unit tests and benchmarks; available without `test-utils` |

---

## XMSS (`src/xmss.rs`)

These functions are public in the current codebase and are mainly useful for testing or benchmarking.

| Function | Notes |
|----------|-------|
| `xmss_node<S>(sk, idx, h, pk, adrs)` | Recursive root/node computation |
| `xmss_node_fast<S>(sk, idx, h, pk, adrs)` | Iterative bottom-up; ~15% faster |
| `xmss_sign<S>(msg, sk, idx_leaf, pk, adrs)` | Baseline signing with auth path |
| `xmss_sign_fast<S>(msg, sk, idx_leaf, pk, adrs)` | Fast signing |
| `xmss_pk_from_sig<S>(idx_leaf, sig, msg, pk, adrs)` | Root recovery from signature (used in verification) |

In practice, the main reason to call these directly is testing or benchmarking rather than normal library use.

---

## Hypertree (`src/ht.rs`)

| Function | Notes |
|----------|-------|
| `ht_sign<S>(msg, sk, pk, idx_tree, idx_leaf)` | Baseline hypertree signing |
| `ht_sign_fast<S>(msg, sk, pk, idx_tree, idx_leaf)` | Fast; calls `xmss_sign_fast` at each layer |
| `ht_verify<S>(msg, sig, pk_seed, idx_tree, idx_leaf, pk_root)` | Shared verifier; works for both |

---

## FORS (`src/fors.rs`)

| Function | Notes |
|----------|-------|
| `fors_sign<S>(md, sk, pk, adrs)` | Signs the 39-byte message digest portion |
| `fors_pk_from_sig<S>(sig, md, pk, adrs)` | Recovers FORS public key; used by both sign and verify |
| `fors_node<S>(...)` | Single node computation; mainly useful for unit tests |
| `fors_sk_gen<S>(...)` | Secret key element derivation |

---

## WOTS+ (`src/wots.rs`)

| Function | Notes |
|----------|-------|
| `wots_pk_gen<S>(sk, pk, adrs)` | Public key from seed |
| `wots_sign<S>(msg, sk, pk, adrs)` | Sign a digest-length value |
| `wots_pk_from_sig<S>(sig, msg, pk, adrs)` | Recover and check public key; used in XMSS verification |

---

## Digest helpers (`src/digest.rs`)

| Function | Notes |
|----------|-------|
| `split_digest(d)` | Splits 47-byte digest into `(md, idx_tree, idx_leaf)` |
| `fors_adrs(idx_tree, idx_leaf)` | Builds the FORS address from indices |

---

## Parameter constants (`src/params.rs`)

```rust
N         = 32      // hash output size (bytes)
W         = 16      // Winternitz parameter
H         = 64      // total tree height
D         = 8       // hypertree layers
HP        = 8       // XMSS height per layer
K         = 22      // FORS trees
A         = 14      // FORS tree height
WOTS_LEN  = 67
MD_BYTES  = 39
M         = 47
SIG_BYTES = 29792
```

---

## Group API (`src/group.rs`)

The group-signature API is experimental. It is not part of the main evaluated
SPHINCS+ core, so it should be read as extra work rather than as a complete
DGSP implementation. In particular, the current API demonstrates a
certificate-backed group-style workflow: manager key generation, member
provisioning, one-time WOTS+ signing under a manager-issued SPHINCS+
certificate, public verification, manager-side signer identification, and
metadata-policy checks. It does not yet implement the full DGSP join protocol,
public opening proofs, encrypted tracing tokens, or the paper's complete
certificate lifecycle.
