# Architecture

## Module layout

The codebase is organised in layers, and each main source file more or less matches one level of the SPHINCS+ algorithm. Dependencies mostly flow downward:

```
src/params.rs / params_alpha.rs     ← constants only, no logic
  src/hash.rs                       ← SphincsHasher trait + implementations
    src/adrs.rs                     ← domain-separation addresses
      src/wots.rs                   ← WOTS+ one-time signatures
        src/xmss.rs                 ← Merkle tree over WOTS+ keys
        src/fors.rs                 ← FORS few-time signatures
          src/ht.rs                 ← hypertree (stacks XMSS layers)
            src/sphincs.rs          ← top-level keygen / sign / verify
            src/group.rs            ← experimental group-sig (not core)
```

`src/digest.rs` sits a bit to the side of this stack. It just splits the 47-byte digest into `(md, idx_tree, idx_leaf)` and builds the corresponding FORS address. Both the main SPHINCS+ flow and the group-signature experiment use it.

This layout was not just for neatness. Early on, larger modules got hard to read very quickly, and debugging them was even worse. Splitting the code by layer made it much easier to narrow down where a wrong value was actually coming from.

---

## Why this layering matters

The main benefit is that each layer can be read and tested without needing to keep the whole scheme in your head at once. WOTS+ does not need to know anything about the hypertree. FORS does not need to know how the public API is exposed. That separation made debugging a lot more manageable.

It also helped with optimisation. Most of the performance-sensitive work is concentrated in `xmss.rs` and `ht.rs`, so the faster path could be added without rewriting the whole top-level API.

Another deliberate choice was keeping both the baseline and fast implementations in the same tree. The baseline version is slower, but it is easier to trust because it stays closer to the spec. The fast version is the one you would actually want to run. Keeping both is what makes the equivalence test possible.

---

## Key data flows

**Signing:**

```
message
  → PRF_msg(SK.prf, PK.seed, msg) = R              (randomisation seed, 32 bytes)
  → H_msg(R, PK.seed, PK.root, msg) = digest       (47 bytes)
  → split: md (39 bytes) | idx_tree (u64) | idx_leaf (u64)
  → fors_sign(md) = SIG_FORS + FORS_pk             (the "few-time" part)
  → ht_sign_fast(FORS_pk, idx_tree, idx_leaf) = SIG_HT
  → output: R ‖ SIG_FORS ‖ SIG_HT                  (29 792 bytes)
```

The `R` value is one of the main reasons the scheme is effectively stateless. For the same message and secret key, signing is deterministic, but across different messages the digest drives the signer to different leaves in the hypertree.

**Verification:**

```
message + signature + PK
  → recompute digest from signature's R            (R is in the signature)
  → recover FORS_pk from SIG_FORS                  (walks K=22 auth paths)
  → ht_verify(FORS_pk, SIG_HT, idx_tree, idx_leaf, PK.root)
  → accept iff final root matches PK.root
```

Verification is much simpler than signing because it only walks the authentication paths that are already inside the signature. No tree gets rebuilt from scratch.

---

## Key and signature layout

```
SK = SK.seed || SK.prf || PK.seed || PK.root    (128 bytes)
PK =                      PK.seed || PK.root    ( 64 bytes)
SIG = R || SIG_FORS || SIG_HT                   (29 792 bytes)
```

`SK.seed` is used to derive lower-level secret material. `SK.prf` is used to derive the per-message randomness `R`. `PK.seed` is the public seed that feeds the tweakable hash functions, and `PK.root` is the final hypertree commitment.

In practice, most of key-generation cost is in computing `PK.root`. The other fields are just random bytes, so the fast key-generation path mainly wins by building that root more efficiently.

---

## The optimisation architecture

`xmss.rs` is the main place where two versions of the same logic are kept side by side:

- `xmss_node` — recursive. Computes any subtree by recursively computing its children. Clean, reads like the spec, but recomputes many nodes when building authentication paths (the same subtree gets rebuilt multiple times across different leaf indices).
- `xmss_node_fast` — iterative bottom-up. Builds the whole tree in one pass, computes each node exactly once, and stores intermediate layers explicitly. Roughly 15% faster sequentially.

Both should produce exactly the same root for the same input. That equivalence check is the main reason the fast path is believable at all.

The `parallel` feature adds Rayon parallelism to leaf generation inside `xmss_node_fast`. That works well because leaves are independent. We did not keep pushing parallelism into every stage because the extra scheduling overhead was not always worth it.

`ht.rs` mirrors the same idea: baseline signing calls the baseline XMSS path, and fast signing calls the fast XMSS path. Verification is shared.

---

## Hash abstraction

`hash.rs` defines `SphincsHasher`, and most of the rest of the code is generic over that trait. That made it possible to keep one structure while swapping between the real hasher and a simplified one for testing.

The two implementations:

- `Sha256Hasher` — the real thing. Implements the FIPS 205 SHA-2 instantiation properly: separate domain-separated constructions for `PRF`, `F`, `H`, `T_l`, `H_msg`. This is what you'd deploy.
- `RawSha256` — a stripped-down hasher that just hashes the concatenation of its inputs through a single SHA-256 call, without the domain-separation padding. Faster, not compliant, but useful in two places: benchmarks (isolates algorithmic cost from hashing overhead) and unit tests (smaller traces are easier to eyeball). Signatures produced with `RawSha256` will not verify against `Sha256Hasher` — and that's correct behaviour, since the two are genuinely different schemes.

Having two hashers started as a debugging convenience, but it ended up being useful enough to keep.

---

## What's outside the core

`src/group.rs` adds an experimental group-signature layer on top of SPHINCS+. It reuses a lot of the existing code, but it is not part of the main evaluated core and it currently has merge conflicts, so its detailed design should be treated as unstable.

---

## Things we considered and didn't do

A few alternatives came up during the project but were not pursued:

- **SHAKE-based instantiation.** This would fit the trait design, but the project already had enough scope, so SHA-2 was the more practical choice.
- **SIMD-batched WOTS+.** It could be faster, but it would also add a lot of complexity and platform-specific work.
- **Memoised recursion instead of iterative XMSS.** We considered it, but the iterative version ended up being the cleaner and faster result.










