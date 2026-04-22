# Alpha Comparison Report

This report is based on the integration test file and the command:

```bash
cargo test --test integration -- --nocapture --test-threads=1
```

The goal was to check that the alpha changes had not broken signing and verification, and then compare signature size and runtime after the parameter change. The tests covered the normal success case, a few obvious failure cases, size checks, repeated runs, and one small benchmark. That was enough for this stage.

---

## Test Cases

| Test | Purpose |
|------|---------|
| `test_sign_and_verify_ok` | Generate a key pair, sign a message, then verify it with the matching public key. |
| `test_verify_fail_when_message_is_modified` | Sign the original message, then change the message before verification. Verification should fail. |
| `test_verify_fail_when_signature_is_modified` | Sign normally, flip one byte in the signature, and verify again. Verification should fail. |
| `test_verify_fail_with_wrong_public_key` | Sign with one key pair and verify with a different public key. Verification should fail. |
| `test_key_and_signature_sizes_are_consistent` | Check that generated secret key, public key, and signature lengths match the constants in `parameters.rs`. |
| `test_multiple_rounds_correctness` | Run signing and verification several times to make sure success is not a one-off result. |
| `benchmark_keygen_sign_verify` | Measure one full round of key generation, signing, and verification. |

All eight tests passed in both versions. Valid signatures verified correctly, while modified messages, modified signatures, and wrong public keys were rejected.

---

## Baseline Implementation

The baseline program is split across several Rust files, with each file handling one part of the signature scheme. `main.rs` runs a simple end-to-end test by creating a sample message, generating a key pair, signing the message, and checking whether the signature verifies. The heavier cryptographic work is spread across `wots.rs`, `xmss.rs`, `fors.rs`, `hypertree.rs`, `sphincs.rs`, `adrs.rs`, and `parameters.rs`.

At a high level, the flow is simple even though the internals are not. The message is hashed first, FORS signs the digest, and then the hypertree signs the recovered FORS public key. Verification rebuilds that path and checks whether the final root matches the public root.

For the baseline version, we kept the official SPHINCS+-256s style parameters instead of changing everything at once. That was mainly practical: the standard WOTS+ setup gives a direct base-w conversion with a checksum, so the chain lengths are easier to reason about and debug.

The main baseline settings were:

- `N = 32`, so each hash output is 32 bytes
- `w = 16` for WOTS+
- hypertree height `h = 64`
- hypertree layers `d = 8`
- FORS trees `k = 22`
- FORS tree height `a = 14`
- `debug_mode = true` by default

The code was kept modular so failures could be isolated to WOTS+, XMSS, FORS, or the hypertree layer. Keys and signatures are packed and unpacked explicitly with slices and vectors. This is plain, but it makes byte layout, sizes, and offsets easier to check.

---

## Alpha Version

The alpha version keeps the same outer signing flow, but the implementation changes are more than parameter edits. Once the code moved closer to the SPHINCS-alpha design, several internal pieces changed structurally.

The baseline code uses the familiar SPHINCS+ setting with `w = 16`, `h = 64`, `d = 8`, `k = 22`, and `a = 14`. The alpha version moves to the SPHINCS-alpha 256s setting:

- `w = 79`
- `h = 66`
- `d = 11`
- `k = 23`
- `a = 13`

Those constants have knock-on effects. Once the WOTS setting changes, XMSS subtree size, FORS signature size, hypertree signature size, and total signature length all have to remain consistent.

### Chain-Length Computation

The chain-length computation is where the alpha version stops being a small edit. In the baseline code, WOTS chain lengths come from base-w conversion plus checksum. In the alpha code, that is replaced by constant-sum decoding for CS-WOTS+, so the program is no longer just reading digits out of the digest and extending them with a checksum.

The decoding loop has to keep the remaining length and remaining sum consistent at the same time, while avoiding values outside the valid range for each digit. The implementation was kept direct, even though it is longer, because a compact version was harder to check during debugging.

There is also an explicit failure path if decoding cannot produce a valid chain-length vector. That is useful because silently producing wrong chain values would only show up later as a verification failure.

### Address Handling

The alpha version adds two extra address types: `wots_prf` and `fors_prf`. These separate secret-value generation from normal hash and tree operations.

This affects both WOTS+ and FORS. In the baseline code, the ordinary address context was enough for deriving chain starts and FORS leaf secrets. In the alpha code, those values are generated under dedicated PRF address types. That improves domain separation and makes each address type's role clearer.

### Helper Code

Some changes were not cryptographic. Additional helper functions were added because the alpha version was getting harder to read without them. In `sphincs.rs`, explicit encode/decode functions were added for keys and signatures. In `hypertree.rs`, flattening and unflattening helpers were added for XMSS signatures. These reduce repeated slicing code and make the data flow easier to follow.

The outer workflow remains the same: generate `R`, hash the message into `md` and tree indices, sign `md` with FORS, rebuild the FORS public key, and sign that result with the hypertree.

---

## Parameter Comparison

| Item | Baseline | Alpha |
|------|----------|-------|
| WOTS chains | 67 | 42 |
| `w` | 16 | 79 |
| FORS trees | 22 | 23 |
| FORS height | 14 | 13 |
| Hypertree height | 64 | 66 |
| Hypertree layers | 8 | 11 |
| Total signature length | 29,792 bytes | 27,232 bytes |

The alpha signature is smaller by 2,560 bytes. The tree structure also changes because the subtree height and layer count are different.

---

## Runtime Results

The correctness result was solid, but the runtime result was less intuitive. Even though the alpha version signs with fewer WOTS chains and produces a smaller signature, it was slower in the benchmark.

| Version | Round 1 | Round 2 | Round 3 | Average | Signature size |
|---------|---------|---------|---------|---------|----------------|
| Baseline | 109.6326937 s | 109.6260658 s | 112.3090096 s | 110.5225897 s | 29,792 bytes |
| Alpha | 130.9509263 s | 131.1945539 s | 131.0337248 s | 131.0597350 s | 27,232 bytes |

| Version | Tests passed | Signature size | Average benchmark time |
|---------|--------------|----------------|------------------------|
| Baseline | 8 / 8 | 29,792 bytes | 110.52 s |
| Alpha | 8 / 8 | 27,232 bytes | 131.06 s |

So in this implementation, shorter signatures did not translate into faster runs. The extra time appears to come from the alpha-side preprocessing rather than an obvious sign/verify failure loop. The baseline path is shorter: base-w conversion, checksum, then chain lengths. The alpha path does more work before the chains are evaluated.

These runs only show what happened in this Rust implementation, under this parameter set, with this test setup. The safe conclusion is that the alpha version reduced signature size, but the current code paid for it in runtime.

The correctness side held up. That matters because the alpha changes were not just parameter edits: they also changed chain-length derivation and separated some internal address handling. Those are exactly the kinds of changes that can quietly break sign/verify agreement if a small detail is wrong.
