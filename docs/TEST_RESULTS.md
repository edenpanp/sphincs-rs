# Test Results

**Machine:** MacBook Pro, Apple M2 Max, macOS 26.4.1, rustc 1.94.1 (Homebrew)  
**Where run:** locally on the development machine  
**Last full test run:** recorded during the project validation phase

---

## Build note

The previous merge-conflict markers in `src/group.rs`, `src/xmss.rs`, and
`benches/sphincs_bench.rs` have been cleaned up. The results below are recorded
project-validation results; re-run the commands before final submission if any
code changes are made.

```bash
cargo check
cargo test --lib
cargo test
cargo test --features test-utils --test integration
cargo test --test kat
```

| Command | Result |
|---------|--------|
| `cargo check --features test-utils` | PASS in the recorded lightweight check |
| `cargo test --features test-utils --lib` | 54 library tests discovered; PASS in the recorded clean run |
| `cargo test` | PASS in the recorded clean run |
| `cargo test --features test-utils --test integration` | PASS — 10/10 |
| `cargo test --test kat` | PASS — parser tests always run; file-based tests run if the KAT file is in place |

The repository currently contains 75 `#[test]` markers across `src/` and
`tests/`. Of these, 69 are exercised by the normal Cargo commands listed above:
54 library tests, 10 integration tests, and 5 KAT-related tests. The remaining
6 are in `src/group_impl_helpers.rs`, which is not currently included by
`src/lib.rs`.

---

## Unit tests

Most source files include inline `#[test]` blocks. Roughly, they cover:

- `hash.rs` — output sizes, basic invocations, that `Sha256Hasher` and `RawSha256` produce different digests for the same input (sanity check that they're actually different schemes)
- `adrs.rs` — field setters, byte layout, round-trip through setter → getter
- `wots.rs` — sign/recover round-trips, public-key gen matches recovered pk from a valid signature
- `fors.rs` — node computation, pk recovery from sig, bit-decomposition of the message digest into FORS tree indices
- `xmss.rs` — **baseline root == fast root for the same inputs**; sign/verify round-trip; auth path correctness
- `ht.rs` — hypertree signing and verification, both baseline and fast paths agree on output
- `sphincs.rs` — full round-trips, serialisation / deserialisation, tamper rejection at the top level
- `digest.rs` — split boundaries (md is exactly 39 bytes, idx_tree and idx_leaf have the right bit widths)

The XMSS equivalence check is probably the most important test in the suite. If there is some indexing mistake in the iterative version, that test usually fails right away because the fast root stops matching the baseline one.

---

## Integration tests

All 10 integration tests passed in the recorded clean run. [`tests/integration.rs`](../tests/integration.rs) uses the public API rather than internal helpers, so this is probably the closest thing to "how a normal user would hit the library".

| Test | What it checks | Result |
|------|----------------|--------|
| `integration_raw_sha256` | sign/verify, wrong-msg rejection, serialise/deserialise, raw API, deterministic R, cross-key rejection — all with `RawSha256` | PASS |
| `integration_sha256_hasher` | same six checks with `Sha256Hasher` | PASS |
| `integration_cross_hasher_rejects` | `RawSha256` sig must not verify under `Sha256Hasher` with the same pk material | PASS |
| `integration_empty_message` | sign and verify `b""` | PASS |
| `integration_long_message` | sign and verify a 65 536-byte input | PASS |
| `integration_bit_flip_rejection` | single-bit flips at 8 positions across the signature all cause verification failure | PASS |
| `integration_multiple_keypairs` | 3 keypairs; each sig validates under its own key and fails under the other two | PASS |
| `sig_bytes_constant_correct` | `SIG_BYTES` == `N + K*(1+A)*N + D*(WOTS_LEN+HP)*N` == 29 792 | PASS |
| `group_root_helper_matches_keygen` | `compute_group_root` reproduces the root from `group_keygen` | PASS |
| `group_search_r_hits_target` | `search_r` lands on the expected leaf index for member 3 | PASS |

A few of these are worth calling out:

- `integration_cross_hasher_rejects` checks that signatures from one hasher do not accidentally verify under the other
- `integration_bit_flip_rejection` samples tampering in different parts of the signature and confirms verification fails
- `sig_bytes_constant_correct` independently recomputes the expected signature size from the parameters
- `integration_multiple_keypairs` checks that signatures only verify under the correct public key

The separate baseline-vs-alpha integration and timing comparison is documented in [ALPHA_COMPARISON_REPORT.md](./ALPHA_COMPARISON_REPORT.md).

---

## KAT / real data

A NIST `.rsp` file is included in the repo at `tests/PQCsignKAT_128.rsp`. It contains 100 records produced by the SPHINCS+-SHA2-256s-simple reference implementation, so it is useful because it gives us something external to check against instead of only checking against our own output.

Each record has the standard NIST PQC format:
- `count` — record index (0 through 99)
- `seed` — 48-byte seed used to derive the keypair
- `mlen` — message length
- `msg` — the message bytes (as hex)
- `pk` — 64-byte public key (PK.seed ‖ PK.root)
- `sk` — 128-byte secret key (SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root)
- `smlen` — signed-message length
- `sm` — signature concatenated with message, so the detached signature is `sm[0..smlen-mlen]`

The parser tests in `tests/kat.rs` do not depend on the file being in that exact location, so they pass on their own:

| Test | Result |
|------|--------|
| `parse_rsp_basic` | PASS |
| `decode_sk_fields` | PASS |
| `sm_split_correct` | PASS |

The file-dependent tests run once the test runner can find the file at `tests/kat/sphincs-sha2-256s-simple.rsp`, while the repository currently stores it at `tests/PQCsignKAT_128.rsp`. The one-time fix is:

```bash
mkdir -p tests/kat
cp tests/PQCsignKAT_128.rsp tests/kat/sphincs-sha2-256s-simple.rsp
```

After that:

- `kat_verify_all_signatures` checks that all 100 reference signatures verify correctly
- `kat_sign_matches_reference` checks whether signing reproduces the reference bytes exactly

So this is mostly a file-placement issue, not some deeper parser problem.
