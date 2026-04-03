# Testing Guide for sphincs-rs

## Quick start

```bash
# Run all unit tests (fast, uses RawSha256)
cargo test

# Run unit tests + integration tests (slower, includes Sha256Hasher full round-trip)
cargo test --features test-utils

# Run only integration tests
cargo test --test integration --features test-utils

# Run KAT tests (requires NIST KAT file, see below)
cargo test --test kat --features test-utils

# Run benchmarks
cargo bench --features test-utils
```

## Test categories

### Unit tests (`cargo test`)

Every module has inline `#[cfg(test)]` tests:

| Module       | What is tested                                          |
|--------------|---------------------------------------------------------|
| `params`     | Compile-time constant assertions                        |
| `adrs`       | Field extraction, `compress_adrs` positions            |
| `hash`       | MGF1, HMAC-SHA-256 (RFC 4231 vectors), PRF determinism |
| `wots`       | Sign/verify round-trip, wrong-message rejection         |
| `xmss`       | Root consistency, wrong-message rejection               |
| `fors`       | Decode indices, tree root, sign/verify round-trip       |
| `ht`         | Sign/verify round-trip, wrong-message/key rejection     |
| `sphincs`    | Full keygen/sign/verify, serialisation, bit-flip        |

### Integration tests (`cargo test --test integration --features test-utils`)

Full end-to-end tests across the complete pipeline:

- `RawSha256` and `Sha256Hasher` each pass their own round-trips
- Cross-hasher signatures correctly rejected
- Empty and 64 KiB messages handled correctly
- 8 bit-flip positions all detected
- Multiple independent keypairs non-interfering
- `SIG_BYTES == 29792` verified against the formula

### KAT tests (requires NIST file)

1. Download the SPHINCS+ reference implementation:
   <https://sphincs.org/software.html>

2. Locate the KAT response file:
   ```
   KAT/sphincs-sha2-256s-simple/PQCsignKAT_sphincs-sha2-256s-simple.rsp
   ```

3. Place it at:
   ```
   tests/kat/sphincs-sha2-256s-simple.rsp
   ```

4. Run:
   ```bash
   cargo test --test kat --features test-utils
   ```

The KAT tests check:
- `kat_verify_all_signatures` – our verifier accepts the reference signatures
- `kat_sign_matches_reference` – our signer reproduces the exact reference bytes

If `kat_sign_matches_reference` fails but `kat_verify_all_signatures` passes,
the hash functions are correct but the ADRS compression or padding is off.

## Benchmarks

```bash
# Run all benchmarks and generate HTML report
cargo bench --features test-utils

# Save a baseline, then compare after changes
cargo bench --features test-utils -- --save-baseline before_opt
# ... make changes ...
cargo bench --features test-utils -- --baseline before_opt
```

Benchmark groups:

| Group         | Description                                          |
|---------------|------------------------------------------------------|
| `keygen`      | Full keygen (builds HP-height XMSS tree × D layers) |
| `sign`        | Sign a 64-byte message                               |
| `verify`      | Verify a signature                                   |
| `wots_keygen` | Isolated WOTS+ PK generation (WOTS_LEN chain steps) |
| `xmss_root`   | Compute one XMSS tree root (recursive, 2^HP leaves)  |
| `fors_sign`   | FORS sign (K trees × A-height each)                  |

Each group runs both `raw_sha256` and `sha256_hasher` variants for comparison.

## Interpreting results

| Result           | Likely cause                                    |
|------------------|-------------------------------------------------|
| unit tests pass  | Structural logic correct                        |
| integration pass | Both hashers self-consistent end-to-end         |
| KAT verify pass  | Hash functions produce compatible output        |
| KAT sign pass    | Full byte-exact NIST compliance achieved ✓      |
