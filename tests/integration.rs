//! integration tests for sphincs-rs
//!
//! these tests require the `test-utils` feature to access `RawSha256`
//!
//! run with:
//!   cargo test --features test-utils --test integration

// gate the entire file so `cargo test` (without features) skips it cleanly
#![cfg(feature = "test-utils")]

use sphincs_rs::hash::{RawSha256, Sha256Hasher};
use sphincs_rs::params::N;
use sphincs_rs::sphincs::{
    SIG_BYTES, deserialise_sig, serialise_sig,
    slh_keygen, slh_keygen_fast, slh_sign, slh_sign_fast,
    slh_sign_raw, slh_sign_raw_fast, slh_verify, slh_verify_raw,
};

// ── Helper macro ──────────────────────────────────────────────────────────────

macro_rules! test_with_hasher {
    ($H:ty, $name:literal) => {{
        let tag = $name;
        let (sk, pk) = slh_keygen_fast::<$H>();
        let msg = b"UNSW 26T1 Applied Cryptography integration test";

        // 1. sign + verify
        let sig = slh_sign_fast::<$H>(msg, &sk);
        assert!(slh_verify::<$H>(msg, &sig, &pk), "[{tag}] valid sig rejected");

        // 2. wrong message
        assert!(!slh_verify::<$H>(b"wrong", &sig, &pk), "[{tag}] wrong msg accepted");

        // 3. serialise → deserialise → verify
        let raw = serialise_sig(&sig);
        assert_eq!(raw.len(), SIG_BYTES, "[{tag}] wrong length: {}", raw.len());
        let sig2 = deserialise_sig(&raw).unwrap();
        assert!(slh_verify::<$H>(msg, &sig2, &pk), "[{tag}] deserialised sig rejected");

        // 4. raw API
        let raw_sig = slh_sign_raw_fast::<$H>(msg, &sk);
        assert!(slh_verify_raw::<$H>(msg, &raw_sig, &pk), "[{tag}] raw verify failed");

        // 5. determinism: same msg → same R
        let sig_b = slh_sign_fast::<$H>(msg, &sk);
        assert_eq!(sig.r, sig_b.r, "[{tag}] R is not deterministic");

        // 6. cross-key rejection
        let (_, pk2) = slh_keygen_fast::<$H>();
        assert!(!slh_verify::<$H>(msg, &sig, &pk2), "[{tag}] wrong pk accepted");
    }};
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[test]
fn integration_raw_sha256() {
    test_with_hasher!(RawSha256, "RawSha256");
}

#[test]
fn integration_sha256_hasher() {
    test_with_hasher!(Sha256Hasher, "Sha256Hasher");
}

#[test]
fn integration_cross_hasher_rejects() {
    let msg = b"cross-hasher forgery attempt";
    let (sk_raw, pk_raw) = slh_keygen_fast::<RawSha256>();
    let raw_sig = slh_sign_raw_fast::<RawSha256>(msg, &sk_raw);
    // Use the same pk_seed/pk_root but verify with the *other* hasher.
    let pk_sha = sphincs_rs::sphincs::SphincsPK {
        pk_seed: pk_raw.pk_seed,
        pk_root: pk_raw.pk_root,
    };
    assert!(!slh_verify_raw::<Sha256Hasher>(msg, &raw_sig, &pk_sha));
}

#[test]
fn integration_empty_message() {
    let (sk, pk) = slh_keygen_fast::<RawSha256>();
    let sig = slh_sign_fast::<RawSha256>(b"", &sk);
    assert!(slh_verify::<RawSha256>(b"", &sig, &pk));
}

#[test]
fn integration_long_message() {
    let (sk, pk) = slh_keygen_fast::<RawSha256>();
    let msg = vec![0x42u8; 65536];
    let sig = slh_sign_fast::<RawSha256>(&msg, &sk);
    assert!(slh_verify::<RawSha256>(&msg, &sig, &pk));
}

#[test]
fn integration_bit_flip_rejection() {
    let (sk, pk) = slh_keygen_fast::<RawSha256>();
    let msg = b"bit-flip rejection test";
    let raw = slh_sign_raw_fast::<RawSha256>(msg, &sk);

    let positions = [0, N, N + 100, N + 1000, SIG_BYTES / 2,
                     SIG_BYTES - 200, SIG_BYTES - 32, SIG_BYTES - 1];
    for &pos in &positions {
        let mut tampered = raw.clone();
        tampered[pos] ^= 0xFF;
        assert!(!slh_verify_raw::<RawSha256>(msg, &tampered, &pk),
            "bit-flip at pos {pos} not detected");
    }
}

#[test]
fn integration_multiple_keypairs() {
    let msg = b"multi-keypair test";
    let pairs: Vec<_> = (0..3).map(|_| slh_keygen_fast::<RawSha256>()).collect();
    let sigs: Vec<_> = pairs.iter()
        .map(|(sk, _)| slh_sign_fast::<RawSha256>(msg, sk))
        .collect();
    for (i, ((_, pki), sigi)) in pairs.iter().zip(sigs.iter()).enumerate() {
        assert!(slh_verify::<RawSha256>(msg, sigi, pki), "keypair {i}: own sig failed");
        for (j, (_, pkj)) in pairs.iter().enumerate() {
            if i != j {
                assert!(!slh_verify::<RawSha256>(msg, sigi, pkj),
                    "sig {i} accepted under pk {j}");
            }
        }
    }
}

#[test]
fn sig_bytes_constant_correct() {
    use sphincs_rs::params::{A, D, HP, K, WOTS_LEN};
    let expected = N + K * (1 + A) * N + D * (WOTS_LEN + HP) * N;
    assert_eq!(SIG_BYTES, expected);
    assert_eq!(SIG_BYTES, 29792);
}
