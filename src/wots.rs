//! WOTS+ (Winternitz One-Time Signature) implementation.
//!
//! WOTS+ is the one-time signature scheme at the leaves of every XMSS tree.
//! It is never used standalone; XMSS calls into this module.
//!
//! # Algorithm references (FIPS 205)
//!
//! | Algorithm | Name              | Function here          |
//! |-----------|-------------------|------------------------|
//! | Alg. 5    | `chain`           | [`chain`]              |
//! | Alg. 6    | `wots_PKgen`      | [`wots_pk_gen`]        |
//! | Alg. 7    | `wots_sign`       | [`wots_sign`]          |
//! | Alg. 8    | `wots_PKFromSig`  | [`wots_pk_from_sig`]   |
//!
//! Secret keys are **never stored**. A WOTS+ SK element is derived on demand
//! by calling `PRF(PK.seed, SK.seed, ADRS)`.

use crate::adrs::{Adrs, AdrsType};
use crate::hash::SphincsHasher;
use crate::params::{N, W, WOTS_LEN, WOTS_LEN1, WOTS_LEN2};

// ── Public types ──────────────────────────────────────────────────────────────

/// A WOTS+ signature: `WOTS_LEN` hash values, each `N` bytes.
pub type WotsSig = [[u8; N]; WOTS_LEN];

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Convert an `N`-byte message to `WOTS_LEN` base-W digits including checksum.
///
/// Steps (FIPS 205 §5):
/// 1. Split the `N`-byte message into `WOTS_LEN1` base-W (nibble) digits.
/// 2. Compute `checksum = Σ (W−1 − dᵢ)`.
/// 3. Encode the checksum as `WOTS_LEN2` base-W digits (big-endian, right-aligned).
/// 4. Return `[msg_digits ‖ checksum_digits]` of length `WOTS_LEN`.
fn base_w_and_checksum(msg: &[u8; N]) -> [u8; WOTS_LEN] {
    // Step 1: expand N bytes → WOTS_LEN1 nibbles (base-16 digits)
    let mut digits = [0u8; WOTS_LEN];
    for (i, &byte) in msg.iter().enumerate() {
        digits[2 * i] = (byte >> 4) & 0x0F;
        digits[2 * i + 1] = byte & 0x0F;
    }
    // Sanity: N * 2 must equal WOTS_LEN1 (32 * 2 = 64 ✓)
    debug_assert_eq!(N * 2, WOTS_LEN1);

    // Step 2: checksum over the message digits
    let checksum: u32 = digits[..WOTS_LEN1]
        .iter()
        .map(|&d| (W as u32 - 1) - d as u32)
        .sum();

    // Step 3: encode checksum into WOTS_LEN2 nibbles (right-aligned in 4-byte word)
    let checksum_bytes = checksum.to_be_bytes(); // 4 bytes
    let all_nibbles: [u8; 8] = {
        let mut n = [0u8; 8];
        for (i, &b) in checksum_bytes.iter().enumerate() {
            n[2 * i] = (b >> 4) & 0x0F;
            n[2 * i + 1] = b & 0x0F;
        }
        n
    };
    // Take the last WOTS_LEN2 nibbles (least-significant)
    let cs_start = 8 - WOTS_LEN2;
    digits[WOTS_LEN1..WOTS_LEN].copy_from_slice(&all_nibbles[cs_start..]);

    digits
}

/// WOTS+ chaining function (FIPS 205 Algorithm 5).
///
/// Applies the tweakable hash `F` to `x` for `steps` iterations, starting
/// from chain position `start`. The ADRS `hash_address` is updated at each
/// step before calling `F`.
///
/// `adrs` is taken by value because it is mutated (it is `Copy`).
fn chain<S: SphincsHasher>(
    mut x: [u8; N],
    start: usize,
    steps: usize,
    pk_seed: &[u8; N],
    mut adrs: Adrs,
) -> [u8; N] {
    for j in start..(start + steps) {
        adrs.set_hash_address(j as u32);
        x = S::f(pk_seed, &adrs, &x);
    }
    x
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Derive WOTS+ SK element `i` from the master seed pair (FIPS 205 inline §6).
///
/// `SK[i] = PRF(PK.seed, SK.seed, ADRS)` where ADRS has:
///   - type = Wots
///   - keypair_address = inherited from caller
///   - chain_address   = i
///   - hash_address    = 0
///
/// This function is called internally by [`wots_pk_gen`] and [`wots_sign`].
fn derive_sk<S: SphincsHasher>(
    sk_seed: &[u8; N],
    pk_seed: &[u8; N],
    adrs: &Adrs,
    i: usize,
) -> [u8; N] {
    let mut sk_adrs = *adrs;
    sk_adrs.set_chain_address(i as u32);
    sk_adrs.set_hash_address(0);
    S::prf(pk_seed, sk_seed, &sk_adrs)
}

/// Compute the WOTS+ public key from a secret seed (FIPS 205 Algorithm 6).
///
/// ```text
/// wots_PKgen(SK.seed, PK.seed, ADRS):
///   for i in 0..WOTS_LEN:
///     sk_i  = PRF(PK.seed, SK.seed, ADRS with chain=i, hash=0)
///     tmp_i = chain(sk_i, 0, W-1, PK.seed, ADRS with chain=i)
///   ADRS' = ADRS with type=WOTS_PK, keypair preserved
///   return T_len(PK.seed, ADRS', tmp)
/// ```
///
/// The returned value is the compressed N-byte WOTS+ public key.
pub fn wots_pk_gen<S: SphincsHasher>(sk_seed: &[u8; N], pk_seed: &[u8; N], adrs: &Adrs) -> [u8; N] {
    let mut tmp = [[0u8; N]; WOTS_LEN];

    for i in 0..WOTS_LEN {
        let sk_i = derive_sk::<S>(sk_seed, pk_seed, adrs, i);
        let mut chain_adrs = *adrs;
        chain_adrs.set_chain_address(i as u32);
        tmp[i] = chain::<S>(sk_i, 0, W - 1, pk_seed, chain_adrs);
    }

    // Compress WOTS_LEN values into a single N-byte PK
    let mut pk_adrs = *adrs;
    pk_adrs.set_type_and_clear(AdrsType::WotsPk);
    pk_adrs.set_keypair_address(adrs.get_keypair_address());

    S::t_l(pk_seed, &pk_adrs, &tmp)
}

/// Sign an `N`-byte message with WOTS+ (FIPS 205 Algorithm 7).
///
/// ```text
/// wots_sign(M, SK.seed, PK.seed, ADRS):
///   msg_digits = base_w_and_checksum(M)
///   for i in 0..WOTS_LEN:
///     sk_i   = PRF(PK.seed, SK.seed, ADRS with chain=i, hash=0)
///     sig[i] = chain(sk_i, 0, msg_digits[i], PK.seed, ADRS with chain=i)
///   return sig
/// ```
pub fn wots_sign<S: SphincsHasher>(
    msg: &[u8; N],
    sk_seed: &[u8; N],
    pk_seed: &[u8; N],
    adrs: &Adrs,
) -> WotsSig {
    let digits = base_w_and_checksum(msg);
    let mut sig = [[0u8; N]; WOTS_LEN];

    for i in 0..WOTS_LEN {
        let sk_i = derive_sk::<S>(sk_seed, pk_seed, adrs, i);
        let mut chain_adrs = *adrs;
        chain_adrs.set_chain_address(i as u32);
        sig[i] = chain::<S>(sk_i, 0, digits[i] as usize, pk_seed, chain_adrs);
    }

    sig
}

/// Compute the expected WOTS+ public key from a signature (FIPS 205 Algorithm 8).
///
/// Verification succeeds when the returned value equals the stored WOTS+ PK.
///
/// ```text
/// wots_PKFromSig(sig, M, PK.seed, ADRS):
///   msg_digits = base_w_and_checksum(M)
///   for i in 0..WOTS_LEN:
///     tmp[i] = chain(sig[i], digits[i], W-1-digits[i], PK.seed, ADRS with chain=i)
///   ADRS' = ADRS with type=WOTS_PK, keypair preserved
///   return T_len(PK.seed, ADRS', tmp)
/// ```
pub fn wots_pk_from_sig<S: SphincsHasher>(
    sig: &WotsSig,
    msg: &[u8; N],
    pk_seed: &[u8; N],
    adrs: &Adrs,
) -> [u8; N] {
    let digits = base_w_and_checksum(msg);
    let mut tmp = [[0u8; N]; WOTS_LEN];

    for i in 0..WOTS_LEN {
        let mut chain_adrs = *adrs;
        chain_adrs.set_chain_address(i as u32);
        let start = digits[i] as usize;
        let steps = W - 1 - start;
        tmp[i] = chain::<S>(sig[i], start, steps, pk_seed, chain_adrs);
    }

    let mut pk_adrs = *adrs;
    pk_adrs.set_type_and_clear(AdrsType::WotsPk);
    pk_adrs.set_keypair_address(adrs.get_keypair_address());

    S::t_l(pk_seed, &pk_adrs, &tmp)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::RawSha256;
    use rand::{RngCore, rngs::OsRng};

    /// End-to-end WOTS+ round-trip: sign then verify.
    #[test]
    fn wots_sign_verify_roundtrip() {
        let mut sk_seed = [0u8; N];
        let mut pk_seed = [0u8; N];
        let mut msg = [0u8; N];
        OsRng.fill_bytes(&mut sk_seed);
        OsRng.fill_bytes(&mut pk_seed);
        OsRng.fill_bytes(&mut msg);

        let mut adrs = Adrs::new(AdrsType::Wots);
        adrs.set_layer_address(0);
        adrs.set_tree_address(0);
        adrs.set_keypair_address(0);

        // Generate public key
        let pk = wots_pk_gen::<RawSha256>(&sk_seed, &pk_seed, &adrs);

        // Sign
        let sig = wots_sign::<RawSha256>(&msg, &sk_seed, &pk_seed, &adrs);

        // Recover PK from signature and compare
        let pk_recovered = wots_pk_from_sig::<RawSha256>(&sig, &msg, &pk_seed, &adrs);

        assert_eq!(pk, pk_recovered, "WOTS+ PK recovery failed");
    }

    /// Wrong message must not verify.
    #[test]
    fn wots_wrong_message_fails() {
        let mut sk_seed = [0u8; N];
        let mut pk_seed = [0u8; N];
        let mut msg = [0u8; N];
        let mut wrong = [0u8; N];
        OsRng.fill_bytes(&mut sk_seed);
        OsRng.fill_bytes(&mut pk_seed);
        OsRng.fill_bytes(&mut msg);
        OsRng.fill_bytes(&mut wrong);

        let adrs = Adrs::new(AdrsType::Wots);

        let pk = wots_pk_gen::<RawSha256>(&sk_seed, &pk_seed, &adrs);
        let sig = wots_sign::<RawSha256>(&msg, &sk_seed, &pk_seed, &adrs);
        let pk_wrong = wots_pk_from_sig::<RawSha256>(&sig, &wrong, &pk_seed, &adrs);

        // With overwhelming probability, a wrong message gives a wrong PK
        assert_ne!(pk, pk_wrong, "WOTS+ accepted a wrong message");
    }
}
