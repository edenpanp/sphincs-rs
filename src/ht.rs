//! HT (Hypertree) – D stacked XMSS layers.
//!
//! Provides two signing strategies mirroring `xmss`:
//!
//! | Function        | XMSS strategy used        | Leaf parallelism |
//! |-----------------|---------------------------|------------------|
//! | `ht_sign`       | recursive baseline        | no               |
//! | `ht_sign_fast`  | iterative bottom-up       | yes (with rayon) |
//!
//! Verification (`ht_verify`) is shared — it only walks the stored auth
//! path and does not recompute leaves.
//!
//! # Algorithm references (FIPS 205)
//!
//! | Alg. 12 | `ht_sign`   | [`ht_sign`] / [`ht_sign_fast`] |
//! | Alg. 13 | `ht_verify` | [`ht_verify`]                  |

use crate::adrs::{Adrs, AdrsType};
use crate::hash::SphincsHasher;
use crate::params::{D, HP, N};
use crate::xmss::{self, XmssSig};

// ── Types ─────────────────────────────────────────────────────────────────────

/// An HT signature: D XMSS signatures stacked bottom-to-top.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HtSig {
    pub xmss_sigs: Vec<XmssSig>, // length D
}

// ── Internal helpers ──────────────────────────────────────────────────────────

#[inline]
fn leaf_index_for_layer(idx_leaf: u64, layer: usize) -> usize {
    ((idx_leaf >> (layer * HP)) & ((1u64 << HP) - 1)) as usize
}

#[inline]
fn tree_index_for_layer(idx_tree: u64, layer: usize) -> u64 {
    idx_tree >> (layer * HP)
}

#[inline]
fn make_layer_adrs(layer: usize, tree_idx: u64) -> Adrs {
    let mut adrs = Adrs::new(AdrsType::TreeNode);
    adrs.set_layer_address(layer as u32);
    adrs.set_tree_address(tree_idx);
    adrs
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Sign with the **baseline** recursive XMSS strategy (FIPS 205 Alg. 12).
pub fn ht_sign<S: SphincsHasher>(
    msg: &[u8; N],
    sk_seed: &[u8; N],
    pk_seed: &[u8; N],
    idx_tree: u64,
    idx_leaf: u64,
) -> HtSig {
    let mut sigs = Vec::with_capacity(D);
    let mut current_msg = *msg;

    for j in 0..D {
        let leaf_j = leaf_index_for_layer(idx_leaf, j);
        let tree_j = tree_index_for_layer(idx_tree, j);
        let adrs   = make_layer_adrs(j, tree_j);

        let sig_j = xmss::xmss_sign::<S>(&current_msg, sk_seed, leaf_j, pk_seed, adrs);
        current_msg = xmss::xmss_pk_from_sig::<S>(leaf_j, &sig_j, &current_msg, pk_seed, adrs);
        sigs.push(sig_j);
    }
    HtSig { xmss_sigs: sigs }
}

/// Sign with the **optimised** iterative + parallel XMSS strategy (Alg. 12).
///
/// Each XMSS layer calls `xmss_sign_fast`, which builds the layer tree
/// bottom-up in a single pass and (with `--features parallel`) distributes
/// the 2^HP leaf computations across CPU cores.
pub fn ht_sign_fast<S: SphincsHasher>(
    msg: &[u8; N],
    sk_seed: &[u8; N],
    pk_seed: &[u8; N],
    idx_tree: u64,
    idx_leaf: u64,
) -> HtSig {
    let mut sigs = Vec::with_capacity(D);
    let mut current_msg = *msg;

    for j in 0..D {
        let leaf_j = leaf_index_for_layer(idx_leaf, j);
        let tree_j = tree_index_for_layer(idx_tree, j);
        let adrs   = make_layer_adrs(j, tree_j);

        // ← only this call differs from ht_sign
        let sig_j = xmss::xmss_sign_fast::<S>(&current_msg, sk_seed, leaf_j, pk_seed, adrs);
        current_msg = xmss::xmss_pk_from_sig::<S>(leaf_j, &sig_j, &current_msg, pk_seed, adrs);
        sigs.push(sig_j);
    }
    HtSig { xmss_sigs: sigs }
}

/// Verify an HT signature (FIPS 205 Alg. 13).  Shared by both strategies.
pub fn ht_verify<S: SphincsHasher>(
    msg: &[u8; N],
    sig: &HtSig,
    pk_seed: &[u8; N],
    idx_tree: u64,
    idx_leaf: u64,
    pk_root: &[u8; N],
) -> bool {
    debug_assert_eq!(sig.xmss_sigs.len(), D);
    let mut node = *msg;

    for j in 0..D {
        let leaf_j = leaf_index_for_layer(idx_leaf, j);
        let tree_j = tree_index_for_layer(idx_tree, j);
        let adrs   = make_layer_adrs(j, tree_j);
        node = xmss::xmss_pk_from_sig::<S>(leaf_j, &sig.xmss_sigs[j], &node, pk_seed, adrs);
    }
    node == *pk_root
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::RawSha256;
    use rand::{RngCore, rngs::OsRng};

    fn rng_n() -> [u8; N] {
        let mut b = [0u8; N]; OsRng.fill_bytes(&mut b); b
    }

    fn ht_pk<S: SphincsHasher>(sk: &[u8; N], pk: &[u8; N]) -> [u8; N] {
        let adrs = make_layer_adrs(D - 1, 0);
        xmss::xmss_node_fast::<S>(sk, 0, HP, pk, adrs)
    }

    /// Baseline sign → verify round-trip.
    #[test]
    fn ht_baseline_roundtrip() {
        let (sk, pk, msg) = (rng_n(), rng_n(), rng_n());
        let root = ht_pk::<RawSha256>(&sk, &pk);
        let sig  = ht_sign::<RawSha256>(&msg, &sk, &pk, 0, 0);
        assert!(ht_verify::<RawSha256>(&msg, &sig, &pk, 0, 0, &root));
    }

    /// Fast sign → verify round-trip.
    #[test]
    fn ht_fast_roundtrip() {
        let (sk, pk, msg) = (rng_n(), rng_n(), rng_n());
        let root = ht_pk::<RawSha256>(&sk, &pk);
        let sig  = ht_sign_fast::<RawSha256>(&msg, &sk, &pk, 0, 0);
        assert!(ht_verify::<RawSha256>(&msg, &sig, &pk, 0, 0, &root));
    }

    /// Baseline and fast must produce the same auth paths.
    #[test]
    fn ht_baseline_and_fast_agree() {
        let (sk, pk, msg) = (rng_n(), rng_n(), rng_n());
        let sig_base = ht_sign::<RawSha256>(&msg, &sk, &pk, 0, 2);
        let sig_fast = ht_sign_fast::<RawSha256>(&msg, &sk, &pk, 0, 2);

        for d in 0..D {
            assert_eq!(
                sig_base.xmss_sigs[d].auth, sig_fast.xmss_sigs[d].auth,
                "auth paths differ at layer {d}"
            );
        }
    }

    /// Wrong message must not verify.
    #[test]
    fn ht_wrong_message_fails() {
        let (sk, pk, msg, wrong) = (rng_n(), rng_n(), rng_n(), rng_n());
        let root = ht_pk::<RawSha256>(&sk, &pk);
        let sig  = ht_sign_fast::<RawSha256>(&msg, &sk, &pk, 0, 0);
        assert!(!ht_verify::<RawSha256>(&wrong, &sig, &pk, 0, 0, &root));
    }
}
