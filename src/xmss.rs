//! XMSS tree implementation (baseline vs fast version)
//!
//! two ways to sign:
//!
//! baseline:
//! - use recursive xmss_node
//! - recompute subtree every time (kind of wasteful but simple)
//!
//! fast version:
//! - build full tree once (bottom-up)
//! - then just read auth path
//!
//! fast version avoids duplicate work and is much faster in practice
//! especially when HP is not tiny

use crate::adrs::{Adrs, AdrsType};
use crate::hash::SphincsHasher;
use crate::params::{HP, N};
use crate::wots::{self, WotsSig};

/// auth path: one sibling per level
pub type XmssAuth = [[u8; N]; HP];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XmssSig {
    pub sig_wots: WotsSig,
    pub auth: XmssAuth,
}

// ── leaf helper ───────────────────────────────────────

pub(crate) fn compute_leaf<S: SphincsHasher>(
    sk_seed: &[u8; N],
    pk_seed: &[u8; N],
    i: usize,
    adrs: &Adrs,
) -> [u8; N] {
    // convert address to WOTS mode
    let mut leaf_adrs = *adrs;
    leaf_adrs.set_type_and_clear(AdrsType::Wots);
    leaf_adrs.set_keypair_address(i as u32);

    // leaf = WOTS public key
    wots::wots_pk_gen::<S>(sk_seed, pk_seed, &leaf_adrs)
}

// ── baseline (recursive) ──────────────────────────────

pub fn xmss_node<S: SphincsHasher>(
    sk_seed: &[u8; N],
    i: usize,
    z: usize,
    pk_seed: &[u8; N],
    adrs: Adrs,
) -> [u8; N] {
    if z == 0 {
        return compute_leaf::<S>(sk_seed, pk_seed, i, &adrs);
    }
<<<<<<< HEAD

    // recursively compute children
    let left  = xmss_node::<S>(sk_seed, 2 * i,     z - 1, pk_seed, adrs);
=======
    let left = xmss_node::<S>(sk_seed, 2 * i, z - 1, pk_seed, adrs);
>>>>>>> b64f0cd10f94721a99763f528a27c831730cfe6b
    let right = xmss_node::<S>(sk_seed, 2 * i + 1, z - 1, pk_seed, adrs);

    let mut node_adrs = adrs;
    node_adrs.set_type_and_clear(AdrsType::TreeNode);
    node_adrs.set_tree_height(z as u32);
    node_adrs.set_tree_index(i as u32);

    S::h_two(pk_seed, &node_adrs, &left, &right)
}

pub fn xmss_sign<S: SphincsHasher>(
    msg: &[u8; N],
    sk_seed: &[u8; N],
    idx: usize,
    pk_seed: &[u8; N],
    adrs: Adrs,
) -> XmssSig {
    let mut auth = [[0u8; N]; HP];

    // compute auth path one level at a time
    for j in 0..HP {
        let sibling = (idx >> j) ^ 1;
        auth[j] = xmss_node::<S>(sk_seed, sibling, j, pk_seed, adrs);
    }

    let mut wots_adrs = adrs;
    wots_adrs.set_type_and_clear(AdrsType::Wots);
    wots_adrs.set_keypair_address(idx as u32);

    let sig_wots = wots::wots_sign::<S>(msg, sk_seed, pk_seed, &wots_adrs);

    XmssSig { sig_wots, auth }
}

// ── fast version (build tree once) ────────────────────
// trade-off: uses more memory but avoids recomputation

fn build_tree<S: SphincsHasher>(
    sk_seed: &[u8; N],
    pk_seed: &[u8; N],
    adrs: Adrs,
) -> Vec<Vec<[u8; N]>> {
    let num_leaves = 1 << HP;

    // level 0: leaves
    #[cfg(feature = "parallel")]
    let leaves: Vec<[u8; N]> = {
        use rayon::prelude::*;
        (0..num_leaves)
            .into_par_iter()
            .map(|i| compute_leaf::<S>(sk_seed, pk_seed, i, &adrs))
            .collect()
    };

    #[cfg(not(feature = "parallel"))]
    let leaves: Vec<[u8; N]> = (0..num_leaves)
        .map(|i| compute_leaf::<S>(sk_seed, pk_seed, i, &adrs))
        .collect();

    let mut tree = Vec::with_capacity(HP + 1);
    tree.push(leaves);

    // build upper layers
    for z in 1..=HP {
        let prev = &tree[z - 1];
<<<<<<< HEAD
        let mut layer = Vec::with_capacity(prev.len() / 2);
=======
        let width = prev.len() / 2;
        let mut layer = Vec::with_capacity(width);
>>>>>>> b64f0cd10f94721a99763f528a27c831730cfe6b

        for i in 0..(prev.len() / 2) {
            let mut node_adrs = adrs;
            node_adrs.set_type_and_clear(AdrsType::TreeNode);
            node_adrs.set_tree_height(z as u32);
            node_adrs.set_tree_index(i as u32);
<<<<<<< HEAD

=======
>>>>>>> b64f0cd10f94721a99763f528a27c831730cfe6b
            layer.push(S::h_two(
                pk_seed,
                &node_adrs,
                &prev[2 * i],
                &prev[2 * i + 1],
            ));
        }

        tree.push(layer);
    }

    tree
}

pub fn xmss_node_fast<S: SphincsHasher>(
    sk_seed: &[u8; N],
    i: usize,
    z: usize,
    pk_seed: &[u8; N],
    adrs: Adrs,
) -> [u8; N] {
    if i == 0 && z == HP {
        // common case: just want root
        let tree = build_tree::<S>(sk_seed, pk_seed, adrs);
        tree[HP][0]
    } else if z == 0 {
        compute_leaf::<S>(sk_seed, pk_seed, i, &adrs)
    } else {
        // fallback (rare)
        xmss_node::<S>(sk_seed, i, z, pk_seed, adrs)
    }
}

pub fn xmss_sign_fast<S: SphincsHasher>(
    msg: &[u8; N],
    sk_seed: &[u8; N],
    idx: usize,
    pk_seed: &[u8; N],
    adrs: Adrs,
) -> XmssSig {
    let tree = build_tree::<S>(sk_seed, pk_seed, adrs);

    let mut auth = [[0u8; N]; HP];

    // read auth path directly
    for j in 0..HP {
        let sibling = (idx >> j) ^ 1;
        auth[j] = tree[j][sibling];
    }

    let mut wots_adrs = adrs;
    wots_adrs.set_type_and_clear(AdrsType::Wots);
    wots_adrs.set_keypair_address(idx as u32);

    let sig_wots = wots::wots_sign::<S>(msg, sk_seed, pk_seed, &wots_adrs);

    XmssSig { sig_wots, auth }
}

// ── verify (shared) ───────────────────────────────────

pub fn xmss_pk_from_sig<S: SphincsHasher>(
    idx: usize,
    sig: &XmssSig,
    msg: &[u8; N],
    pk_seed: &[u8; N],
    adrs: Adrs,
) -> [u8; N] {
    let mut wots_adrs = adrs;
    wots_adrs.set_type_and_clear(AdrsType::Wots);
    wots_adrs.set_keypair_address(idx as u32);

    let mut node =
        wots::wots_pk_from_sig::<S>(&sig.sig_wots, msg, pk_seed, &wots_adrs);

    let mut node_adrs = adrs;
    node_adrs.set_type_and_clear(AdrsType::TreeNode);
    node_adrs.set_tree_index(idx as u32);

    for j in 0..HP {
        node_adrs.set_tree_height((j + 1) as u32);

        if (idx >> j) & 1 == 0 {
            node = S::h_two(pk_seed, &node_adrs, &node, &sig.auth[j]);
        } else {
            node = S::h_two(pk_seed, &node_adrs, &sig.auth[j], &node);
        }
    }

    node
<<<<<<< HEAD
}
=======
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::RawSha256;
    use rand::{RngCore, rngs::OsRng};

    fn rng_n() -> [u8; N] {
        let mut b = [0u8; N];
        OsRng.fill_bytes(&mut b);
        b
    }

    /// Baseline and fast strategies must produce the same root.
    #[test]
    fn xmss_fast_root_matches_baseline() {
        let (sk, pk, msg) = (rng_n(), rng_n(), rng_n());
        let adrs = Adrs::new(AdrsType::TreeNode);

        let root_baseline = xmss_node::<RawSha256>(&sk, 0, HP, &pk, adrs);
        let root_fast = xmss_node_fast::<RawSha256>(&sk, 0, HP, &pk, adrs);
        assert_eq!(root_baseline, root_fast, "roots must agree");
    }

    /// Fast sign + shared verify must succeed for multiple leaves.
    #[test]
    fn xmss_fast_sign_verify_roundtrip() {
        let (sk, pk, msg) = (rng_n(), rng_n(), rng_n());
        let adrs = Adrs::new(AdrsType::TreeNode);
        let root = xmss_node_fast::<RawSha256>(&sk, 0, HP, &pk, adrs);

        for idx in [0, 1, (1 << HP) - 2, (1 << HP) - 1] {
            let sig = xmss_sign_fast::<RawSha256>(&msg, &sk, idx, &pk, adrs);
            let recovered = xmss_pk_from_sig::<RawSha256>(idx, &sig, &msg, &pk, adrs);
            assert_eq!(root, recovered, "fast sign failed for idx={idx}");
        }
    }

    /// Baseline and fast sign must produce the same authentication paths.
    #[test]
    fn xmss_fast_and_baseline_auth_paths_equal() {
        let (sk, pk, msg) = (rng_n(), rng_n(), rng_n());
        let adrs = Adrs::new(AdrsType::TreeNode);
        let idx = 7usize;

        let sig_base = xmss_sign::<RawSha256>(&msg, &sk, idx, &pk, adrs);
        let sig_fast = xmss_sign_fast::<RawSha256>(&msg, &sk, idx, &pk, adrs);
        assert_eq!(sig_base.auth, sig_fast.auth, "auth paths must agree");
        assert_eq!(
            sig_base.sig_wots, sig_fast.sig_wots,
            "WOTS+ sigs must agree"
        );
    }

    /// Baseline round-trip (kept for regression).
    #[test]
    fn xmss_baseline_roundtrip() {
        let (sk, pk, msg) = (rng_n(), rng_n(), rng_n());
        let adrs = Adrs::new(AdrsType::TreeNode);
        let root = xmss_node::<RawSha256>(&sk, 0, HP, &pk, adrs);

        for idx in [0, 3, (1 << HP) - 1] {
            let sig = xmss_sign::<RawSha256>(&msg, &sk, idx, &pk, adrs);
            let recovered = xmss_pk_from_sig::<RawSha256>(idx, &sig, &msg, &pk, adrs);
            assert_eq!(root, recovered);
        }
    }
}
>>>>>>> b64f0cd10f94721a99763f528a27c831730cfe6b
