//! XMSS (eXtended Merkle Signature Scheme) tree implementation.
//!
//! # Two signing strategies
//!
//! ## Baseline: `xmss_sign` (recursive, FIPS 205 Alg. 10)
//!
//! Computes each of the HP authentication-path siblings independently by
//! calling the recursive `xmss_node`.  At height j the sibling subtree
//! covers 2^j leaves, so total leaf computations = Σ 2^j for j=0..HP−1
//! = 2^HP − 1 = 255 leaf evaluations (for HP=8).
//!
//! ## Optimised: `xmss_sign_fast` (iterative bottom-up + optional Rayon)
//!
//! Builds the *entire* tree of 2^HP leaves once in a single bottom-up pass,
//! then reads the authentication path directly from the stored nodes.
//! Total leaf evaluations = 2^HP = 256 — nearly identical count, but:
//!
//! * Each leaf is computed **exactly once** (no duplicate subtree work).
//! * With the `parallel` feature, the 256 leaf evaluations are distributed
//!   across all available CPU cores using Rayon, giving ~Ncores× speedup on
//!   the dominant cost (WOTS+ chain evaluations per leaf).
//! * Internal-node computation (h_two calls) is sequential but cheap
//!   compared to leaf generation.
//!
//! The speedup is most visible in `keygen` (which also calls this path) and
//! in `sign` on multi-core hardware.
//!
//! # Algorithm references (FIPS 205)
//!
//! | Algorithm | Name              | Baseline fn            | Fast fn               |
//! |-----------|-------------------|------------------------|-----------------------|
//! | Alg. 9    | `xmss_node`       | [`xmss_node`]          | [`xmss_node_fast`]    |
//! | Alg. 10   | `xmss_sign`       | [`xmss_sign`]          | [`xmss_sign_fast`]    |
//! | Alg. 11   | `xmss_PKFromSig`  | [`xmss_pk_from_sig`]   | (shared)              |

use crate::adrs::{Adrs, AdrsType};
use crate::hash::SphincsHasher;
use crate::params::{HP, N};
use crate::wots::{self, WotsSig};

// ── Public types ──────────────────────────────────────────────────────────────

/// Authentication path: HP sibling nodes, leaf → root.
pub type XmssAuth = [[u8; N]; HP];

/// An XMSS signature.
#[derive(Clone)]
pub struct XmssSig {
    pub sig_wots: WotsSig,
    pub auth: XmssAuth,
}

// ── Leaf helper ───────────────────────────────────────────────────────────────

/// Compute the WOTS+ public key for XMSS leaf `i`.
pub(crate) fn compute_leaf<S: SphincsHasher>(
    sk_seed: &[u8; N],
    pk_seed: &[u8; N],
    i: usize,
    adrs: &Adrs,
) -> [u8; N] {
    let mut leaf_adrs = *adrs;
    leaf_adrs.set_type_and_clear(AdrsType::Wots);
    leaf_adrs.set_keypair_address(i as u32);
    wots::wots_pk_gen::<S>(sk_seed, pk_seed, &leaf_adrs)
}

// ── Baseline: recursive tree ──────────────────────────────────────────────────

/// Compute the XMSS node at block-index `i`, height `z` (FIPS 205 Alg. 9).
///
/// This is the **baseline recursive** implementation used as a reference in
/// benchmarks.  For production use prefer [`xmss_node_fast`].
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
    let left  = xmss_node::<S>(sk_seed, 2 * i,     z - 1, pk_seed, adrs);
    let right = xmss_node::<S>(sk_seed, 2 * i + 1, z - 1, pk_seed, adrs);
    let mut node_adrs = adrs;
    node_adrs.set_type_and_clear(AdrsType::TreeNode);
    node_adrs.set_tree_height(z as u32);
    node_adrs.set_tree_index(i as u32);
    S::h_two(pk_seed, &node_adrs, &left, &right)
}

/// Sign with the **baseline recursive** strategy (FIPS 205 Alg. 10).
///
/// Each authentication-path node is computed independently by re-calling
/// `xmss_node`, which recomputes leaf subtrees from scratch at each level.
pub fn xmss_sign<S: SphincsHasher>(
    msg: &[u8; N],
    sk_seed: &[u8; N],
    idx: usize,
    pk_seed: &[u8; N],
    adrs: Adrs,
) -> XmssSig {
    let mut auth = [[0u8; N]; HP];
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

// ── Optimised: iterative bottom-up tree ───────────────────────────────────────

/// Build the complete 2-layer XMSS tree bottom-up (optimisation).
///
/// Returns `tree` where `tree[z]` is a `Vec` of all nodes at height `z`:
/// - `tree[0]` = 2^HP leaf values
/// - `tree[HP]` = `[root]` (one node)
///
/// # Parallelism
///
/// With `--features parallel` (Rayon), leaf generation at level 0 is
/// distributed across all CPU cores.  Each leaf involves `WOTS_LEN * (W-1)`
/// independent hash evaluations, so the parallel speedup is close to linear
/// in the number of available cores.
///
/// # Memory
///
/// Stores all `2^(HP+1) − 1` nodes: for HP=8, `511 × 32 = 16 352 bytes`.
fn build_tree<S: SphincsHasher>(
    sk_seed: &[u8; N],
    pk_seed: &[u8; N],
    adrs: Adrs,
) -> Vec<Vec<[u8; N]>> {
    let num_leaves = 1usize << HP;

    // ── Level 0: leaf generation ──────────────────────────────────────────
    // With the `parallel` feature, this loop is parallelised with Rayon.
    // Without it, it runs sequentially (identical result, different speed).

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

    // ── Levels 1..HP: combine pairs of children ───────────────────────────
    let mut tree: Vec<Vec<[u8; N]>> = Vec::with_capacity(HP + 1);
    tree.push(leaves);

    for z in 1..=HP {
        let prev  = &tree[z - 1];
        let width = prev.len() / 2;
        let mut layer = Vec::with_capacity(width);

        for i in 0..width {
            let mut node_adrs = adrs;
            node_adrs.set_type_and_clear(AdrsType::TreeNode);
            node_adrs.set_tree_height(z as u32);
            node_adrs.set_tree_index(i as u32);
            layer.push(S::h_two(pk_seed, &node_adrs, &prev[2 * i], &prev[2 * i + 1]));
        }
        tree.push(layer);
    }

    tree
}

/// Compute the root (or any subtree node) using the **optimised** bottom-up
/// strategy (FIPS 205 Alg. 9, optimised implementation).
///
/// For `i = 0, z = HP` (the most common call from keygen), this builds the
/// full tree and returns `tree[HP][0]`.  For all other `(i, z)` it falls
/// back to the recursive baseline so the function signature is compatible.
pub fn xmss_node_fast<S: SphincsHasher>(
    sk_seed: &[u8; N],
    i: usize,
    z: usize,
    pk_seed: &[u8; N],
    adrs: Adrs,
) -> [u8; N] {
    if i == 0 && z == HP {
        // Fast path: build the full tree once; return the root.
        let tree = build_tree::<S>(sk_seed, pk_seed, adrs);
        tree[HP][0]
    } else if z == 0 {
        compute_leaf::<S>(sk_seed, pk_seed, i, &adrs)
    } else {
        // Subtree node: fall back to recursive (called rarely in practice).
        xmss_node::<S>(sk_seed, i, z, pk_seed, adrs)
    }
}

/// Sign with the **optimised** strategy (FIPS 205 Alg. 10, optimised).
///
/// Builds the complete tree once, then reads the authentication path
/// directly from stored nodes.  This avoids the redundant subtree
/// recomputation that occurs in the baseline `xmss_sign`.
///
/// With `--features parallel` the leaf-generation phase runs in parallel.
pub fn xmss_sign_fast<S: SphincsHasher>(
    msg: &[u8; N],
    sk_seed: &[u8; N],
    idx: usize,
    pk_seed: &[u8; N],
    adrs: Adrs,
) -> XmssSig {
    // Build the complete tree (parallel leaf generation if feature enabled).
    let tree = build_tree::<S>(sk_seed, pk_seed, adrs);

    // Extract authentication path: sibling of path node at each height j.
    let mut auth = [[0u8; N]; HP];
    for j in 0..HP {
        let sibling = (idx >> j) ^ 1;
        auth[j] = tree[j][sibling];
    }

    // WOTS+ sign the message at the chosen leaf.
    let mut wots_adrs = adrs;
    wots_adrs.set_type_and_clear(AdrsType::Wots);
    wots_adrs.set_keypair_address(idx as u32);
    let sig_wots = wots::wots_sign::<S>(msg, sk_seed, pk_seed, &wots_adrs);

    XmssSig { sig_wots, auth }
}

// ── Shared: path verification (same for both strategies) ─────────────────────

/// Recover the XMSS root from a signature (FIPS 205 Alg. 11).
///
/// Identical for baseline and optimised — verification always walks the
/// stored authentication path upward.
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
    let mut node = wots::wots_pk_from_sig::<S>(&sig.sig_wots, msg, pk_seed, &wots_adrs);

    let mut node_adrs = adrs;
    node_adrs.set_type_and_clear(AdrsType::TreeNode);
    node_adrs.set_tree_index(idx as u32);

    for j in 0..HP {
        node_adrs.set_tree_height((j + 1) as u32);
        if (idx >> j) & 1 == 0 {
            let parent = node_adrs.get_tree_index() / 2;
            node_adrs.set_tree_index(parent);
            node = S::h_two(pk_seed, &node_adrs, &node, &sig.auth[j]);
        } else {
            let parent = (node_adrs.get_tree_index() - 1) / 2;
            node_adrs.set_tree_index(parent);
            node = S::h_two(pk_seed, &node_adrs, &sig.auth[j], &node);
        }
    }
    node
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

    /// Baseline and fast strategies must produce the same root.
    #[test]
    fn xmss_fast_root_matches_baseline() {
        let (sk, pk, msg) = (rng_n(), rng_n(), rng_n());
        let adrs = Adrs::new(AdrsType::TreeNode);

        let root_baseline = xmss_node::<RawSha256>(&sk, 0, HP, &pk, adrs);
        let root_fast     = xmss_node_fast::<RawSha256>(&sk, 0, HP, &pk, adrs);
        assert_eq!(root_baseline, root_fast, "roots must agree");
    }

    /// Fast sign + shared verify must succeed for multiple leaves.
    #[test]
    fn xmss_fast_sign_verify_roundtrip() {
        let (sk, pk, msg) = (rng_n(), rng_n(), rng_n());
        let adrs = Adrs::new(AdrsType::TreeNode);
        let root = xmss_node_fast::<RawSha256>(&sk, 0, HP, &pk, adrs);

        for idx in [0, 1, (1 << HP) - 2, (1 << HP) - 1] {
            let sig       = xmss_sign_fast::<RawSha256>(&msg, &sk, idx, &pk, adrs);
            let recovered = xmss_pk_from_sig::<RawSha256>(idx, &sig, &msg, &pk, adrs);
            assert_eq!(root, recovered, "fast sign failed for idx={idx}");
        }
    }

    /// Baseline and fast sign must produce the same authentication paths.
    #[test]
    fn xmss_fast_and_baseline_auth_paths_equal() {
        let (sk, pk, msg) = (rng_n(), rng_n(), rng_n());
        let adrs = Adrs::new(AdrsType::TreeNode);
        let idx  = 7usize;

        let sig_base = xmss_sign::<RawSha256>(&msg, &sk, idx, &pk, adrs);
        let sig_fast = xmss_sign_fast::<RawSha256>(&msg, &sk, idx, &pk, adrs);
        assert_eq!(sig_base.auth, sig_fast.auth, "auth paths must agree");
        assert_eq!(sig_base.sig_wots, sig_fast.sig_wots, "WOTS+ sigs must agree");
    }

    /// Baseline round-trip (kept for regression).
    #[test]
    fn xmss_baseline_roundtrip() {
        let (sk, pk, msg) = (rng_n(), rng_n(), rng_n());
        let adrs = Adrs::new(AdrsType::TreeNode);
        let root = xmss_node::<RawSha256>(&sk, 0, HP, &pk, adrs);

        for idx in [0, 3, (1 << HP) - 1] {
            let sig       = xmss_sign::<RawSha256>(&msg, &sk, idx, &pk, adrs);
            let recovered = xmss_pk_from_sig::<RawSha256>(idx, &sig, &msg, &pk, adrs);
            assert_eq!(root, recovered);
        }
    }
}