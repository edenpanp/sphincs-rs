//! FORS (Forest of Random Subsets) signature implementation.
//!
//! FORS is the few-time signature scheme used at the bottom of SPHINCS+.
//! It signs the `MD_BYTES`-byte FORS portion of the message digest before
//! passing a commitment up to the hypertree (HT) layer.
//!
//! # Structure
//!
//! FORS consists of `K` independent binary Merkle trees, each of height `A`
//! (2^A = T leaves). The private key is K × T secret values; the public key
//! is all K tree roots compressed into N bytes.
//!
//! # Node indexing
//!
//! Same block-index convention as XMSS:
//!   - `fors_node(i, 0)` = leaf at absolute index i (across all K trees)
//!   - `fors_node(i, z)` = ancestor covering leaves [i·2^z, (i+1)·2^z − 1]
//!   - Tree j's root = `fors_node(j, A)` (covers its T leaves exclusively)
//!   - Tree j's leaves span absolute indices [j·T, (j+1)·T − 1]
//!
//! # Algorithm references (FIPS 205)
//!
//! | Algorithm | Name              | Function here          |
//! |-----------|-------------------|------------------------|
//! | Alg. 14   | `fors_SKgen`      | [`fors_sk_gen`]        |
//! | Alg. 15   | `fors_node`       | [`fors_node`]          |
//! | Alg. 16   | `fors_sign`       | [`fors_sign`]          |
//! | Alg. 17   | `fors_PKFromSig`  | [`fors_pk_from_sig`]   |
//!
//! # TODO: KAT compliance
//!
//! Verify auth-path index computation `(j·T + (idx_j >> l)) ^ 1` against NIST
//! FIPS 205 KAT vectors. The signing/verification are mutually consistent here.

use crate::adrs::{Adrs, AdrsType};
use crate::hash::SphincsHasher;
use crate::params::{A, K, MD_BYTES, N, T};

// ── Public types ──────────────────────────────────────────────────────────────

/// Authentication path for one FORS tree: A sibling nodes (leaf → root).
pub type ForsAuth = [[u8; N]; A];

/// FORS signature element for a single tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForsTreeSig {
    /// The revealed FORS secret key leaf (= `PRF(pk_seed, sk_seed, ADRS)`).
    pub sk: [u8; N],
    /// Merkle authentication path (A sibling nodes, leaf → root).
    pub auth: ForsAuth,
}

/// Full FORS signature: K independent tree signatures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForsSig {
    /// One [`ForsTreeSig`] per FORS tree (length K).
    pub trees: Vec<ForsTreeSig>,
}

// ── Digest decoding ───────────────────────────────────────────────────────────

/// Decode the FORS portion of the message digest into K leaf indices.
///
/// The `MD_BYTES = ⌈K·A/8⌉` bytes are split into K consecutive A-bit
/// integers (big-endian bit order). Each index selects one leaf in the
/// corresponding tree, i.e. each is in [0, T = 2^A).
///
/// # Example (K=2, A=3)
///
/// ```text
/// md bytes: [0b_110_010_xx, ...]
///             ^^^  ^^^
///            idx₀=6  idx₁=2
/// ```
fn decode_indices(md: &[u8; MD_BYTES]) -> [usize; K] {
    let mut indices = [0usize; K];
    let mut bit_ptr = 0usize; // current bit position in `md` (MSB-first)

    for idx in indices.iter_mut() {
        let mut val = 0usize;
        for _ in 0..A {
            let byte_pos = bit_ptr / 8;
            let bit_pos = 7 - (bit_ptr % 8); // MSB-first within each byte
            val = (val << 1) | (((md[byte_pos] >> bit_pos) & 1) as usize);
            bit_ptr += 1;
        }
        *idx = val;
    }

    indices
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Derive FORS secret key element at absolute leaf index `idx` (Alg. 14).
///
/// ```text
/// fors_SKgen(SK.seed, PK.seed, ADRS, idx):
///   ADRS.type = FORS_TREE
///   ADRS.keypair = outer keypair address  (preserved from caller)
///   ADRS.tree_height = 0
///   ADRS.tree_index  = idx  (absolute leaf in the K-tree forest)
///   return PRF(PK.seed, SK.seed, ADRS)
/// ```
pub fn fors_sk_gen<S: SphincsHasher>(
    sk_seed: &[u8; N],
    pk_seed: &[u8; N],
    adrs: &Adrs,
    idx: usize,
) -> [u8; N] {
    let mut sk_adrs = *adrs;
    sk_adrs.set_type_and_clear(AdrsType::ForsTree);
    sk_adrs.set_keypair_address(adrs.get_keypair_address());
    sk_adrs.set_tree_height(0);
    sk_adrs.set_tree_index(idx as u32);
    S::prf(pk_seed, sk_seed, &sk_adrs)
}

/// Compute FORS node at block-index `i`, height `z` (Alg. 15).
///
/// Block-index `i` covers absolute leaves [i·2^z, (i+1)·2^z − 1].
///
/// ```text
/// if z == 0:
///   sk = fors_SKgen(SK.seed, PK.seed, ADRS, i)
///   return F(PK.seed, ADRS with height=0 index=i, sk)
/// else:
///   left  = fors_node(SK.seed, 2i,   z-1, PK.seed, ADRS)
///   right = fors_node(SK.seed, 2i+1, z-1, PK.seed, ADRS)
///   return H(PK.seed, ADRS with height=z index=i, left, right)
/// ```
pub fn fors_node<S: SphincsHasher>(
    sk_seed: &[u8; N],
    i: usize,
    z: usize,
    pk_seed: &[u8; N],
    adrs: &Adrs,
) -> [u8; N] {
    if z == 0 {
        // Leaf: derive SK, then apply F
        let sk = fors_sk_gen::<S>(sk_seed, pk_seed, adrs, i);

        let mut leaf_adrs = *adrs;
        leaf_adrs.set_type_and_clear(AdrsType::ForsTree);
        leaf_adrs.set_keypair_address(adrs.get_keypair_address());
        leaf_adrs.set_tree_height(0);
        leaf_adrs.set_tree_index(i as u32);

        return S::f(pk_seed, &leaf_adrs, &sk);
    }

    let left = fors_node::<S>(sk_seed, 2 * i, z - 1, pk_seed, adrs);
    let right = fors_node::<S>(sk_seed, 2 * i + 1, z - 1, pk_seed, adrs);

    let mut node_adrs = *adrs;
    node_adrs.set_type_and_clear(AdrsType::ForsTree);
    node_adrs.set_keypair_address(adrs.get_keypair_address());
    node_adrs.set_tree_height(z as u32);
    node_adrs.set_tree_index(i as u32);

    S::h_two(pk_seed, &node_adrs, &left, &right)
}

/// Generate a FORS signature for message digest `md` (Alg. 16).
///
/// For each tree j (0..K):
///   1. Decode leaf index `idx_j = indices[j]` from `md`.
///   2. Reveal `SK[j·T + idx_j]` = the secret leaf.
///   3. Compute the A-node authentication path from that leaf to tree j's root.
///
/// The absolute leaf in tree j is `j·T + idx_j`.
/// The auth node at height l is the sibling of the ancestor of that leaf:
/// `fors_node(abs_leaf >> (l+1) << (l+1) | (sibling_bit << l), l)`
/// which simplifies to: sibling block-index = `(abs_leaf >> l) ^ 1`.
pub fn fors_sign<S: SphincsHasher>(
    md: &[u8; MD_BYTES],
    sk_seed: &[u8; N],
    pk_seed: &[u8; N],
    adrs: &Adrs,
) -> ForsSig {
    let indices = decode_indices(md);
    let mut trees = Vec::with_capacity(K);

    for j in 0..K {
        let idx_j = indices[j];
        let abs_leaf = j * T + idx_j; // absolute leaf in the K·T forest

        // Reveal the secret key leaf
        let sk = fors_sk_gen::<S>(sk_seed, pk_seed, adrs, abs_leaf);

        // Build authentication path: sibling block at each height
        let mut auth = [[0u8; N]; A];
        for l in 0..A {
            let sibling_block = (abs_leaf >> l) ^ 1;
            auth[l] = fors_node::<S>(sk_seed, sibling_block, l, pk_seed, adrs);
        }

        trees.push(ForsTreeSig { sk, auth });
    }

    ForsSig { trees }
}

/// Recover the FORS public key from a signature (Alg. 17).
///
/// For each tree j:
///   1. Recompute the leaf node from `sk_j` using `F`.
///   2. Walk the authentication path to recover tree j's root.
/// Then compress all K roots into a single N-byte public key using `T_K`.
pub fn fors_pk_from_sig<S: SphincsHasher>(
    sig: &ForsSig,
    md: &[u8; MD_BYTES],
    pk_seed: &[u8; N],
    adrs: &Adrs,
) -> [u8; N] {
    debug_assert_eq!(sig.trees.len(), K, "ForsSig must contain exactly K trees");

    let indices = decode_indices(md);
    let mut roots = [[0u8; N]; K];

    for j in 0..K {
        let idx_j = indices[j];
        let abs_leaf = j * T + idx_j;
        let tree_sig = &sig.trees[j];

        // Step 1: leaf node = F(pk_seed, ADRS, sk_j)
        let mut leaf_adrs = *adrs;
        leaf_adrs.set_type_and_clear(AdrsType::ForsTree);
        leaf_adrs.set_keypair_address(adrs.get_keypair_address());
        leaf_adrs.set_tree_height(0);
        leaf_adrs.set_tree_index(abs_leaf as u32);
        let mut node = S::f(pk_seed, &leaf_adrs, &tree_sig.sk);

        // Step 2: walk up the authentication path
        let mut node_adrs = *adrs;
        node_adrs.set_type_and_clear(AdrsType::ForsTree);
        node_adrs.set_keypair_address(adrs.get_keypair_address());
        node_adrs.set_tree_index(abs_leaf as u32);

        for l in 0..A {
            node_adrs.set_tree_height((l + 1) as u32);

            if (abs_leaf >> l) & 1 == 0 {
                // Current is left child → parent block = current / 2
                let parent = node_adrs.get_tree_index() / 2;
                node_adrs.set_tree_index(parent);
                node = S::h_two(pk_seed, &node_adrs, &node, &tree_sig.auth[l]);
            } else {
                // Current is right child → parent block = (current − 1) / 2
                let parent = (node_adrs.get_tree_index() - 1) / 2;
                node_adrs.set_tree_index(parent);
                node = S::h_two(pk_seed, &node_adrs, &tree_sig.auth[l], &node);
            }
        }

        roots[j] = node;
    }

    // Compress K roots into the FORS public key
    let mut pk_adrs = *adrs;
    pk_adrs.set_type_and_clear(AdrsType::ForsPk);
    pk_adrs.set_keypair_address(adrs.get_keypair_address());
    S::t_l(pk_seed, &pk_adrs, &roots)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::RawSha256;
    use rand::{RngCore, rngs::OsRng};

    fn random_n() -> [u8; N] {
        let mut b = [0u8; N];
        OsRng.fill_bytes(&mut b);
        b
    }

    fn random_md() -> [u8; MD_BYTES] {
        let mut b = [0u8; MD_BYTES];
        OsRng.fill_bytes(&mut b);
        b
    }

    /// decode_indices round-trips: same md always gives same indices.
    #[test]
    fn decode_indices_deterministic() {
        let md = random_md();
        assert_eq!(decode_indices(&md), decode_indices(&md));
    }

    /// All decoded indices must be in [0, T).
    #[test]
    fn decode_indices_range() {
        for _ in 0..10 {
            let md = random_md();
            for idx in decode_indices(&md) {
                assert!(idx < T, "index {idx} out of range [0, {T})");
            }
        }
    }

    /// fors_node(j, A) for each j = independent computation of tree j's root.
    #[test]
    fn fors_tree_roots_are_distinct() {
        let (sk_seed, pk_seed) = (random_n(), random_n());
        let mut adrs = Adrs::new(AdrsType::ForsTree);
        adrs.set_keypair_address(0);

        let roots: Vec<_> = (0..K)
            .map(|j| fors_node::<RawSha256>(&sk_seed, j, A, &pk_seed, &adrs))
            .collect();

        // All roots should be distinct with overwhelming probability
        for i in 0..K {
            for j in (i + 1)..K {
                assert_ne!(roots[i], roots[j], "trees {i} and {j} have the same root");
            }
        }
    }

    /// Full FORS sign → pk_from_sig round-trip.
    #[test]
    fn fors_sign_verify_roundtrip() {
        let (sk_seed, pk_seed) = (random_n(), random_n());
        let md = random_md();

        let mut adrs = Adrs::new(AdrsType::ForsTree);
        adrs.set_keypair_address(0);

        // Compute FORS PK directly (K tree roots → T_K)
        let roots: [[u8; N]; K] = {
            let v: Vec<_> = (0..K)
                .map(|j| fors_node::<RawSha256>(&sk_seed, j, A, &pk_seed, &adrs))
                .collect();
            let mut arr = [[0u8; N]; K];
            arr.copy_from_slice(&v);
            arr
        };
        let mut pk_adrs = adrs;
        pk_adrs.set_type_and_clear(AdrsType::ForsPk);
        pk_adrs.set_keypair_address(adrs.get_keypair_address());
        let fors_pk_direct = RawSha256::t_l(&pk_seed, &pk_adrs, &roots);

        // Sign and recover PK
        let sig = fors_sign::<RawSha256>(&md, &sk_seed, &pk_seed, &adrs);
        let fors_pk_recovered = fors_pk_from_sig::<RawSha256>(&sig, &md, &pk_seed, &adrs);

        assert_eq!(fors_pk_direct, fors_pk_recovered, "FORS PK recovery failed");
    }

    /// A different message digest must produce a different (wrong) recovered PK.
    #[test]
    fn fors_wrong_digest_fails() {
        let (sk_seed, pk_seed) = (random_n(), random_n());
        let md = random_md();
        let wrong = random_md();

        let mut adrs = Adrs::new(AdrsType::ForsTree);
        adrs.set_keypair_address(0);

        let sig = fors_sign::<RawSha256>(&md, &sk_seed, &pk_seed, &adrs);
        let pk_correct = fors_pk_from_sig::<RawSha256>(&sig, &md, &pk_seed, &adrs);
        let pk_wrong = fors_pk_from_sig::<RawSha256>(&sig, &wrong, &pk_seed, &adrs);

        assert_ne!(pk_correct, pk_wrong, "FORS accepted wrong digest");
    }
}
