//! # Design Notes
//!
//! This implementation prioritises clarity and correctness,
//! and is used as a baseline for comparison with optimised versions.
//! In particular, the recursive `fors_node` implementation is simple
//! but not optimal, as it recomputes intermediate nodes.
//!
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

/// Split digest into K indices (each A bits)
fn decode_indices(md: &[u8; MD_BYTES]) -> [usize; K] {
    let mut indices = [0usize; K];
    let mut bit_ptr = 0usize;

    for idx in indices.iter_mut() {
        let mut val = 0usize;
        for j in 0..A {
            let byte_pos = bit_ptr / 8;
            let bit_pos = bit_ptr % 8; // LSB-first: bit 0 is the least significant bit
            val |= (((md[byte_pos] >> bit_pos) & 1) as usize) << j;
            bit_ptr += 1;
        }
        *idx = val;
    }

    indices
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Generate secret for one leaf
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

/// Recursive node computation (not optimal but simple)
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

/// Sign digest using FORS
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

/// Recover public key from signature
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

    /// decode_indices round-trips: same md always gives same indices
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

    /// fors_node(j, A) for each j = independent computation of tree j's root
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

    /// Full FORS sign → pk_from_sig round-trip
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

    /// A different message digest must produce a different (wrong) recovered PK
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
