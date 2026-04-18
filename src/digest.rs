//! Digest parsing utilities shared by sphincs and group modules.
//!
//! This module provides common digest handling functions to avoid duplication
//! between the main SPHINCS+ signature scheme and the group signature extension.

use crate::adrs::{Adrs, AdrsType};
use crate::params::{IDX_LEAF_BYTES, IDX_TREE_BYTES, MD_BYTES, M};

/// Split an M-byte message digest into its three components.
///
/// The digest is structured as:
/// ```text
/// [ md (MD_BYTES) | idx_tree (IDX_TREE_BYTES) | idx_leaf (IDX_LEAF_BYTES) ]
/// ```
///
/// Returns `(md, idx_tree, idx_leaf)`.
pub fn split_digest(digest: &[u8; M]) -> ([u8; MD_BYTES], u64, u64) {
    let mut md = [0u8; MD_BYTES];
    md.copy_from_slice(&digest[..MD_BYTES]);

    let idx_tree = {
        let mut buf = [0u8; 8];
        let len = IDX_TREE_BYTES.min(8);
        buf[8 - len..].copy_from_slice(&digest[MD_BYTES..MD_BYTES + len]);
        u64::from_be_bytes(buf)
    };
    let idx_leaf = {
        let mut buf = [0u8; 8];
        let len = IDX_LEAF_BYTES.min(8);
        let start = MD_BYTES + IDX_TREE_BYTES;
        buf[8 - len..].copy_from_slice(&digest[start..start + len]);
        u64::from_be_bytes(buf)
    };
    (md, idx_tree, idx_leaf)
}

/// Create a FORS tree ADRS for the given tree and leaf indices.
pub fn fors_adrs(idx_tree: u64, idx_leaf: u64) -> Adrs {
    let mut adrs = Adrs::new(AdrsType::ForsTree);
    adrs.set_layer_address(0);
    adrs.set_tree_address(idx_tree);
    adrs.set_keypair_address(idx_leaf as u32);
    adrs
}
