//! utils for digest parsing
//!
//! tbh this is just to avoid rewriting same code in sphincs + group part
//! nothing fancy, just split things correctly

use crate::adrs::{Adrs, AdrsType};
use crate::params::{IDX_LEAF_BYTES, IDX_TREE_BYTES, MD_BYTES, M};

/// split digest -> (md, tree, leaf)
///
/// layout:
/// [ md | tree | leaf ]
pub fn split_digest(digest: &[u8; M]) -> ([u8; MD_BYTES], u64, u64) {
    // ---- md ----
    let mut md = [0u8; MD_BYTES];
    md.copy_from_slice(&digest[..MD_BYTES]); 
    // should be safe since size is fixed

    // ---- tree idx ----
    let idx_tree = {
        let mut tmp = [0u8; 8]; // use tmp buf to extend into u64
        let len = IDX_TREE_BYTES.min(8); // just in case (although normally <= 8)

        // NOTE: big endian align (important, don't mess this up lol)
        tmp[8 - len..].copy_from_slice(&digest[MD_BYTES..MD_BYTES + len]);

        u64::from_be_bytes(tmp)
    };

    // ---- leaf idx ----
    let idx_leaf = {
        let mut tmp = [0u8; 8];
        let len = IDX_LEAF_BYTES.min(8);

        let offset = MD_BYTES + IDX_TREE_BYTES; // start pos
        tmp[8 - len..].copy_from_slice(&digest[offset..offset + len]);

        u64::from_be_bytes(tmp)
    };

    // quick sanity: all parts extracted
    (md, idx_tree, idx_leaf)
}

/// construct FORS address from indices
///
/// basically just fill in fields we need
pub fn fors_adrs(idx_tree: u64, idx_leaf: u64) -> Adrs {
    let mut adrs = Adrs::new(AdrsType::ForsTree);

    // these are kinda fixed for FORS
    adrs.set_layer_address(0); // always 0 here (i think...)
    adrs.set_tree_address(idx_tree);

    // leaf idx fits into u32 (spec says so), so just cast
    adrs.set_keypair_address(idx_leaf as u32);

    adrs
}