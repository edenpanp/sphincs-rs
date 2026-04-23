use crate::adrs::AdrsType;
use crate::digest::{fors_adrs, split_digest};
use crate::group::{add_member, group_keygen, group_sign, group_verify};
use crate::hash::RawSha256;
use crate::params::{IDX_LEAF_BYTES, IDX_TREE_BYTES, M, MD_BYTES};
use crate::sphincs::{slh_keygen_fast, slh_sign_fast, slh_verify};

#[test]
fn split_digest_extracts_expected_sections() {
    let mut digest = [0u8; M];
    for (idx, byte) in digest.iter_mut().enumerate() {
        *byte = idx as u8;
    }

    let (md, idx_tree, idx_leaf) = split_digest(&digest);

    assert_eq!(md, digest[..MD_BYTES]);

    let mut tree_bytes = [0u8; 8];
    tree_bytes[8 - IDX_TREE_BYTES..].copy_from_slice(&digest[MD_BYTES..MD_BYTES + IDX_TREE_BYTES]);
    assert_eq!(idx_tree, u64::from_be_bytes(tree_bytes));

    let mut leaf_bytes = [0u8; 8];
    let leaf_start = MD_BYTES + IDX_TREE_BYTES;
    leaf_bytes[8 - IDX_LEAF_BYTES..].copy_from_slice(&digest[leaf_start..leaf_start + IDX_LEAF_BYTES]);
    assert_eq!(idx_leaf, u64::from_be_bytes(leaf_bytes));
}

#[test]
fn fors_adrs_binds_tree_and_leaf_indices() {
    let adrs = fors_adrs(0x0102_0304_0506_0708, 0x99);

    assert_eq!(adrs.adrs_type, AdrsType::ForsTree);
    assert_eq!(adrs.get_layer_address(), 0);
    assert_eq!(adrs.get_tree_address(), 0x0102_0304_0506_0708);
    assert_eq!(adrs.get_keypair_address(), 0x99);
}

#[test]
fn crate_public_apis_roundtrip() {
    let (sk, pk) = slh_keygen_fast::<RawSha256>();
    let msg = b"crate-level regression";
    let sig = slh_sign_fast::<RawSha256>(msg, &sk);
    assert!(slh_verify::<RawSha256>(msg, &sig, &pk));

    let (mut manager, gpk) = group_keygen();
    let mut member = add_member(&mut manager, 1).expect("member should be created");
    let group_sig = group_sign(b"group smoke", &mut member).expect("group signing should work");
    assert!(group_verify(b"group smoke", &group_sig, &gpk));
}
