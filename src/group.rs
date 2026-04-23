//! group signature experiment using the existing SPHINCS+ code.
//! one group is one top XMSS tree, so with HP=8 this gives up to 256 members.
//! roughly follows eprint 2025/760 but only keeps sign/verify/open/revocation.

use std::collections::BTreeSet;

use rand::{RngCore, rngs::OsRng};

use crate::digest::{fors_adrs, split_digest};
use crate::fors;
use crate::hash::SphincsHasher;
use crate::ht;
use crate::params::{D, HP, N};
use crate::sphincs::{SphincsPK, SphincsSignature, deserialise_sig, slh_verify};
use crate::xmss;

/// The group manager's master key material.
///
/// The manager distributes individual [`MemberSK`]s from this.
/// `master_seed` is sensitive — compromise of it allows forging signatures
/// for any member.
pub struct GroupManagerKey {
    /// Shared master secret (derives every member leaf).
    pub master_seed: [u8; N],
    /// Public seed (shared with all members and verifiers).
    pub pk_seed: [u8; N],
    /// Pre-computed group root (top-level XMSS tree root = group PK.root).
    pub group_root: [u8; N],
    /// Maximum number of members (2^HP per top-level XMSS tree).
    pub max_members: usize,
}

/// A single member's secret key.
///
/// Derived by the manager and distributed to member `index`.
/// This API hides the signing seed inside the member key structure so callers
/// cannot trivially rewrite the member index and impersonate another member
/// through the public API. It is still an experimental design, not a full
/// cryptographically isolated member-key architecture.
#[derive(Clone)]
pub struct MemberSK {
    /// Hidden signing seed used by the current XMSS-root construction.
    ///
    /// In this experimental design the member retains the signing seed needed
    /// to authenticate against the shared group root, but the field is not
    /// public so outside callers cannot trivially mutate the member index while
    /// reusing exposed manager material.
    signing_seed: [u8; N],
    /// Per-member PRF key for message randomness.
    /// Each member has an independent `sk_prf` so their R values are
    /// unlinkable across signatures.
    pub sk_prf: [u8; N],
    /// Public seed (same for all members).
    pub pk_seed: [u8; N],
    /// Pre-computed group root.
    pub group_root: [u8; N],
    /// This member's leaf index within the top-level XMSS tree (0..2^HP).
    pub member_index: u32,
}

/// The group public key.
///
/// Any verifier can verify a group signature using only this key.
/// It is structurally identical to a SPHINCS+ public key.
pub struct GroupPK {
    pub pk_seed: [u8; N],
    pub group_root: [u8; N],
}

/// Manager-side revocation list for the experimental group extension.
///
/// This is intentionally lightweight: public verifiers still call
/// [`group_verify`], while manager-side policy checks can additionally require
/// `group_verify_not_revoked`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GroupRevocationList {
    revoked_members: BTreeSet<u32>,
}

impl GroupRevocationList {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn revoke(&mut self, member_index: u32) -> bool {
        self.revoked_members.insert(member_index)
    }

    pub fn unrevoke(&mut self, member_index: u32) -> bool {
        self.revoked_members.remove(&member_index)
    }

    pub fn is_revoked(&self, member_index: u32) -> bool {
        self.revoked_members.contains(&member_index)
    }
}

impl GroupPK {
    /// Convert to the underlying SPHINCS+ public key for `slh_verify`.
    pub fn as_sphincs_pk(&self) -> SphincsPK {
        SphincsPK {
            pk_seed: self.pk_seed,
            pk_root: self.group_root,
        }
    }
}

// compute top-level XMSS root (= group root). same as slh_keygen does
// but pull out so we can test it seperately.
pub fn compute_group_root<S: SphincsHasher>(sk_seed: &[u8; N], pk_seed: &[u8; N]) -> [u8; N] {
    let mut adrs = crate::adrs::Adrs::new(crate::adrs::AdrsType::TreeNode);
    adrs.set_layer_address((D - 1) as u32);
    adrs.set_tree_address(0);
    xmss::xmss_node_fast::<S>(sk_seed, 0, HP, pk_seed, adrs)
}

// search for r so digest's idx_leaf == target_leaf.
// scan last 2 bytes of opt_rand, 2^16 combos. for HP=8 around 256 tries
// on average. return None if all fail (basicly never).
// TODO: maybe also randomize more bytes if 2 bytes not enough.
pub fn search_r<S: SphincsHasher>(
    msg: &[u8],
    sk_prf: &[u8; N],
    pk_seed: &[u8; N],
    group_root: &[u8; N],
    target_leaf: u64,
) -> Option<[u8; N]> {
    #[cfg(feature = "parallel")]
    {
        use rayon::prelude::*;
        return (0u32..65536).into_par_iter().find_map_any(|idx| {
            let hi = (idx >> 8) as u8;
            let lo = (idx & 0xff) as u8;
            let mut opt = *pk_seed;
            opt[N - 2] = hi;
            opt[N - 1] = lo;
            let r_try = S::prf_msg(sk_prf, &opt, msg);
            let d = S::h_msg(&r_try, pk_seed, group_root, msg);
            let (_, _, leaf) = split_digest(&d);
            if leaf == target_leaf {
                Some(r_try)
            } else {
                None
            }
        });
    }

    // sequential fallback (no rayon).
    let mut ans: Option<[u8; N]> = None;
    let mut done = false;
    for hi in 0u8..=255 {
        if done {
            break;
        }
        for lo in 0u8..=255 {
            let mut opt = *pk_seed;
            opt[N - 2] = hi;
            opt[N - 1] = lo;
            let r_try = S::prf_msg(sk_prf, &opt, msg);
            let d = S::h_msg(&r_try, pk_seed, group_root, msg);
            let (_, _, leaf) = split_digest(&d);
            if leaf == target_leaf {
                ans = Some(r_try);
                done = true;
                break;
            }
        }
    }
    ans
}

/// Generate a group key pair for up to `2^HP` members (FIPS 205 Alg. 18 variant).
///
/// The manager calls this once and distributes member keys via [`derive_member_key`].
pub fn group_keygen<S: SphincsHasher>() -> (GroupManagerKey, GroupPK) {
    let mut master_seed = [0u8; N];
    let mut pk_seed = [0u8; N];
    OsRng.fill_bytes(&mut master_seed);
    OsRng.fill_bytes(&mut pk_seed);

    let group_root = compute_group_root::<S>(&master_seed, &pk_seed);

    let manager = GroupManagerKey {
        master_seed,
        pk_seed,
        group_root,
        max_members: 1 << HP,
    };
    let gpk = GroupPK {
        pk_seed,
        group_root,
    };
    (manager, gpk)
}

/// Derive member `index`'s secret key from the manager key.
///
/// `index` must be in `0..manager.max_members`.
/// Each member gets an independent `sk_prf` sampled freshly so their
/// per-message randomness is unlinkable.
pub fn derive_member_key<S: SphincsHasher>(manager: &GroupManagerKey, index: u32) -> MemberSK {
    assert!(
        (index as usize) < manager.max_members,
        "member index {index} exceeds max_members {}",
        manager.max_members
    );
    let mut sk_prf = [0u8; N];
    OsRng.fill_bytes(&mut sk_prf);

    MemberSK {
        signing_seed: manager.master_seed,
        sk_prf,
        pk_seed: manager.pk_seed,
        group_root: manager.group_root,
        member_index: index,
    }
}

/// Sign a message as a group member (FIPS 205 Alg. 19 variant).
///
/// # Key difference from `slh_sign`
///
/// In standard SPHINCS+, `idx_leaf` comes from the message digest.
/// Here, `idx_leaf` is **forced to `member_index`**, so the member's
/// WOTS+ leaf is always used, regardless of the message content.
/// The `idx_tree` still comes from the digest for domain separation.
///
/// This means the FORS signature is computed for the same tree/leaf
/// combination as in standard signing, but the HT signature always
/// authenticates through the member's specific leaf.
pub fn group_sign<S: SphincsHasher>(msg: &[u8], sk: &MemberSK) -> SphincsSignature {
    // find r so idx_leaf from digest == member_index. otherwise FORS and
    // HT will not agree and verify fail.
    let r = search_r::<S>(
        msg,
        &sk.sk_prf,
        &sk.pk_seed,
        &sk.group_root,
        sk.member_index as u64,
    )
    .expect("search_r: 2^16 tries exhausted");
    let d = S::h_msg(&r, &sk.pk_seed, &sk.group_root, msg);
    let (md, idx_tree, _) = split_digest(&d);
    let idx_leaf = sk.member_index as u64;

    let f_adrs = fors_adrs(idx_tree, idx_leaf);
    let fors_sig = fors::fors_sign::<S>(&md, &sk.signing_seed, &sk.pk_seed, &f_adrs);
    let fors_pk = fors::fors_pk_from_sig::<S>(&fors_sig, &md, &sk.pk_seed, &f_adrs);
    let ht_sig = ht::ht_sign_fast::<S>(
        &fors_pk,
        &sk.signing_seed,
        &sk.pk_seed,
        idx_tree,
        idx_leaf,
    );

    SphincsSignature {
        r,
        fors_sig,
        ht_sig,
    }
}

/// Verify a group signature (standard `slh_verify` under the group public key).
///
/// Returns `true` iff the signature is valid under `gpk`.
/// Does NOT reveal which member signed.
pub fn group_verify<S: SphincsHasher>(msg: &[u8], sig: &SphincsSignature, gpk: &GroupPK) -> bool {
    slh_verify::<S>(msg, sig, &gpk.as_sphincs_pk())
}

/// Verify a group signature from raw bytes.
pub fn group_verify_raw<S: SphincsHasher>(msg: &[u8], sig_bytes: &[u8], gpk: &GroupPK) -> bool {
    match deserialise_sig(sig_bytes) {
        Some(sig) => group_verify::<S>(msg, &sig, gpk),
        None => false,
    }
}

/// Manager-side opening algorithm for the experimental group extension.
///
/// This returns the identified signer index if the signature is valid for some
/// member leaf under the current group manager state.
pub fn group_open<S: SphincsHasher>(
    msg: &[u8],
    sig: &SphincsSignature,
    manager: &GroupManagerKey,
) -> Option<u32> {
    group_identify_member::<S>(msg, sig, manager)
}

/// Manager-side verification with a revocation policy check.
///
/// Public verification remains `group_verify`. This helper is for the manager
/// or an authority that can both open the signature and consult the revocation
/// list.
pub fn group_verify_not_revoked<S: SphincsHasher>(
    msg: &[u8],
    sig: &SphincsSignature,
    gpk: &GroupPK,
    manager: &GroupManagerKey,
    revocations: &GroupRevocationList,
) -> bool {
    if !group_verify::<S>(msg, sig, gpk) {
        return false;
    }
    match group_open::<S>(msg, sig, manager) {
        Some(member_index) => !revocations.is_revoked(member_index),
        None => false,
    }
}

/// Attempt to identify which member produced a signature (manager only).
///
/// The manager scans candidate leaves and checks whether the FORS and
/// hypertree parts are consistent with that member leaf. Returns
/// `Some(member_index)` if a matching member is found.
///
/// # Complexity
/// O(M × WOTS+ key generation) where M = number of members.
/// For M ≤ 256 (HP=8) this is practical; for larger groups, the manager
/// should use the authentication path structure to narrow the search.
///
/// # Note on anonymity
/// An external verifier who does NOT have the manager state cannot efficiently
/// perform this check, so anonymity holds against non-manager adversaries.
pub fn group_identify_member<S: SphincsHasher>(
    msg: &[u8],
    sig: &SphincsSignature,
    manager: &GroupManagerKey,
) -> Option<u32> {
    let d = S::h_msg(&sig.r, &manager.pk_seed, &manager.group_root, msg);
    let (md, idx_tree, _) = split_digest(&d);

    #[cfg(feature = "parallel")]
    {
        use rayon::prelude::*;
        return (0..(manager.max_members as u32))
            .into_par_iter()
            .find_any(|c| {
                let leaf = *c as u64;
                let f_adrs = fors_adrs(idx_tree, leaf);
                let expected_sig =
                    fors::fors_sign::<S>(&md, &manager.master_seed, &manager.pk_seed, &f_adrs);
                if expected_sig != sig.fors_sig {
                    return false;
                }
                let fpk = fors::fors_pk_from_sig::<S>(
                    &sig.fors_sig,
                    &md,
                    &manager.pk_seed,
                    &f_adrs,
                );
                ht::ht_verify::<S>(
                    &fpk,
                    &sig.ht_sig,
                    &manager.pk_seed,
                    idx_tree,
                    leaf,
                    &manager.group_root,
                )
            });
    }

    for c in 0..(manager.max_members as u32) {
        let leaf = c as u64;
        let f_adrs = fors_adrs(idx_tree, leaf);
        let expected_sig =
            fors::fors_sign::<S>(&md, &manager.master_seed, &manager.pk_seed, &f_adrs);
        if expected_sig != sig.fors_sig {
            continue;
        }
        let fpk = fors::fors_pk_from_sig::<S>(&sig.fors_sig, &md, &manager.pk_seed, &f_adrs);
        if ht::ht_verify::<S>(
            &fpk,
            &sig.ht_sig,
            &manager.pk_seed,
            idx_tree,
            leaf,
            &manager.group_root,
        ) {
            return Some(c);
        }
    }
    None
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::RawSha256;
    use crate::sphincs::{SIG_BYTES, serialise_sig};

    #[test]
    fn group_sign_verify_roundtrip() {
        let (manager, gpk) = group_keygen::<RawSha256>();
        let msg = b"UNSW 26T1 Applied Cryptography group sig test";

        for idx in [0u32, 1, 7, (1 << HP) - 1] {
            let msk = derive_member_key::<RawSha256>(&manager, idx);
            let sig = group_sign::<RawSha256>(msg, &msk);
            assert!(
                group_verify::<RawSha256>(msg, &sig, &gpk),
                "group_verify failed for member {idx}"
            );
        }
    }

    #[test]
    fn group_wrong_message_fails() {
        let (manager, gpk) = group_keygen::<RawSha256>();
        let msk = derive_member_key::<RawSha256>(&manager, 0);
        let sig = group_sign::<RawSha256>(b"correct", &msk);
        assert!(!group_verify::<RawSha256>(b"wrong", &sig, &gpk));
    }

    #[test]
    fn group_cross_group_fails() {
        let (manager1, gpk1) = group_keygen::<RawSha256>();
        let (_manager2, gpk2) = group_keygen::<RawSha256>();
        let msk = derive_member_key::<RawSha256>(&manager1, 0);
        let msg = b"cross group test";
        let sig = group_sign::<RawSha256>(msg, &msk);
        assert!(
            group_verify::<RawSha256>(msg, &sig, &gpk1),
            "valid sig rejected under own group"
        );
        assert!(
            !group_verify::<RawSha256>(msg, &sig, &gpk2),
            "sig accepted under different group"
        );
    }

    #[test]
    fn group_raw_roundtrip() {
        let (manager, gpk) = group_keygen::<RawSha256>();
        let msk = derive_member_key::<RawSha256>(&manager, 3);
        let msg = b"raw group sig test";
        let sig = group_sign::<RawSha256>(msg, &msk);
        let sig_bytes = serialise_sig(&sig);
        assert_eq!(sig_bytes.len(), SIG_BYTES);
        assert!(group_verify_raw::<RawSha256>(msg, &sig_bytes, &gpk));
    }

    #[test]
    fn group_identify_correct_member() {
        let (manager, _gpk) = group_keygen::<RawSha256>();
        let msg = b"identify me";

        for expected_idx in [0u32, 1, 5] {
            let msk = derive_member_key::<RawSha256>(&manager, expected_idx);
            let sig = group_sign::<RawSha256>(msg, &msk);
            let found = group_identify_member::<RawSha256>(msg, &sig, &manager);
            assert_eq!(
                found,
                Some(expected_idx),
                "manager identified wrong member: got {found:?}, expected Some({expected_idx})"
            );
        }
    }

    #[test]
    fn group_signatures_are_anonymous() {
        let (manager, gpk) = group_keygen::<RawSha256>();
        let msg = b"anonymous message";
        let msk0 = derive_member_key::<RawSha256>(&manager, 0);
        let msk1 = derive_member_key::<RawSha256>(&manager, 1);

        let sig0 = group_sign::<RawSha256>(msg, &msk0);
        let sig1 = group_sign::<RawSha256>(msg, &msk1);

        assert!(
            group_verify::<RawSha256>(msg, &sig0, &gpk),
            "sig0 should verify"
        );
        assert!(
            group_verify::<RawSha256>(msg, &sig1, &gpk),
            "sig1 should verify"
        );

        let bytes0 = serialise_sig(&sig0);
        let bytes1 = serialise_sig(&sig1);
        assert_ne!(
            bytes0, bytes1,
            "signatures from different members should differ"
        );
    }

    #[test]
    fn group_member_can_sign_multiple_messages() {
        let (manager, gpk) = group_keygen::<RawSha256>();
        let msk = derive_member_key::<RawSha256>(&manager, 2);

        let msgs: &[&[u8]] = &[b"msg one", b"msg two", b"msg three"];
        for msg in msgs {
            let sig = group_sign::<RawSha256>(msg, &msk);
            assert!(
                group_verify::<RawSha256>(msg, &sig, &gpk),
                "member 2 failed to verify for: {}",
                String::from_utf8_lossy(msg)
            );
        }
    }

    // check compute_group_root give the same root as keygen.
    #[test]
    fn compute_group_root_same_as_keygen() {
        let (manager, _gpk) = group_keygen::<RawSha256>();
        let again = compute_group_root::<RawSha256>(&manager.master_seed, &manager.pk_seed);
        assert_eq!(again, manager.group_root);
    }

    // search_r must find a r that make digest hit the target leaf.
    #[test]
    fn search_r_hits_target() {
        let (manager, _gpk) = group_keygen::<RawSha256>();
        let msk = derive_member_key::<RawSha256>(&manager, 4);
        let msg = b"find target leaf";

        let r = search_r::<RawSha256>(
            msg,
            &msk.sk_prf,
            &msk.pk_seed,
            &msk.group_root,
            msk.member_index as u64,
        )
        .expect("search_r must hit within 2^16");
        let digest = RawSha256::h_msg(&r, &msk.pk_seed, &msk.group_root, msg);
        let (_, _, leaf) = split_digest(&digest);

        assert_eq!(leaf, msk.member_index as u64);
    }

    #[test]
    fn member_key_hides_signing_seed_from_public_api() {
        let (manager, _gpk) = group_keygen::<RawSha256>();
        let member0 = derive_member_key::<RawSha256>(&manager, 0);
        let member1 = derive_member_key::<RawSha256>(&manager, 1);

        assert_eq!(member0.signing_seed, manager.master_seed);
        assert_eq!(member1.signing_seed, manager.master_seed);
        assert_ne!(member0.sk_prf, member1.sk_prf);
    }

    #[test]
    fn group_open_matches_identify() {
        let (manager, _gpk) = group_keygen::<RawSha256>();
        let msk = derive_member_key::<RawSha256>(&manager, 6);
        let msg = b"open the signature";
        let sig = group_sign::<RawSha256>(msg, &msk);

        assert_eq!(
            group_open::<RawSha256>(msg, &sig, &manager),
            group_identify_member::<RawSha256>(msg, &sig, &manager)
        );
        assert_eq!(group_open::<RawSha256>(msg, &sig, &manager), Some(6));
    }

    #[test]
    fn group_verify_not_revoked_rejects_revoked_member() {
        let (manager, gpk) = group_keygen::<RawSha256>();
        let msk = derive_member_key::<RawSha256>(&manager, 9);
        let msg = b"revocation policy";
        let sig = group_sign::<RawSha256>(msg, &msk);

        let mut revocations = GroupRevocationList::new();
        assert!(group_verify_not_revoked::<RawSha256>(
            msg,
            &sig,
            &gpk,
            &manager,
            &revocations
        ));

        revocations.revoke(9);
        assert!(!group_verify_not_revoked::<RawSha256>(
            msg,
            &sig,
            &gpk,
            &manager,
            &revocations
        ));
    }
}
