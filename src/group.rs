use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};

use crate::adrs::{Adrs, AdrsType};
use crate::hash::Sha256Hasher;
use crate::params::{N, WOTS_LEN};
use crate::sphincs::{
    SIG_BYTES, SphincsPK, SphincsSK, SphincsSignature, deserialise_sig, serialise_sig,
    slh_keygen_fast, slh_sign_fast, slh_verify,
};
use crate::wots::{self, WotsSig};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupError {
    MemberLimitReached,
    UnknownMember,
    NoUnusedCertifiedKey,
    BadKeyIndex,
    CertificateMismatch,
    BadRawEncoding,
}

/// Public part of one one-time WOTS+ key.
#[derive(Clone, Debug)]
pub struct OneTimePublicKey {
    pub member_id: u32,
    pub key_id: u32,
    pub pk_seed: [u8; N],
    pub wots_pk: [u8; N],
}

/// Full one-time WOTS+ key pair held by the member.
#[derive(Clone, Debug)]
struct OneTimeKeyPair {
    key_id: u32,
    sk_seed: [u8; N],
    pk_seed: [u8; N],
    public_key: OneTimePublicKey,
}

/// Certificate issued by the manager for one WOTS+ public key.
#[derive(Clone, Debug)]
pub struct MemberCertificate {
    pub certificate_id: u64,
    pub member_id: u32,
    pub key_id: u32,
    pub issued_epoch: u64,
    pub expiry_epoch: u64,
    pub role: u8,
    pub pk_seed: [u8; N],
    pub wots_pk: [u8; N],
    pub manager_signature: SphincsSignature,
}

/// Extra policy used during verification.
#[derive(Clone, Debug)]
pub struct CertificateValidationPolicy {
    pub current_epoch: u64,
    pub check_role: bool,
    pub required_role: u8,
    pub revoked_certificate_ids: Vec<u64>,
    pub revoked_members: Vec<u32>,
}

impl CertificateValidationPolicy {
    /// Build a default policy for a given current epoch.
    pub fn new(current_epoch: u64) -> Self {
        CertificateValidationPolicy {
            current_epoch,
            check_role: false,
            required_role: 0,
            revoked_certificate_ids: Vec::new(),
            revoked_members: Vec::new(),
        }
    }
}

/// Local member state: one key pair + one certificate + a used flag.
#[derive(Clone, Debug)]
struct CertifiedKey {
    key_pair: OneTimeKeyPair,
    certificate: MemberCertificate,
    used: bool,
}

/// Full member signing state.
#[derive(Clone, Debug)]
pub struct MemberSK {
    pub member_id: u32,
    member_seed: [u8; N],
    certified_keys: Vec<CertifiedKey>,
    next_key_id: u32,
}

/// Final group signature = certificate + WOTS+ signature.
#[derive(Clone, Debug)]
pub struct GroupSignature {
    pub certificate: MemberCertificate,
    pub wots_signature: WotsSig,
}

pub const GROUP_SIG_BYTES: usize = 8 + 4 + 4 + 8 + 8 + 1 + N + N + SIG_BYTES + WOTS_LEN * N;

/// Public verification key for the group system.
#[derive(Clone, Debug)]
pub struct GroupPK {
    pub manager_pk: SphincsPK,
}

impl GroupPK {
    pub fn as_sphincs_pk(&self) -> &SphincsPK {
        &self.manager_pk
    }
}

/// Manager secret state.
#[derive(Clone, Debug)]
pub struct GroupManagerKey {
    signing_sk: SphincsSK,
    signing_pk: SphincsPK,
    max_members: u32,
    next_member_id: u32,
    next_certificate_id: u64,
    current_epoch: u64,
    default_validity_epochs: u64,
    issued_certificates: Vec<(u64, u32)>,
    member_seeds: Vec<(u32, [u8; N])>,
    member_roles: Vec<(u32, u8)>,
}

/// Small helper: hash multiple byte slices into one N-byte output.
fn hash32(parts: &[&[u8]]) -> [u8; N] {
    let mut h = Sha256::new();
    let mut i = 0usize;

    while i < parts.len() {
        h.update(parts[i]);
        i += 1;
    }

    let digest = h.finalize();
    let mut out = [0u8; N];
    out.copy_from_slice(&digest[..N]);
    out
}

/// Find the position of a member seed record in the manager.
fn find_member_seed_pos(manager: &GroupManagerKey, member_id: u32) -> Option<usize> {
    let mut i = 0usize;

    while i < manager.member_seeds.len() {
        if manager.member_seeds[i].0 == member_id {
            return Some(i);
        }
        i += 1;
    }

    None
}

/// Find the role of one member. If no role was set, return the default role 1.
fn get_member_role(manager: &GroupManagerKey, member_id: u32) -> u8 {
    let mut i = 0usize;

    while i < manager.member_roles.len() {
        if manager.member_roles[i].0 == member_id {
            return manager.member_roles[i].1;
        }
        i += 1;
    }

    1u8
}

/// Find the member id that belongs to one certificate id.
fn get_member_from_certificate_id(manager: &GroupManagerKey, certificate_id: u64) -> Option<u32> {
    let mut i = 0usize;

    while i < manager.issued_certificates.len() {
        if manager.issued_certificates[i].0 == certificate_id {
            return Some(manager.issued_certificates[i].1);
        }
        i += 1;
    }

    None
}

/// Check whether a revoked certificate list contains a given certificate id.
fn revoked_certificate_list_contains(list: &[u64], certificate_id: u64) -> bool {
    let mut i = 0usize;

    while i < list.len() {
        if list[i] == certificate_id {
            return true;
        }
        i += 1;
    }

    false
}

/// Check whether a revoked member list contains a given member id.
fn revoked_member_list_contains(list: &[u32], member_id: u32) -> bool {
    let mut i = 0usize;

    while i < list.len() {
        if list[i] == member_id {
            return true;
        }
        i += 1;
    }

    false
}

/// Hash an arbitrary message down to the fixed N-byte input expected here.
fn hash_message_for_wots(msg: &[u8]) -> [u8; N] {
    hash32(&[msg])
}

/// Build the ADRS used for one member's one-time WOTS key.
///
/// Here we bind:
/// - `member_id` into the tree address
/// - `key_id` into the keypair address
fn member_wots_adrs(member_id: u32, key_id: u32) -> Adrs {
    let mut adrs = Adrs::new(AdrsType::Wots);

    adrs.set_layer_address(0);
    adrs.set_tree_address(member_id as u64);
    adrs.set_keypair_address(key_id);

    adrs
}

/// Derive one WOTS+ key pair from the member seed and indices.
fn derive_wots_key_pair(member_seed: &[u8; N], member_id: u32, key_id: u32) -> OneTimeKeyPair {
    let member_id_bytes = member_id.to_be_bytes();
    let key_id_bytes = key_id.to_be_bytes();

    let sk_seed = hash32(&[
        &member_seed[..],
        &b"member-wots-sk"[..],
        &member_id_bytes[..],
        &key_id_bytes[..],
    ]);

    let pk_seed = hash32(&[
        &member_seed[..],
        &b"member-wots-pk"[..],
        &member_id_bytes[..],
        &key_id_bytes[..],
    ]);

    let adrs = member_wots_adrs(member_id, key_id);
    let wots_pk = wots::wots_pk_gen::<Sha256Hasher>(&sk_seed, &pk_seed, &adrs);

    let public_key = OneTimePublicKey {
        member_id,
        key_id,
        pk_seed,
        wots_pk,
    };

    OneTimeKeyPair {
        key_id,
        sk_seed,
        pk_seed,
        public_key,
    }
}

/// Serialise the exact certificate body that the manager signs.
fn serialise_certificate_body(
    certificate_id: u64,
    member_id: u32,
    key_id: u32,
    issued_epoch: u64,
    expiry_epoch: u64,
    role: u8,
    pk_seed: &[u8; N],
    wots_pk: &[u8; N],
) -> Vec<u8> {
    let mut out = Vec::new();

    out.extend_from_slice(&certificate_id.to_be_bytes());
    out.extend_from_slice(&member_id.to_be_bytes());
    out.extend_from_slice(&key_id.to_be_bytes());
    out.extend_from_slice(&issued_epoch.to_be_bytes());
    out.extend_from_slice(&expiry_epoch.to_be_bytes());
    out.push(role);
    out.extend_from_slice(pk_seed);
    out.extend_from_slice(wots_pk);

    out
}

/// Build one certificate for one WOTS+ public key.
fn make_certificate(
    manager: &mut GroupManagerKey,
    public_key: &OneTimePublicKey,
) -> MemberCertificate {
    let certificate_id = manager.next_certificate_id;
    manager.next_certificate_id += 1;

    let issued_epoch = manager.current_epoch;
    let expiry_epoch = if u64::MAX - issued_epoch < manager.default_validity_epochs {
        u64::MAX
    } else {
        issued_epoch + manager.default_validity_epochs
    };

    let role = get_member_role(manager, public_key.member_id);

    let cert_body = serialise_certificate_body(
        certificate_id,
        public_key.member_id,
        public_key.key_id,
        issued_epoch,
        expiry_epoch,
        role,
        &public_key.pk_seed,
        &public_key.wots_pk,
    );

    let manager_signature = slh_sign_fast::<Sha256Hasher>(&cert_body, &manager.signing_sk);

    manager
        .issued_certificates
        .push((certificate_id, public_key.member_id));

    MemberCertificate {
        certificate_id,
        member_id: public_key.member_id,
        key_id: public_key.key_id,
        issued_epoch,
        expiry_epoch,
        role,
        pk_seed: public_key.pk_seed,
        wots_pk: public_key.wots_pk,
        manager_signature,
    }
}

/// Append `count` new certified WOTS+ keys to one member.
fn append_new_certified_keys(manager: &mut GroupManagerKey, member: &mut MemberSK, count: usize) {
    let start = member.next_key_id;
    let mut offset = 0u32;

    while (offset as usize) < count {
        let key_id = start + offset;
        let key_pair = derive_wots_key_pair(&member.member_seed, member.member_id, key_id);
        let certificate = make_certificate(manager, &key_pair.public_key);

        member.certified_keys.push(CertifiedKey {
            key_pair,
            certificate,
            used: false,
        });
        offset += 1;
    }

    member.next_key_id = start + count as u32;
}

/// Generate manager keys and the group public key.
pub fn group_keygen() -> (GroupManagerKey, GroupPK) {
    let (signing_sk, signing_pk) = slh_keygen_fast::<Sha256Hasher>();

    let manager = GroupManagerKey {
        signing_sk,
        signing_pk: signing_pk.clone(),
        max_members: 1u32 << crate::params::HP,
        next_member_id: 0,
        next_certificate_id: 0,
        current_epoch: 0,
        default_validity_epochs: 64,
        issued_certificates: Vec::new(),
        member_seeds: Vec::new(),
        member_roles: Vec::new(),
    };

    let gpk = GroupPK {
        manager_pk: signing_pk,
    };

    (manager, gpk)
}

/// Add one new member and give them an initial batch of certified keys.
pub fn add_member(
    manager: &mut GroupManagerKey,
    initial_keys: usize,
) -> Result<MemberSK, GroupError> {
    if manager.next_member_id >= manager.max_members {
        return Err(GroupError::MemberLimitReached);
    }

    let member_id = manager.next_member_id;
    manager.next_member_id += 1;

    let mut member_seed = [0u8; N];
    OsRng.fill_bytes(&mut member_seed);

    manager.member_seeds.push((member_id, member_seed));
    manager.member_roles.push((member_id, 1));

    let mut member = MemberSK {
        member_id,
        member_seed,
        certified_keys: Vec::new(),
        next_key_id: 0,
    };

    append_new_certified_keys(manager, &mut member, initial_keys);

    Ok(member)
}

/// Rebuild a member signing key from manager state.
pub fn derive_member_key(
    manager: &mut GroupManagerKey,
    member_id: u32,
    initial_keys: usize,
) -> Result<MemberSK, GroupError> {
    let Some(pos) = find_member_seed_pos(manager, member_id) else {
        return Err(GroupError::UnknownMember);
    };

    let member_seed = manager.member_seeds[pos].1;

    let mut member = MemberSK {
        member_id,
        member_seed,
        certified_keys: Vec::new(),
        next_key_id: 0,
    };

    append_new_certified_keys(manager, &mut member, initial_keys);

    Ok(member)
}

/// Issue more certified WOTS+ keys for an existing member.
pub fn certify_new_keys_for_member(
    manager: &mut GroupManagerKey,
    member: &mut MemberSK,
    count: usize,
) -> Result<(), GroupError> {
    if find_member_seed_pos(manager, member.member_id).is_none() {
        return Err(GroupError::UnknownMember);
    }

    append_new_certified_keys(manager, member, count);

    Ok(())
}

/// Set the manager's current epoch.
pub fn set_manager_epoch(manager: &mut GroupManagerKey, epoch: u64) {
    manager.current_epoch = epoch;
}

/// Set the default certificate lifetime.
pub fn set_default_certificate_validity(manager: &mut GroupManagerKey, validity_epochs: u64) {
    manager.default_validity_epochs = validity_epochs;
}

/// Set the role of a member.
pub fn set_member_role(
    manager: &mut GroupManagerKey,
    member_id: u32,
    role: u8,
) -> Result<(), GroupError> {
    if find_member_seed_pos(manager, member_id).is_none() {
        return Err(GroupError::UnknownMember);
    }

    let mut i = 0usize;
    while i < manager.member_roles.len() {
        if manager.member_roles[i].0 == member_id {
            manager.member_roles[i].1 = role;
            return Ok(());
        }
        i += 1;
    }

    manager.member_roles.push((member_id, role));
    Ok(())
}

impl MemberSK {
    /// Count how many certified one-time keys remain unused.
    pub fn remaining_signatures(&self) -> usize {
        let mut count = 0usize;
        let mut i = 0usize;

        while i < self.certified_keys.len() {
            if !self.certified_keys[i].used {
                count += 1;
            }
            i += 1;
        }

        count
    }
}

/// Verify only the manager's SPHINCS+ signature on the certificate.
pub fn verify_manager_certificate_signature(
    certificate: &MemberCertificate,
    gpk: &GroupPK,
) -> bool {
    let cert_body = serialise_certificate_body(
        certificate.certificate_id,
        certificate.member_id,
        certificate.key_id,
        certificate.issued_epoch,
        certificate.expiry_epoch,
        certificate.role,
        &certificate.pk_seed,
        &certificate.wots_pk,
    );

    slh_verify::<Sha256Hasher>(
        &cert_body,
        &certificate.manager_signature,
        gpk.as_sphincs_pk(),
    )
}

/// Check whether the certificate matches the expected member/key binding.
pub fn verify_certificate_binding(
    certificate: &MemberCertificate,
    expected_member_id: u32,
    expected_key_id: u32,
) -> bool {
    certificate.member_id == expected_member_id && certificate.key_id == expected_key_id
}

/// Check certificate metadata against a verification policy.
pub fn verify_certificate_metadata(
    certificate: &MemberCertificate,
    policy: &CertificateValidationPolicy,
) -> bool {
    if certificate.issued_epoch > certificate.expiry_epoch {
        return false;
    }

    if policy.current_epoch < certificate.issued_epoch {
        return false;
    }

    if policy.current_epoch > certificate.expiry_epoch {
        return false;
    }

    if policy.check_role && certificate.role != policy.required_role {
        return false;
    }

    if revoked_certificate_list_contains(
        &policy.revoked_certificate_ids,
        certificate.certificate_id,
    ) {
        return false;
    }

    if revoked_member_list_contains(&policy.revoked_members, certificate.member_id) {
        return false;
    }

    true
}

/// Full certificate check = manager signature + metadata policy.
pub fn verify_certificate(
    certificate: &MemberCertificate,
    gpk: &GroupPK,
    policy: &CertificateValidationPolicy,
) -> bool {
    verify_manager_certificate_signature(certificate, gpk)
        && verify_certificate_metadata(certificate, policy)
}

/// Sign with a specific certified key index.
pub fn group_sign_with_key_index(
    msg: &[u8],
    member: &mut MemberSK,
    key_index: usize,
) -> Result<GroupSignature, GroupError> {
    if key_index >= member.certified_keys.len() {
        return Err(GroupError::BadKeyIndex);
    }

    let certified_key = &mut member.certified_keys[key_index];
    if certified_key.used {
        return Err(GroupError::NoUnusedCertifiedKey);
    }

    let msg_digest = hash_message_for_wots(msg);
    let adrs = member_wots_adrs(member.member_id, certified_key.key_pair.key_id);

    let wots_signature = wots::wots_sign::<Sha256Hasher>(
        &msg_digest,
        &certified_key.key_pair.sk_seed,
        &certified_key.key_pair.pk_seed,
        &adrs,
    );

    certified_key.used = true;

    Ok(GroupSignature {
        certificate: certified_key.certificate.clone(),
        wots_signature,
    })
}

/// Sign with the first unused certified key.
pub fn group_sign(msg: &[u8], member: &mut MemberSK) -> Result<GroupSignature, GroupError> {
    let mut i = 0usize;

    while i < member.certified_keys.len() {
        if !member.certified_keys[i].used {
            return group_sign_with_key_index(msg, member, i);
        }
        i += 1;
    }

    Err(GroupError::NoUnusedCertifiedKey)
}

/// Verify using a very small default policy.
pub fn group_verify(msg: &[u8], signature: &GroupSignature, gpk: &GroupPK) -> bool {
    let policy = CertificateValidationPolicy::new(signature.certificate.issued_epoch);
    group_verify_with_policy(msg, signature, gpk, &policy)
}

/// Verify the full group signature under a given policy.
pub fn group_verify_with_policy(
    msg: &[u8],
    signature: &GroupSignature,
    gpk: &GroupPK,
    policy: &CertificateValidationPolicy,
) -> bool {
    if !verify_certificate(&signature.certificate, gpk, policy) {
        return false;
    }

    let msg_digest = hash_message_for_wots(msg);
    let member_id = signature.certificate.member_id;
    let key_id = signature.certificate.key_id;
    let adrs = member_wots_adrs(member_id, key_id);

    let pk_from_sig = wots::wots_pk_from_sig::<Sha256Hasher>(
        &signature.wots_signature,
        &msg_digest,
        &signature.certificate.pk_seed,
        &adrs,
    );

    pk_from_sig == signature.certificate.wots_pk
}

/// Manager-side signer identification.
pub fn group_identify_member(
    msg: &[u8],
    signature: &GroupSignature,
    manager: &GroupManagerKey,
) -> Option<u32> {
    let temp_gpk = GroupPK {
        manager_pk: manager.signing_pk.clone(),
    };

    if !group_verify(msg, signature, &temp_gpk) {
        return None;
    }

    let expected = get_member_from_certificate_id(manager, signature.certificate.certificate_id)?;
    if expected != signature.certificate.member_id {
        return None;
    }

    Some(expected)
}

/// Serialise the full group signature.
pub fn serialise_group_sig(sig: &GroupSignature) -> Vec<u8> {
    let mut out = Vec::new();

    out.extend_from_slice(&sig.certificate.certificate_id.to_be_bytes());
    out.extend_from_slice(&sig.certificate.member_id.to_be_bytes());
    out.extend_from_slice(&sig.certificate.key_id.to_be_bytes());
    out.extend_from_slice(&sig.certificate.issued_epoch.to_be_bytes());
    out.extend_from_slice(&sig.certificate.expiry_epoch.to_be_bytes());
    out.push(sig.certificate.role);
    out.extend_from_slice(&sig.certificate.pk_seed);
    out.extend_from_slice(&sig.certificate.wots_pk);

    let manager_sig_bytes = serialise_sig(&sig.certificate.manager_signature);
    out.extend_from_slice(&manager_sig_bytes);

    let mut i = 0usize;
    while i < WOTS_LEN {
        out.extend_from_slice(&sig.wots_signature[i]);
        i += 1;
    }

    out
}

/// Read one big-endian u64 from `bytes` and move `pos` forward.
fn read_u64_at(bytes: &[u8], pos: &mut usize) -> Option<u64> {
    if *pos + 8 > bytes.len() {
        return None;
    }

    let mut out = [0u8; 8];
    out.copy_from_slice(&bytes[*pos..*pos + 8]);
    *pos += 8;

    Some(u64::from_be_bytes(out))
}

/// Read one big-endian u32 from `bytes` and move `pos` forward.
fn read_u32_at(bytes: &[u8], pos: &mut usize) -> Option<u32> {
    if *pos + 4 > bytes.len() {
        return None;
    }

    let mut out = [0u8; 4];
    out.copy_from_slice(&bytes[*pos..*pos + 4]);
    *pos += 4;

    Some(u32::from_be_bytes(out))
}

/// Read one N-byte array from `bytes` and move `pos` forward.
fn read_n_array_at(bytes: &[u8], pos: &mut usize) -> Option<[u8; N]> {
    if *pos + N > bytes.len() {
        return None;
    }

    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[*pos..*pos + N]);
    *pos += N;

    Some(out)
}

/// Deserialise a full group signature from raw bytes.
pub fn deserialise_group_sig(bytes: &[u8]) -> Option<GroupSignature> {
    if bytes.len() != GROUP_SIG_BYTES {
        return None;
    }

    let mut pos = 0usize;

    let certificate_id = read_u64_at(bytes, &mut pos)?;
    let member_id = read_u32_at(bytes, &mut pos)?;
    let key_id = read_u32_at(bytes, &mut pos)?;
    let issued_epoch = read_u64_at(bytes, &mut pos)?;
    let expiry_epoch = read_u64_at(bytes, &mut pos)?;

    if pos >= bytes.len() {
        return None;
    }
    let role = bytes[pos];
    pos += 1;

    let pk_seed = read_n_array_at(bytes, &mut pos)?;
    let wots_pk = read_n_array_at(bytes, &mut pos)?;

    if pos + SIG_BYTES > bytes.len() {
        return None;
    }
    let manager_signature = deserialise_sig(&bytes[pos..pos + SIG_BYTES])?;
    pos += SIG_BYTES;

    let mut wots_signature = [[0u8; N]; WOTS_LEN];
    let mut i = 0usize;
    while i < WOTS_LEN {
        wots_signature[i] = read_n_array_at(bytes, &mut pos)?;
        i += 1;
    }

    Some(GroupSignature {
        certificate: MemberCertificate {
            certificate_id,
            member_id,
            key_id,
            issued_epoch,
            expiry_epoch,
            role,
            pk_seed,
            wots_pk,
            manager_signature,
        },
        wots_signature,
    })
}

/// Verify a raw encoded signature.
pub fn group_verify_raw(msg: &[u8], sig_bytes: &[u8], gpk: &GroupPK) -> bool {
    let Some(sig) = deserialise_group_sig(sig_bytes) else {
        return false;
    };

    group_verify(msg, &sig, gpk)
}

/// Verify a raw encoded signature with policy.
pub fn group_verify_raw_with_policy(
    msg: &[u8],
    sig_bytes: &[u8],
    gpk: &GroupPK,
    policy: &CertificateValidationPolicy,
) -> bool {
    let Some(sig) = deserialise_group_sig(sig_bytes) else {
        return false;
    };

    group_verify_with_policy(msg, &sig, gpk, policy)
}

/// Identify a signer from raw bytes.
pub fn group_identify_member_raw(
    msg: &[u8],
    sig_bytes: &[u8],
    manager: &GroupManagerKey,
) -> Option<u32> {
    let sig = deserialise_group_sig(sig_bytes)?;
    group_identify_member(msg, &sig, manager)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_roundtrip_and_identify_member() {
        let (mut manager, gpk) = group_keygen();
        let mut member = add_member(&mut manager, 2).expect("member should be created");
        let member_id = member.member_id;

        let sig = group_sign(b"group roundtrip", &mut member).expect("signing should succeed");

        assert!(group_verify(b"group roundtrip", &sig, &gpk));
        assert_eq!(
            group_identify_member(b"group roundtrip", &sig, &manager),
            Some(member_id)
        );
        assert_eq!(member.remaining_signatures(), 1);
    }

    #[test]
    fn group_specific_key_index_is_one_time() {
        let (mut manager, gpk) = group_keygen();
        let mut member = add_member(&mut manager, 3).expect("member should be created");

        let sig = group_sign_with_key_index(b"indexed", &mut member, 2)
            .expect("indexed signing should succeed");

        assert!(group_verify(b"indexed", &sig, &gpk));
        assert_eq!(member.remaining_signatures(), 2);
        assert!(matches!(
            group_sign_with_key_index(b"indexed reuse", &mut member, 2),
            Err(GroupError::NoUnusedCertifiedKey)
        ));
        assert!(matches!(
            group_sign_with_key_index(b"bad index", &mut member, 99),
            Err(GroupError::BadKeyIndex)
        ));
    }

    #[test]
    fn group_policy_enforces_role_expiry_and_revocation() {
        let (mut manager, gpk) = group_keygen();
        set_manager_epoch(&mut manager, 10);
        set_default_certificate_validity(&mut manager, 1);

        let mut member = add_member(&mut manager, 0).expect("member should be created");
        let member_id = member.member_id;
        set_member_role(&mut manager, member_id, 7).expect("role should be updated");
        certify_new_keys_for_member(&mut manager, &mut member, 1)
            .expect("new key should be certified");

        let sig = group_sign(b"policy test", &mut member).expect("signing should succeed");

        let mut ok_policy = CertificateValidationPolicy::new(10);
        ok_policy.check_role = true;
        ok_policy.required_role = 7;
        assert!(group_verify_with_policy(
            b"policy test",
            &sig,
            &gpk,
            &ok_policy
        ));

        let mut wrong_role = ok_policy.clone();
        wrong_role.required_role = 1;
        assert!(!group_verify_with_policy(
            b"policy test",
            &sig,
            &gpk,
            &wrong_role
        ));

        let expired = CertificateValidationPolicy {
            current_epoch: 12,
            ..ok_policy.clone()
        };
        assert!(!group_verify_with_policy(
            b"policy test",
            &sig,
            &gpk,
            &expired
        ));

        let mut revoked_cert = ok_policy.clone();
        revoked_cert
            .revoked_certificate_ids
            .push(sig.certificate.certificate_id);
        assert!(!group_verify_with_policy(
            b"policy test",
            &sig,
            &gpk,
            &revoked_cert
        ));

        let mut revoked_member = ok_policy;
        revoked_member.revoked_members.push(member_id);
        assert!(!group_verify_with_policy(
            b"policy test",
            &sig,
            &gpk,
            &revoked_member
        ));
    }

    #[test]
    fn group_raw_roundtrip_and_tamper_rejection() {
        let (mut manager, gpk) = group_keygen();
        let mut member = add_member(&mut manager, 1).expect("member should be created");
        let sig = group_sign(b"raw group", &mut member).expect("signing should succeed");
        let raw = serialise_group_sig(&sig);

        assert_eq!(raw.len(), GROUP_SIG_BYTES);
        assert!(group_verify_raw(b"raw group", &raw, &gpk));

        let parsed = deserialise_group_sig(&raw).expect("raw signature should parse");
        assert_eq!(
            parsed.certificate.certificate_id,
            sig.certificate.certificate_id
        );
        assert_eq!(parsed.certificate.member_id, sig.certificate.member_id);
        assert_eq!(parsed.certificate.key_id, sig.certificate.key_id);

        let mut tampered = raw.clone();
        tampered[GROUP_SIG_BYTES - 1] ^= 0x01;
        assert!(!group_verify_raw(b"raw group", &tampered, &gpk));

        let truncated = &raw[..raw.len() - 1];
        assert!(!group_verify_raw(b"raw group", truncated, &gpk));
    }

    #[test]
    fn derive_member_key_supports_existing_members() {
        let (mut manager, gpk) = group_keygen();
        let member = add_member(&mut manager, 0).expect("member should be created");
        let member_id = member.member_id;

        let mut derived = derive_member_key(&mut manager, member_id, 1)
            .expect("existing member should be derivable");
        let sig = group_sign(b"derived member", &mut derived).expect("derived member should sign");

        assert!(group_verify(b"derived member", &sig, &gpk));
        assert_eq!(
            group_identify_member(b"derived member", &sig, &manager),
            Some(member_id)
        );
        assert!(matches!(
            derive_member_key(&mut manager, member_id + 1_000, 1),
            Err(GroupError::UnknownMember)
        ));
        assert!(matches!(
            set_member_role(&mut manager, member_id + 1_000, 3),
            Err(GroupError::UnknownMember)
        ));
    }

    #[test]
    fn identify_member_requires_the_original_manager() {
        let (mut manager_a, gpk_a) = group_keygen();
        let (manager_b, _gpk_b) = group_keygen();
        let mut member = add_member(&mut manager_a, 1).expect("member should be created");
        let member_id = member.member_id;

        let sig = group_sign(b"manager identity", &mut member).expect("signing should succeed");

        assert!(group_verify(b"manager identity", &sig, &gpk_a));
        assert_eq!(
            group_identify_member(b"manager identity", &sig, &manager_a),
            Some(member_id)
        );
        assert_eq!(
            group_identify_member(b"manager identity", &sig, &manager_b),
            None
        );
    }
}
