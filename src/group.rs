//! cert-based SPHINCS+ + WOTS group signature (basic features)
//!
//! idea is not complicated:
//! - member locally generates a bunch of WOTS one-time keys
//! - manager does NOT touch private keys, only signs the public part
//! - when signing, just pick one unused key + its cert
//! - verifier checks two things: cert is valid + WOTS sig is valid
//!
//! cert does NOT include member_id (for anonymity)
//! only manager keeps that mapping internally (for open)
//!
//! this is more like a clean demo implementation, not super optimized

use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};

use crate::adrs::{Adrs, AdrsType};
use crate::hash::SphincsHasher;
use crate::params::{N, WOTS_LEN};
use crate::sphincs::{
    SIG_BYTES, SphincsPK, SphincsSK, SphincsSignature, deserialise_sig, serialise_sig,
    slh_keygen_fast, slh_sign_fast, slh_verify,
};
use crate::wots::{self, WotsSig};

const CERT_DOMAIN_SEP: &[u8] = b"sphincs-rs/group-cert/v2";
const GROUP_SIG_VERSION: u8 = 1;

/// fixed size for easier parsing (no dynamic stuff)
pub const GROUP_SIGNATURE_BYTES: usize =
    1 + 8 + 4 + N + N + SIG_BYTES + (WOTS_LEN * N);

/// some basic errors for this flow
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupError {
    EmptyBatch,
    BatchTooLarge,
    CertificateCountMismatch,
    CertificateMismatch,
    CertifiedKeyUnavailable,
    NoUnusedCertifiedKey,
    InvalidSignatureBytes,
}

/// public half of one one-time WOTS+ keypair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OneTimePublicKey {
    pub key_id: u32,
    pub pk_seed: [u8; N],
    pub wots_pk: [u8; N],
}

#[derive(Clone)]
struct OneTimeKeyPair {
    sk_seed: [u8; N],
    public_key: OneTimePublicKey,
}

/// what member sends to manager
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberCertificationRequest {
    pub member_id: u32,
    pub keys: Vec<OneTimePublicKey>,
}

/// member-side temp batch before cert
pub struct MemberKeyBatch {
    pub member_id: u32,
    keys: Vec<OneTimeKeyPair>,
}

impl MemberKeyBatch {
    /// strip private part, keep only what manager needs
    pub fn certification_request(&self) -> MemberCertificationRequest {
        MemberCertificationRequest {
            member_id: self.member_id,
            keys: self.keys.iter().map(|key| key.public_key).collect(),
        }
    }

    pub fn batch_size(&self) -> usize {
        self.keys.len()
    }
}

/// manager-signed cert
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberCertificate {
    pub certificate_id: u64,
    pub key: OneTimePublicKey,
    pub manager_signature: SphincsSignature,
}

#[derive(Clone)]
struct CertifiedKey {
    key_pair: OneTimeKeyPair,
    certificate: MemberCertificate,
    used: bool,
}

/// member state after attaching certs
#[derive(Clone)]
pub struct MemberSK {
    pub member_id: u32,
    certified_keys: Vec<CertifiedKey>,
}

impl MemberSK {
    pub fn remaining_signatures(&self) -> usize {
        self.certified_keys.iter().filter(|key| !key.used).count()
    }

    pub fn total_certified_keys(&self) -> usize {
        self.certified_keys.len()
    }
}

/// manager-side record (for opening)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IssuedCertificateRecord {
    pub certificate_id: u64,
    pub member_id: u32,
    pub key: OneTimePublicKey,
}

pub struct GroupManagerKey {
    signing_key: SphincsSK,
    next_certificate_id: u64,
    issued_certificates: Vec<IssuedCertificateRecord>,
}

impl GroupManagerKey {
    pub fn issued_certificates(&self) -> &[IssuedCertificateRecord] {
        &self.issued_certificates
    }
}

pub struct GroupPK {
    manager_pk: SphincsPK,
}

impl GroupPK {
    pub fn as_sphincs_pk(&self) -> &SphincsPK {
        &self.manager_pk
    }
}

/// final signature: cert + WOTS
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupSignature {
    pub certificate: MemberCertificate,
    pub wots_signature: WotsSig,
}

fn hash_message_for_wots(msg: &[u8]) -> [u8; N] {
    // WOTS only signs N bytes, so compress first
    let digest = Sha256::digest(msg);
    let mut out = [0u8; N];
    out.copy_from_slice(&digest[..N]);
    out
}

fn wots_adrs(key_id: u32) -> Adrs {
    // keep things simple: layer/tree fixed
    let mut adrs = Adrs::new(AdrsType::Wots);
    adrs.set_layer_address(0);
    adrs.set_tree_address(0);
    adrs.set_keypair_address(key_id);
    adrs
}

fn serialise_certificate_body(certificate_id: u64, key: &OneTimePublicKey) -> Vec<u8> {
    // no member_id here (privacy)
    let mut out =
        Vec::with_capacity(CERT_DOMAIN_SEP.len() + 8 + 4 + N + N);
    out.extend_from_slice(CERT_DOMAIN_SEP);
    out.extend_from_slice(&certificate_id.to_be_bytes());
    out.extend_from_slice(&key.key_id.to_be_bytes());
    out.extend_from_slice(&key.pk_seed);
    out.extend_from_slice(&key.wots_pk);
    out
}

/// manager gen SPHINCS+ keypair for signing certs
pub fn group_keygen<S: SphincsHasher>() -> (GroupManagerKey, GroupPK) {
    let (signing_key, manager_pk) = slh_keygen_fast::<S>();
    let manager = GroupManagerKey {
        signing_key,
        next_certificate_id: 0,
        issued_certificates: Vec::new(),
    };
    let gpk = GroupPK { manager_pk };
    (manager, gpk)
}

/// member local gen a batch of one-time WOTS+ keys
pub fn generate_member_key_batch<S: SphincsHasher>(
    member_id: u32,
    batch_size: usize,
) -> Result<MemberKeyBatch, GroupError> {
    if batch_size == 0 {
        return Err(GroupError::EmptyBatch);
    }
    if batch_size > u32::MAX as usize {
        return Err(GroupError::BatchTooLarge);
    }

    let mut keys = Vec::with_capacity(batch_size);
    for key_id in 0..batch_size {
        // every WOTS keypair gets fresh seeds
        let mut sk_seed = [0u8; N];
        let mut pk_seed = [0u8; N];
        OsRng.fill_bytes(&mut sk_seed);
        OsRng.fill_bytes(&mut pk_seed);

        let public_key = OneTimePublicKey {
            key_id: key_id as u32,
            pk_seed,
            wots_pk: wots::wots_pk_gen::<S>(&sk_seed, &pk_seed, &wots_adrs(key_id as u32)),
        };

        keys.push(OneTimeKeyPair { sk_seed, public_key });
    }

    Ok(MemberKeyBatch { member_id, keys })
}

/// manager signs every one-time public key in the batch
pub fn certify_key_batch<S: SphincsHasher>(
    manager: &mut GroupManagerKey,
    request: &MemberCertificationRequest,
) -> Result<Vec<MemberCertificate>, GroupError> {
    if request.keys.is_empty() {
        return Err(GroupError::EmptyBatch);
    }

    let mut certificates = Vec::with_capacity(request.keys.len());
    for key in &request.keys {
        let certificate_id = manager.next_certificate_id;
        manager.next_certificate_id = manager
            .next_certificate_id
            .checked_add(1)
            .expect("certificate id overflowed");

        let certificate_body = serialise_certificate_body(certificate_id, key);
        // manager signs only cert body, not member_id
        let manager_signature = slh_sign_fast::<S>(&certificate_body, &manager.signing_key);

        manager.issued_certificates.push(IssuedCertificateRecord {
            certificate_id,
            member_id: request.member_id,
            key: *key,
        });

        certificates.push(MemberCertificate {
            certificate_id,
            key: *key,
            manager_signature,
        });
    }

    Ok(certificates)
}

/// Bind returned certs back to the member's private batch.
///
/// We keep it simple here:
/// `certificates` should stay in the same order as the request.
pub fn attach_certificates(
    batch: MemberKeyBatch,
    certificates: Vec<MemberCertificate>,
) -> Result<MemberSK, GroupError> {
    if batch.keys.len() != certificates.len() {
        return Err(GroupError::CertificateCountMismatch);
    }

    let mut certified_keys = Vec::with_capacity(batch.keys.len());
    for (key_pair, certificate) in batch.keys.into_iter().zip(certificates) {
        if key_pair.public_key != certificate.key {
            return Err(GroupError::CertificateMismatch);
        }
        certified_keys.push(CertifiedKey {
            key_pair,
            certificate,
            used: false,
        });
    }

    Ok(MemberSK {
        member_id: batch.member_id,
        certified_keys,
    })
}

pub fn certify_member_batch<S: SphincsHasher>(
    manager: &mut GroupManagerKey,
    batch: MemberKeyBatch,
) -> Result<MemberSK, GroupError> {
    let request = batch.certification_request();
    let certificates = certify_key_batch::<S>(manager, &request)?;
    attach_certificates(batch, certificates)
}

/// sign with a specific certified one-time key
///
/// if caller wants to manually pick "which unused key", use this one
pub fn group_sign_with_key_index<S: SphincsHasher>(
    msg: &[u8],
    member: &mut MemberSK,
    key_index: usize,
) -> Result<GroupSignature, GroupError> {
    let certified_key = member
        .certified_keys
        .get_mut(key_index)
        .ok_or(GroupError::CertifiedKeyUnavailable)?;

    if certified_key.used {
        return Err(GroupError::CertifiedKeyUnavailable);
    }

    // WOTS is one-time, so once we sign, this slot is considered burned
    let msg_digest = hash_message_for_wots(msg);
    let wots_signature = wots::wots_sign::<S>(
        &msg_digest,
        &certified_key.key_pair.sk_seed,
        &certified_key.key_pair.public_key.pk_seed,
        &wots_adrs(certified_key.key_pair.public_key.key_id),
    );

    certified_key.used = true;

    Ok(GroupSignature {
        certificate: certified_key.certificate.clone(),
        wots_signature,
    })
}

/// sign with the first unused certified one-time key
pub fn group_sign<S: SphincsHasher>(
    msg: &[u8],
    member: &mut MemberSK,
) -> Result<GroupSignature, GroupError> {
    let Some(key_index) = member.certified_keys.iter().position(|key| !key.used) else {
        return Err(GroupError::NoUnusedCertifiedKey);
    };

    group_sign_with_key_index::<S>(msg, member, key_index)
}

/// verify both layers:
/// 1. manager cert
/// 2. WOTS sig under the certified one-time public key
pub fn group_verify<S: SphincsHasher>(
    msg: &[u8],
    signature: &GroupSignature,
    gpk: &GroupPK,
) -> bool {
    let certificate_body =
        serialise_certificate_body(signature.certificate.certificate_id, &signature.certificate.key);
    if !slh_verify::<S>(
        &certificate_body,
        &signature.certificate.manager_signature,
        gpk.as_sphincs_pk(),
    ) {
        return false;
    }

    let msg_digest = hash_message_for_wots(msg);
    let recovered_pk = wots::wots_pk_from_sig::<S>(
        &signature.wots_signature,
        &msg_digest,
        &signature.certificate.key.pk_seed,
        &wots_adrs(signature.certificate.key.key_id),
    );

    recovered_pk == signature.certificate.key.wots_pk
}

/// serialize group sig to raw bytes
pub fn serialise_group_sig(signature: &GroupSignature) -> Vec<u8> {
    let mut out = Vec::with_capacity(GROUP_SIGNATURE_BYTES);
    out.push(GROUP_SIG_VERSION);
    out.extend_from_slice(&signature.certificate.certificate_id.to_be_bytes());
    out.extend_from_slice(&signature.certificate.key.key_id.to_be_bytes());
    out.extend_from_slice(&signature.certificate.key.pk_seed);
    out.extend_from_slice(&signature.certificate.key.wots_pk);
    out.extend_from_slice(&serialise_sig(&signature.certificate.manager_signature));
    for element in &signature.wots_signature {
        out.extend_from_slice(element);
    }
    debug_assert_eq!(out.len(), GROUP_SIGNATURE_BYTES);
    out
}

/// parse raw bytes back into a group sig
pub fn deserialise_group_sig(bytes: &[u8]) -> Option<GroupSignature> {
    if bytes.len() != GROUP_SIGNATURE_BYTES || bytes.first().copied()? != GROUP_SIG_VERSION {
        return None;
    }

    let mut pos = 1usize;
    let read_u64 = |bytes: &[u8], pos: &mut usize| -> u64 {
        let mut out = [0u8; 8];
        out.copy_from_slice(&bytes[*pos..*pos + 8]);
        *pos += 8;
        u64::from_be_bytes(out)
    };
    let read_u32 = |bytes: &[u8], pos: &mut usize| -> u32 {
        let mut out = [0u8; 4];
        out.copy_from_slice(&bytes[*pos..*pos + 4]);
        *pos += 4;
        u32::from_be_bytes(out)
    };
    let read_n = |bytes: &[u8], pos: &mut usize| -> [u8; N] {
        let mut out = [0u8; N];
        out.copy_from_slice(&bytes[*pos..*pos + N]);
        *pos += N;
        out
    };

    let certificate_id = read_u64(bytes, &mut pos);
    let key_id = read_u32(bytes, &mut pos);
    let pk_seed = read_n(bytes, &mut pos);
    let wots_pk = read_n(bytes, &mut pos);

    let manager_signature = deserialise_sig(&bytes[pos..pos + SIG_BYTES])?;
    pos += SIG_BYTES;

    let mut wots_signature = [[0u8; N]; WOTS_LEN];
    for element in &mut wots_signature {
        *element = read_n(bytes, &mut pos);
    }

    Some(GroupSignature {
        certificate: MemberCertificate {
            certificate_id,
            key: OneTimePublicKey {
                key_id,
                pk_seed,
                wots_pk,
            },
            manager_signature,
        },
        wots_signature,
    })
}

/// verify directly from raw bytes
pub fn group_verify_raw<S: SphincsHasher>(
    msg: &[u8],
    sig_bytes: &[u8],
    gpk: &GroupPK,
) -> bool {
    match deserialise_group_sig(sig_bytes) {
        Some(signature) => group_verify::<S>(msg, &signature, gpk),
        None => false,
    }
}

/// manager-only open
/// basically just use cert id + key info to look up who got this cert before
pub fn group_open_signature(
    signature: &GroupSignature,
    manager: &GroupManagerKey,
) -> Option<u32> {
    manager
        .issued_certificates
        .iter()
        .find(|record| {
            record.certificate_id == signature.certificate.certificate_id
                && record.key == signature.certificate.key
        })
        .map(|record| record.member_id)
}

/// same idea as open, just another name
pub fn group_identify_member(
    signature: &GroupSignature,
    manager: &GroupManagerKey,
) -> Option<u32> {
    group_open_signature(signature, manager)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::RawSha256;

    #[test]
    fn certificate_flow_roundtrip() {
        let (mut manager, gpk) = group_keygen::<RawSha256>();
        let batch = generate_member_key_batch::<RawSha256>(7, 4).unwrap();
        let request = batch.certification_request();
        let certificates = certify_key_batch::<RawSha256>(&mut manager, &request).unwrap();
        let mut member = attach_certificates(batch, certificates).unwrap();

        let msg = b"certificate-based group signature";
        let signature = group_sign::<RawSha256>(msg, &mut member).unwrap();

        assert!(group_verify::<RawSha256>(msg, &signature, &gpk));
        assert_eq!(group_open_signature(&signature, &manager), Some(7));
        assert_eq!(member.remaining_signatures(), 3);
    }

    #[test]
    fn signing_consumes_unused_keys() {
        let (mut manager, gpk) = group_keygen::<RawSha256>();
        let batch = generate_member_key_batch::<RawSha256>(3, 2).unwrap();
        let mut member = certify_member_batch::<RawSha256>(&mut manager, batch).unwrap();

        let sig0 = group_sign::<RawSha256>(b"first", &mut member).unwrap();
        let sig1 = group_sign::<RawSha256>(b"second", &mut member).unwrap();

        assert!(group_verify::<RawSha256>(b"first", &sig0, &gpk));
        assert!(group_verify::<RawSha256>(b"second", &sig1, &gpk));
        assert_eq!(member.remaining_signatures(), 0);
        assert_eq!(
            group_sign::<RawSha256>(b"third", &mut member),
            Err(GroupError::NoUnusedCertifiedKey)
        );
    }

    #[test]
    fn signing_specific_key_index_works() {
        let (mut manager, gpk) = group_keygen::<RawSha256>();
        let batch = generate_member_key_batch::<RawSha256>(11, 3).unwrap();
        let mut member = certify_member_batch::<RawSha256>(&mut manager, batch).unwrap();

        let signature = group_sign_with_key_index::<RawSha256>(b"indexed", &mut member, 2).unwrap();

        assert!(group_verify::<RawSha256>(b"indexed", &signature, &gpk));
        assert_eq!(
            group_sign_with_key_index::<RawSha256>(b"reuse", &mut member, 2),
            Err(GroupError::CertifiedKeyUnavailable)
        );
        assert_eq!(member.remaining_signatures(), 2);
    }

    #[test]
    fn wrong_message_fails() {
        let (mut manager, gpk) = group_keygen::<RawSha256>();
        let batch = generate_member_key_batch::<RawSha256>(1, 1).unwrap();
        let mut member = certify_member_batch::<RawSha256>(&mut manager, batch).unwrap();

        let signature = group_sign::<RawSha256>(b"correct", &mut member).unwrap();
        assert!(!group_verify::<RawSha256>(b"wrong", &signature, &gpk));
    }

    #[test]
    fn tampered_certificate_fails() {
        let (mut manager, gpk) = group_keygen::<RawSha256>();
        let batch = generate_member_key_batch::<RawSha256>(5, 1).unwrap();
        let mut member = certify_member_batch::<RawSha256>(&mut manager, batch).unwrap();

        let signature = group_sign::<RawSha256>(b"hello", &mut member).unwrap();
        let mut tampered = signature.clone();
        tampered.certificate.key.wots_pk[0] ^= 0x01;

        assert!(!group_verify::<RawSha256>(b"hello", &tampered, &gpk));
    }

    #[test]
    fn raw_roundtrip_works() {
        let (mut manager, gpk) = group_keygen::<RawSha256>();
        let batch = generate_member_key_batch::<RawSha256>(9, 2).unwrap();
        let mut member = certify_member_batch::<RawSha256>(&mut manager, batch).unwrap();

        let signature = group_sign::<RawSha256>(b"raw", &mut member).unwrap();
        let raw = serialise_group_sig(&signature);

        assert_eq!(raw.len(), GROUP_SIGNATURE_BYTES);
        assert!(group_verify_raw::<RawSha256>(b"raw", &raw, &gpk));
    }

    #[test]
    fn attach_rejects_mismatched_certificates() {
        let (mut manager, _gpk) = group_keygen::<RawSha256>();
        let batch = generate_member_key_batch::<RawSha256>(13, 2).unwrap();
        let request = batch.certification_request();
        let mut certificates = certify_key_batch::<RawSha256>(&mut manager, &request).unwrap();
        certificates.swap(0, 1);

        assert!(matches!(
            attach_certificates(batch, certificates),
            Err(GroupError::CertificateMismatch)
        ));
    }

    #[test]
    fn identify_member_returns_none_for_unknown_certificate() {
        let (mut manager_a, _gpk_a) = group_keygen::<RawSha256>();
        let (mut manager_b, _gpk_b) = group_keygen::<RawSha256>();

        let batch = generate_member_key_batch::<RawSha256>(21, 1).unwrap();
        let mut member = certify_member_batch::<RawSha256>(&mut manager_a, batch).unwrap();
        let signature = group_sign::<RawSha256>(b"open", &mut member).unwrap();

        assert_eq!(group_identify_member(&signature, &manager_a), Some(21));
        assert_eq!(group_identify_member(&signature, &manager_b), None);

        let other_batch = generate_member_key_batch::<RawSha256>(22, 1).unwrap();
        let _ = certify_member_batch::<RawSha256>(&mut manager_b, other_batch).unwrap();
    }
}
