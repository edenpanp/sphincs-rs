use sphincs_rs::group::{
    CertificateValidationPolicy, add_member, certify_new_keys_for_member, group_identify_member,
    group_keygen, group_sign, group_verify, group_verify_raw, group_verify_with_policy,
    serialise_group_sig, set_manager_epoch, set_member_role,
};
use sphincs_rs::hash::{RawSha256, Sha256Hasher};
use sphincs_rs::params::N;
use sphincs_rs::sphincs::{
    SIG_BYTES, SphincsPK, deserialise_sig, serialise_sig, slh_keygen_fast, slh_sign_fast,
    slh_sign_raw_fast, slh_verify, slh_verify_raw,
};

macro_rules! test_with_hasher {
    ($H:ty, $name:literal) => {{
        let tag = $name;
        let (sk, pk) = slh_keygen_fast::<$H>();
        let msg = b"UNSW 26T1 Applied Cryptography integration test";

        let sig = slh_sign_fast::<$H>(msg, &sk);
        assert!(slh_verify::<$H>(msg, &sig, &pk), "[{tag}] valid sig rejected");
        assert!(
            !slh_verify::<$H>(b"wrong", &sig, &pk),
            "[{tag}] wrong message accepted"
        );

        let raw = serialise_sig(&sig);
        assert_eq!(raw.len(), SIG_BYTES, "[{tag}] wrong serialised length");
        let sig2 = deserialise_sig(&raw).expect("signature should round-trip");
        assert!(
            slh_verify::<$H>(msg, &sig2, &pk),
            "[{tag}] deserialised sig rejected"
        );

        let raw_sig = slh_sign_raw_fast::<$H>(msg, &sk);
        assert!(
            slh_verify_raw::<$H>(msg, &raw_sig, &pk),
            "[{tag}] raw API verify failed"
        );

        let sig_b = slh_sign_fast::<$H>(msg, &sk);
        assert_eq!(sig.r, sig_b.r, "[{tag}] R is not deterministic");

        let (_, pk2) = slh_keygen_fast::<$H>();
        assert!(
            !slh_verify::<$H>(msg, &sig, &pk2),
            "[{tag}] wrong public key accepted"
        );
    }};
}

#[test]
fn integration_raw_sha256() {
    test_with_hasher!(RawSha256, "RawSha256");
}

#[test]
fn integration_sha256_hasher() {
    test_with_hasher!(Sha256Hasher, "Sha256Hasher");
}

#[test]
fn integration_cross_hasher_rejects() {
    let msg = b"cross-hasher forgery attempt";
    let (sk_raw, pk_raw) = slh_keygen_fast::<RawSha256>();
    let raw_sig = slh_sign_raw_fast::<RawSha256>(msg, &sk_raw);
    let pk_sha = SphincsPK {
        pk_seed: pk_raw.pk_seed,
        pk_root: pk_raw.pk_root,
    };

    assert!(!slh_verify_raw::<Sha256Hasher>(msg, &raw_sig, &pk_sha));
}

#[test]
fn integration_empty_and_long_messages() {
    let (sk, pk) = slh_keygen_fast::<RawSha256>();

    let empty_sig = slh_sign_fast::<RawSha256>(b"", &sk);
    assert!(slh_verify::<RawSha256>(b"", &empty_sig, &pk));

    let long_msg = vec![0x42u8; 65_536];
    let long_sig = slh_sign_fast::<RawSha256>(&long_msg, &sk);
    assert!(slh_verify::<RawSha256>(&long_msg, &long_sig, &pk));
}

#[test]
fn integration_bit_flip_rejection() {
    let (sk, pk) = slh_keygen_fast::<RawSha256>();
    let msg = b"bit-flip rejection test";
    let raw = slh_sign_raw_fast::<RawSha256>(msg, &sk);

    let positions = [
        0,
        N,
        N + 100,
        N + 1_000,
        SIG_BYTES / 2,
        SIG_BYTES - 200,
        SIG_BYTES - 32,
        SIG_BYTES - 1,
    ];

    for pos in positions {
        let mut tampered = raw.clone();
        tampered[pos] ^= 0xFF;
        assert!(
            !slh_verify_raw::<RawSha256>(msg, &tampered, &pk),
            "bit flip at pos {pos} was not detected"
        );
    }
}

#[test]
fn integration_multiple_keypairs() {
    let msg = b"multi-keypair test";
    let pairs: Vec<_> = (0..3).map(|_| slh_keygen_fast::<RawSha256>()).collect();
    let sigs: Vec<_> = pairs
        .iter()
        .map(|(sk, _)| slh_sign_fast::<RawSha256>(msg, sk))
        .collect();

    for (i, ((_, own_pk), sig)) in pairs.iter().zip(sigs.iter()).enumerate() {
        assert!(
            slh_verify::<RawSha256>(msg, sig, own_pk),
            "keypair {i}: own signature failed"
        );
        for (j, (_, other_pk)) in pairs.iter().enumerate() {
            if i != j {
                assert!(
                    !slh_verify::<RawSha256>(msg, sig, other_pk),
                    "signature {i} accepted under public key {j}"
                );
            }
        }
    }
}

#[test]
fn sig_bytes_constant_correct() {
    use sphincs_rs::params::{A, D, HP, K, WOTS_LEN};

    let expected = N + K * (1 + A) * N + D * (WOTS_LEN + HP) * N;
    assert_eq!(SIG_BYTES, expected);
    assert_eq!(SIG_BYTES, 29_792);
}

#[test]
fn integration_group_public_api_roundtrip() {
    let (mut manager, gpk) = group_keygen();
    set_manager_epoch(&mut manager, 3);

    let mut member = add_member(&mut manager, 0).expect("member should be created");
    let member_id = member.member_id;
    set_member_role(&mut manager, member_id, 4).expect("role should be assigned");
    certify_new_keys_for_member(&mut manager, &mut member, 1)
        .expect("new key should be certified");

    let msg = b"group integration roundtrip";
    let sig = group_sign(msg, &mut member).expect("group signing should succeed");
    assert!(group_verify(msg, &sig, &gpk));

    let raw = serialise_group_sig(&sig);
    assert!(group_verify_raw(msg, &raw, &gpk));
    assert_eq!(group_identify_member(msg, &sig, &manager), Some(member_id));

    let mut policy = CertificateValidationPolicy::new(3);
    policy.check_role = true;
    policy.required_role = 4;
    assert!(group_verify_with_policy(msg, &sig, &gpk, &policy));

    let mut wrong_role = policy.clone();
    wrong_role.required_role = 1;
    assert!(!group_verify_with_policy(msg, &sig, &gpk, &wrong_role));
}
