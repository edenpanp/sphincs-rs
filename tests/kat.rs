//! KAT (Known Answer Test) runner for SPHINCS+ SHA2-256s-simple.
//!
//! # What are KAT vectors?
//!
//! The NIST PQC submission process requires each candidate to ship a
//! deterministic test program that generates a `.rsp` file from a fixed
//! DRBG seed.  The resulting file lists (seed, pk, sk, msg, sm) tuples
//! that any conforming implementation must reproduce byte-for-byte.
//!
//! # How to obtain the vectors
//!
//! Download the SPHINCS+ reference package from:
//! <https://sphincs.org/software.html> → "Additional implementations"
//! or from the NIST submission archive. Locate:
//!
//! ```
//! KAT/sphincs-sha2-256s-simple/PQCsignKAT_sphincs-sha2-256s-simple.rsp
//! ```
//!
//! Place it at `tests/kat/sphincs-sha2-256s-simple.rsp` relative to the
//! crate root.  The tests below will be automatically enabled.
//!
//! # File format (NIST `.rsp`)
//!
//! ```text
//! # SPHINCS+-SHA2-256s-simple
//!
//! count = 0
//! seed = <DRBG seed, 96 hex chars>
//! mlen = <message length in bytes>
//! msg = <message hex>
//! pk = <public key hex, 64 bytes = 128 hex chars for SHA2-256s>
//! sk = <secret key hex, 128 bytes = 256 hex chars>
//! smlen = <signed message length>
//! sm = <signed message hex = signature || message>
//! ```
//!
//! The "sm" field is `sig ‖ msg` (signature prepended, not appended).
//! Detach the message by taking `sm[..smlen-mlen]` as the raw signature.

use std::collections::HashMap;
use std::path::PathBuf;

// ── KAT record ────────────────────────────────────────────────────────────────

/// One record from a NIST KAT `.rsp` file.
#[derive(Debug)]
pub struct KatRecord {
    pub count:  usize,
    pub mlen:   usize,
    pub msg:    Vec<u8>,
    pub pk:     Vec<u8>,
    pub sk:     Vec<u8>,
    pub smlen:  usize,
    pub sm:     Vec<u8>,
    // `seed` field is included for completeness but not used in these tests
    // because we derive the key pair directly from (sk_seed, sk_prf, pk_seed)
    // encoded in the `sk` field rather than running the DRBG.
}

impl KatRecord {
    /// Extract the raw detached signature bytes: `sm[0 .. smlen - mlen]`.
    pub fn signature_bytes(&self) -> &[u8] {
        &self.sm[..self.smlen - self.mlen]
    }

    /// Extract the message bytes: `sm[smlen - mlen ..]`.
    pub fn msg_from_sm(&self) -> &[u8] {
        &self.sm[self.smlen - self.mlen..]
    }

    /// Decode the secret key fields from the raw `sk` bytes.
    ///
    /// SPHINCS+ SHA2-256s-simple SK layout (128 bytes):
    /// ```text
    /// sk[  0..32] = SK.seed
    /// sk[ 32..64] = SK.prf
    /// sk[ 64..96] = PK.seed
    /// sk[96..128] = PK.root
    /// ```
    pub fn decode_sk(&self) -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
        assert_eq!(self.sk.len(), 128, "SK must be 128 bytes for SHA2-256s");
        let mut sk_seed = [0u8; 32];
        let mut sk_prf  = [0u8; 32];
        let mut pk_seed = [0u8; 32];
        let mut pk_root = [0u8; 32];
        sk_seed.copy_from_slice(&self.sk[  0.. 32]);
        sk_prf .copy_from_slice(&self.sk[ 32.. 64]);
        pk_seed.copy_from_slice(&self.sk[ 64.. 96]);
        pk_root.copy_from_slice(&self.sk[ 96..128]);
        (sk_seed, sk_prf, pk_seed, pk_root)
    }

    /// Decode the public key fields from the raw `pk` bytes.
    ///
    /// SPHINCS+ SHA2-256s-simple PK layout (64 bytes):
    /// ```text
    /// pk[ 0..32] = PK.seed
    /// pk[32..64] = PK.root
    /// ```
    pub fn decode_pk(&self) -> ([u8; 32], [u8; 32]) {
        assert_eq!(self.pk.len(), 64, "PK must be 64 bytes for SHA2-256s");
        let mut pk_seed = [0u8; 32];
        let mut pk_root = [0u8; 32];
        pk_seed.copy_from_slice(&self.pk[ 0..32]);
        pk_root.copy_from_slice(&self.pk[32..64]);
        (pk_seed, pk_root)
    }
}

// ── KAT parser ────────────────────────────────────────────────────────────────

/// Parse a NIST `.rsp` file into a list of [`KatRecord`]s.
///
/// Skips comment lines (starting with `#`) and blank lines.
/// Stops at `EOF` or any line starting with `#` that follows at least one record.
pub fn parse_rsp(content: &str) -> Vec<KatRecord> {
    let mut records = Vec::new();
    let mut fields: HashMap<&str, &str> = HashMap::new();

    for line in content.lines() {
        let line = line.trim();

        // Skip blank lines and comments
        if line.is_empty() || line.starts_with('#') {
            // If we have accumulated fields for one record, flush it
            if fields.contains_key("count") {
                if let Some(rec) = build_record(&fields) {
                    records.push(rec);
                }
                fields.clear();
            }
            continue;
        }

        // Parse "key = value"
        if let Some((key, val)) = line.split_once(" = ") {
            fields.insert(key.trim(), val.trim());
        }
    }

    // Flush final record if file doesn't end with a blank line
    if fields.contains_key("count") {
        if let Some(rec) = build_record(&fields) {
            records.push(rec);
        }
    }

    records
}

fn build_record(fields: &HashMap<&str, &str>) -> Option<KatRecord> {
    let decode_hex = |key: &str| -> Option<Vec<u8>> {
        hex::decode(fields.get(key)?).ok()
    };
    let parse_usize = |key: &str| -> Option<usize> {
        fields.get(key)?.parse().ok()
    };

    Some(KatRecord {
        count: parse_usize("count")?,
        mlen:  parse_usize("mlen")?,
        smlen: parse_usize("smlen")?,
        msg:   decode_hex("msg")?,
        pk:    decode_hex("pk")?,
        sk:    decode_hex("sk")?,
        sm:    decode_hex("sm")?,
    })
}

// ── KAT file path helper ──────────────────────────────────────────────────────

/// Path where the NIST KAT file is expected.
pub fn kat_file_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("kat")
        .join("sphincs-sha2-256s-simple.rsp")
}

// ── Parser unit tests (no KAT file needed) ───────────────────────────────────

#[cfg(test)]
mod parser_tests {
    use super::*;

    /// parse_rsp must handle the canonical format correctly.
    #[test]
    fn parse_rsp_basic() {
        let sample = r#"
# sphincs-sha2-256s-simple

count = 0
seed = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f
mlen = 33
msg = d81c4d8d734fcbfbeade3d3f8a039faa2a2c9957e835ad55b22e75bf57bb556ac8
pk = 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
sk = 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
smlen = 36
sm = aabbccdd0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20d81c4d8d734fcbfbeade3d3f8a039faa2a2c9957e835ad55b22e75bf57bb556ac8

"#;
        let records = parse_rsp(sample);
        assert_eq!(records.len(), 1, "Should parse exactly 1 record");
        let rec = &records[0];
        assert_eq!(rec.count, 0);
        assert_eq!(rec.mlen,  33);
        assert_eq!(rec.smlen, 36);
        assert_eq!(rec.pk.len(),  64);
        assert_eq!(rec.sk.len(), 128);
    }

    /// decode_sk must extract the four N-byte fields correctly.
    #[test]
    fn decode_sk_fields() {
        let mut sk_bytes = [0u8; 128];
        // Fill each 32-byte field with a distinct byte value
        sk_bytes[ 0.. 32].fill(0x11); // SK.seed
        sk_bytes[32.. 64].fill(0x22); // SK.prf
        sk_bytes[64.. 96].fill(0x33); // PK.seed
        sk_bytes[96..128].fill(0x44); // PK.root

        let rec = KatRecord {
            count: 0, mlen: 0, smlen: 0,
            msg: vec![], pk: vec![0u8; 64], sk: sk_bytes.to_vec(), sm: vec![],
        };
        let (sk_seed, sk_prf, pk_seed, pk_root) = rec.decode_sk();
        assert_eq!(sk_seed, [0x11u8; 32]);
        assert_eq!(sk_prf,  [0x22u8; 32]);
        assert_eq!(pk_seed, [0x33u8; 32]);
        assert_eq!(pk_root, [0x44u8; 32]);
    }

    /// signature_bytes + msg_from_sm must cover the full sm without overlap.
    #[test]
    fn sm_split_correct() {
        // sig = [0xAA; 4], msg = [0xBB; 3], smlen = 7, mlen = 3
        let sm = [0xAAu8; 4].iter().chain([0xBBu8; 3].iter()).copied().collect();
        let rec = KatRecord {
            count: 0, mlen: 3, smlen: 7,
            msg: vec![], pk: vec![], sk: vec![], sm,
        };
        assert_eq!(rec.signature_bytes(), &[0xAAu8; 4]);
        assert_eq!(rec.msg_from_sm(),     &[0xBBu8; 3]);
    }
}

// ── KAT-file-dependent tests ──────────────────────────────────────────────────
//
// These tests require the NIST KAT file at `tests/kat/sphincs-sha2-256s-simple.rsp`.
// They are skipped automatically if the file is absent.
//
// To run:
//   cargo test --test kat -- --include-ignored
// or place the KAT file and run:
//   cargo test --test kat

#[cfg(test)]
mod kat_file_tests {
    use super::*;
    use sphincs_rs::hash::Sha256Hasher;
    use sphincs_rs::sphincs::{SphincsPK, SphincsSK};

    /// Skip helper: returns true if the KAT file is available.
    fn kat_available() -> bool {
        kat_file_path().exists()
    }

    /// Load and parse the KAT file.
    fn load_kat() -> Vec<KatRecord> {
        let content = std::fs::read_to_string(kat_file_path())
            .expect("Failed to read KAT file");
        parse_rsp(&content)
    }

    // ── Signature verification KAT ────────────────────────────────────────────

    /// For each KAT record, verify that the stored `sm` signature is valid
    /// under the stored `pk` and `msg`.
    ///
    /// This tests that `slh_verify` accepts exactly the signatures produced
    /// by the NIST reference implementation.
    #[test]
    fn kat_verify_all_signatures() {
        if !kat_available() {
            eprintln!("[SKIP] KAT file not found at {:?}", kat_file_path());
            eprintln!("       Place the NIST KAT file there to run this test.");
            return;
        }

        let records = load_kat();
        assert!(!records.is_empty(), "KAT file must contain at least one record");

        for rec in &records {
            // Decode PK from the KAT record
            let (pk_seed, pk_root) = rec.decode_pk();
            let pk = SphincsPK { pk_seed, pk_root };

            // The signature bytes are sm[0 .. smlen - mlen]
            let sig_bytes = rec.signature_bytes();
            let msg       = rec.msg_from_sm();

            // Deserialise the signature and verify
            // NOTE: slh_verify_raw takes raw bytes once the serialisation
            // module is implemented.  For now we use the structured path.
            let result = sphincs_rs::sphincs::slh_verify_raw::<Sha256Hasher>(
                msg, sig_bytes, &pk,
            );
            assert!(
                result,
                "KAT count={} failed verification (sig bytes = {})",
                rec.count, hex::encode(&sig_bytes[..8]),
            );
        }

        println!("✓ Verified {} KAT records", records.len());
    }

    // ── Signature generation KAT ──────────────────────────────────────────────

    /// For each KAT record, re-sign the message from the stored SK and
    /// check that the produced signature matches the stored `sm` byte-for-byte.
    ///
    /// This requires **deterministic** signing (`opt_rand = PK.seed`).
    /// If this test fails but `kat_verify_all_signatures` passes, the issue
    /// is in randomness generation, not in the hash functions.
    #[test]
    fn kat_sign_matches_reference() {
        if !kat_available() {
            eprintln!("[SKIP] KAT file not found at {:?}", kat_file_path());
            return;
        }

        let records = load_kat();

        for rec in &records {
            let (sk_seed, sk_prf, pk_seed, pk_root) = rec.decode_sk();
            let sk = SphincsSK { sk_seed, sk_prf, pk_seed, pk_root };

            let msg       = rec.msg_from_sm();
            let sig_bytes = sphincs_rs::sphincs::slh_sign_raw::<Sha256Hasher>(msg, &sk);
            let expected  = rec.signature_bytes();

            assert_eq!(
                sig_bytes.len(), expected.len(),
                "KAT count={} signature length mismatch: got {} expected {}",
                rec.count, sig_bytes.len(), expected.len(),
            );
            assert_eq!(
                sig_bytes.as_slice(), expected,
                "KAT count={} signature bytes mismatch (first 8: {} vs {})",
                rec.count,
                hex::encode(&sig_bytes[..8]),
                hex::encode(&expected[..8]),
            );
        }

        println!("✓ Reproduced {} KAT signatures", records.len());
    }
}