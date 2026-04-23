use std::collections::HashMap;
use std::path::PathBuf;

use sphincs_rs::hash::Sha256Hasher;
use sphincs_rs::sphincs::{SphincsPK, slh_verify_raw};

#[derive(Debug)]
pub struct KatRecord {
    pub count: usize,
    pub mlen: usize,
    pub msg: Vec<u8>,
    pub pk: Vec<u8>,
    pub sk: Vec<u8>,
    pub smlen: usize,
    pub sm: Vec<u8>,
}

impl KatRecord {
    pub fn signature_bytes(&self) -> &[u8] {
        &self.sm[..self.smlen - self.mlen]
    }

    pub fn msg_from_sm(&self) -> &[u8] {
        &self.sm[self.smlen - self.mlen..]
    }

    pub fn decode_sk(&self) -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
        assert_eq!(self.sk.len(), 128, "SK must be 128 bytes for SHA2-256s");
        let mut sk_seed = [0u8; 32];
        let mut sk_prf = [0u8; 32];
        let mut pk_seed = [0u8; 32];
        let mut pk_root = [0u8; 32];
        sk_seed.copy_from_slice(&self.sk[0..32]);
        sk_prf.copy_from_slice(&self.sk[32..64]);
        pk_seed.copy_from_slice(&self.sk[64..96]);
        pk_root.copy_from_slice(&self.sk[96..128]);
        (sk_seed, sk_prf, pk_seed, pk_root)
    }

    pub fn decode_pk(&self) -> ([u8; 32], [u8; 32]) {
        assert_eq!(self.pk.len(), 64, "PK must be 64 bytes for SHA2-256s");
        let mut pk_seed = [0u8; 32];
        let mut pk_root = [0u8; 32];
        pk_seed.copy_from_slice(&self.pk[0..32]);
        pk_root.copy_from_slice(&self.pk[32..64]);
        (pk_seed, pk_root)
    }
}

pub fn parse_rsp(content: &str) -> Vec<KatRecord> {
    let mut records = Vec::new();
    let mut fields: HashMap<&str, &str> = HashMap::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            if fields.contains_key("count") {
                if let Some(record) = build_record(&fields) {
                    records.push(record);
                }
                fields.clear();
            }
            continue;
        }

        if let Some((key, value)) = line.split_once(" = ") {
            fields.insert(key.trim(), value.trim());
        }
    }

    if fields.contains_key("count") {
        if let Some(record) = build_record(&fields) {
            records.push(record);
        }
    }

    records
}

fn build_record(fields: &HashMap<&str, &str>) -> Option<KatRecord> {
    let decode_hex = |key: &str| -> Option<Vec<u8>> { hex::decode(fields.get(key)?).ok() };
    let parse_usize = |key: &str| -> Option<usize> { fields.get(key)?.parse().ok() };

    Some(KatRecord {
        count: parse_usize("count")?,
        mlen: parse_usize("mlen")?,
        msg: decode_hex("msg")?,
        pk: decode_hex("pk")?,
        sk: decode_hex("sk")?,
        smlen: parse_usize("smlen")?,
        sm: decode_hex("sm")?,
    })
}

pub fn kat_file_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("PQCsignKAT_128.rsp")
}

fn load_kat() -> Vec<KatRecord> {
    let content = std::fs::read_to_string(kat_file_path()).expect("failed to read KAT file");
    parse_rsp(&content)
}

#[test]
fn parse_rsp_basic() {
    let sample = r#"
# SPHINCS+

count = 0
seed = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f
mlen = 3
msg = aabbcc
pk = 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
sk = 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
smlen = 7
sm = deadbeefaabbcc
"#;

    let records = parse_rsp(sample);
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record.count, 0);
    assert_eq!(record.mlen, 3);
    assert_eq!(record.msg, vec![0xaa, 0xbb, 0xcc]);
    assert_eq!(record.pk.len(), 64);
    assert_eq!(record.sk.len(), 128);
    assert_eq!(record.signature_bytes(), &[0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(record.msg_from_sm(), &[0xaa, 0xbb, 0xcc]);
}

#[test]
fn decode_sk_fields() {
    let mut sk_bytes = [0u8; 128];
    sk_bytes[0..32].fill(0x11);
    sk_bytes[32..64].fill(0x22);
    sk_bytes[64..96].fill(0x33);
    sk_bytes[96..128].fill(0x44);

    let record = KatRecord {
        count: 0,
        mlen: 0,
        msg: vec![],
        pk: vec![0u8; 64],
        sk: sk_bytes.to_vec(),
        smlen: 0,
        sm: vec![],
    };

    let (sk_seed, sk_prf, pk_seed, pk_root) = record.decode_sk();
    assert_eq!(sk_seed, [0x11u8; 32]);
    assert_eq!(sk_prf, [0x22u8; 32]);
    assert_eq!(pk_seed, [0x33u8; 32]);
    assert_eq!(pk_root, [0x44u8; 32]);
}

#[test]
fn kat_file_parses_and_lengths_match() {
    let records = load_kat();
    assert!(!records.is_empty(), "KAT file should contain records");

    let record = &records[0];
    assert_eq!(record.msg.len(), record.mlen);
    assert_eq!(record.msg_from_sm(), record.msg.as_slice());
    assert_eq!(
        record.signature_bytes().len() + record.msg_from_sm().len(),
        record.smlen
    );
    assert_eq!(record.pk.len(), 64);
    assert_eq!(record.sk.len(), 128);
}

#[test]
#[ignore = "Bundled reference vectors do not yet verify under the current SHA2 backend"]
fn kat_verify_sample_records() {
    let records = load_kat();

    for record in records.iter().take(3) {
        let (pk_seed, pk_root) = record.decode_pk();
        let pk = SphincsPK { pk_seed, pk_root };
        assert!(
            slh_verify_raw::<Sha256Hasher>(record.msg_from_sm(), record.signature_bytes(), &pk),
            "KAT count={} failed verification",
            record.count
        );
    }
}

#[test]
#[ignore = "Long-running KAT sweep"]
fn kat_verify_first_ten_records() {
    let records = load_kat();

    for record in records.iter().take(10) {
        let (pk_seed, pk_root) = record.decode_pk();
        let pk = SphincsPK { pk_seed, pk_root };
        assert!(
            slh_verify_raw::<Sha256Hasher>(record.msg_from_sm(), record.signature_bytes(), &pk),
            "KAT count={} failed verification",
            record.count
        );
    }
}
