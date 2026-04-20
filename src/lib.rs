///! # sphincs-rs
//!
//! A SPHINCS+ (SLH-DSA) implementation in Rust.
//!
//! overall structure is layered, roughly follows the spec but written in a more "engineering" way.
//!
//! ## Module structure (top → bottom)
//!
//! ```text
//! params / params_alpha   ← parameter sets (security + size tradeoffs)
//!   └─ hash              ← SphincsHasher trait + SHA-256 impl
//!       └─ adrs          ← ADRS (32-byte address struct)
//!           └─ wots      ← WOTS+ one-time sigs
//!               └─ xmss  ← Merkle tree (baseline + fast version)
//!                   ├─ fors   ← few-time sig (FORS)
//!                   └─ ht     ← hypertree
//!                       ├─ sphincs  ← full SLH-DSA
//!                       └─ group    ← simple group sig extension
//! ```
//!
//! idea is basically:
//! build from small pieces → compose into full SPHINCS+
//!
//! ## Quick start
//!
//! ```rust,ignore
//! use sphincs_rs::sphincs::{slh_keygen_fast, slh_sign_fast, slh_verify};
//! use sphincs_rs::hash::Sha256Hasher;
//!
//! let (sk, pk) = slh_keygen_fast::<Sha256Hasher>();
//! let sig = slh_sign_fast::<Sha256Hasher>(b"my message", &sk);
//!
//! assert!(slh_verify::<Sha256Hasher>(b"my message", &sig, &pk));
//! ```
//!
//! ## Group signature quick start
//!
//! ```rust,ignore
//! use sphincs_rs::group::{
//!     attach_certificates,
//!     certify_key_batch,
//!     generate_member_key_batch,
//!     group_keygen,
//!     group_sign,
//!     group_verify,
//! };
//! use sphincs_rs::hash::Sha256Hasher;
//!
//! // member locally generate a batch of one-time WOTS+ keys
//! let (mut manager, gpk) = group_keygen::<Sha256Hasher>();
//! let batch = generate_member_key_batch::<Sha256Hasher>(0, 8).unwrap();
//! let request = batch.certification_request();
//!
//! // manager signs those public keys (issue certs)
//! let certificates = certify_key_batch::<Sha256Hasher>(&mut manager, &request).unwrap();
//! let mut member_sk = attach_certificates(batch, certificates).unwrap();
//!
//! // when signing, just pick one unused key + cert
//! let sig = group_sign::<Sha256Hasher>(b"hello group", &mut member_sk).unwrap();
//!
//! // verify needs to pass two checks:
//! // 1. manager cert is valid
//! // 2. WOTS signature is valid
//! assert!(group_verify::<Sha256Hasher>(b"hello group", &sig, &gpk));
//! ```
//!
//! current group module uses a cert-based design:
//! - member pre-generates one-time keys
//! - manager signs those public keys (no private key access)
//! - actual signing consumes one certified key
//!
//! ## Optimisations
//!
//! - `slh_keygen_fast` / `slh_sign_fast`:
//!   use bottom-up XMSS tree instead of recursive version
//!   → avoids recomputing subtrees again and again
//!
//! - `--features parallel`:
//!   parallelise leaf generation (Rayon)
//!   → big speedup since WOTS chain is the bottleneck
//!
//! - `params_alpha`:
//!   some parameter experiments
//!   → e.g. (K=14, A=17) can reduce FORS size ~24%
//!
//! trade-off note:
//! fast version uses more memory, but much less redundant computation

pub mod adrs;
pub mod digest;
pub mod fors;
pub mod group;
pub mod hash;
pub mod ht;
pub mod params;
pub mod params_alpha;
pub mod sphincs;
pub mod wots;
pub mod xmss;
