//! # sphincs-rs
//!
//! SPHINCS+ (SLH-DSA) in Rust — UNSW 26T1 Applied Cryptography project.
//!
//! ## Modules
//!
//! ```text
//! params / params_alpha   ← security parameter constants + SPHINCS-alpha sets
//!   └─ hash              ← SphincsHasher trait + SHA-256 instantiation
//!       └─ adrs          ← 32-byte ADRS structure
//!           └─ wots      ← WOTS+ one-time signatures          (Alg. 5–8)
//!               └─ xmss  ← XMSS Merkle tree, baseline + fast  (Alg. 9–11)
//!                   ├─ fors   ← FORS few-time signatures       (Alg. 14–17)
//!                   └─ ht     ← hypertree, baseline + fast     (Alg. 12–13)
//!                       ├─ sphincs  ← SLH-DSA keygen/sign/verify (Alg. 18–20)
//!                       └─ group    ← group signature extension
//! ```
//!
//! ## Quick start
//!
//! ```rust,ignore
//! use sphincs_rs::sphincs::{slh_keygen_fast, slh_sign_fast, slh_verify};
//! use sphincs_rs::hash::Sha256Hasher;
//!
//! let (sk, pk) = slh_keygen_fast::<Sha256Hasher>();
//! let sig = slh_sign_fast::<Sha256Hasher>(b"my message", &sk);
//! assert!(slh_verify::<Sha256Hasher>(b"my message", &sig, &pk));
//! ```
//!
//! ## Group signature quick start
//!
//! ```rust,ignore
//! use sphincs_rs::group::{group_keygen, derive_member_key, group_sign, group_verify};
//! use sphincs_rs::hash::Sha256Hasher;
//!
//! // Manager generates group key + distributes member keys
//! let (manager, gpk) = group_keygen::<Sha256Hasher>();
//! let member_sk = derive_member_key(&manager, 0); // member index 0
//!
//! // Member signs
//! let sig = group_sign::<Sha256Hasher>(b"hello group", &member_sk);
//!
//! // Anyone verifies (no identity revealed)
//! assert!(group_verify::<Sha256Hasher>(b"hello group", &sig, &gpk));
//! ```
//!
//! ## Optimisations
//!
//! - `slh_keygen_fast` / `slh_sign_fast`: iterative bottom-up XMSS tree
//!   (avoids redundant subtree recomputation in the baseline recursive approach).
//! - `--features parallel`: Rayon-based parallel leaf generation,
//!   distributing the 2^HP WOTS+ evaluations across CPU cores.
//! - `params_alpha`: SPHINCS-alpha parameter analysis showing that (K=14, A=17)
//!   reduces FORS signature size by 24% vs the NIST standard.

pub mod params;
pub mod params_alpha;
pub mod adrs;
pub mod hash;
pub mod wots;
pub mod xmss;
pub mod fors;
pub mod ht;
pub mod sphincs;
pub mod group;
