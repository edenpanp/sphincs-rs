//! # sphincs-rs
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
//!     derive_member_key,
//!     group_keygen,
//!     group_open,
//!     group_sign,
//!     group_verify,
//! };
//! use sphincs_rs::hash::Sha256Hasher;
//!
//! let (manager, gpk) = group_keygen::<Sha256Hasher>();
//! let member_sk = derive_member_key::<Sha256Hasher>(&manager, 0);
//!
//! let sig = group_sign::<Sha256Hasher>(b"hello group", &member_sk);
//!
//! assert!(group_verify::<Sha256Hasher>(b"hello group", &sig, &gpk));
//! assert_eq!(group_open::<Sha256Hasher>(b"hello group", &sig, &manager), Some(0));
//! ```
//!
//! current group module uses a top-level XMSS tree as the group public key:
//! - manager owns the tree seed and distributes member signing material
//! - member signatures verify under the group public key
//! - manager can open the signer index for a valid group signature
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
