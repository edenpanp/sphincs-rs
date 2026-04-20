//! SPHINCS+ parameter set: SHA2-256s (stateless, 256-bit security).
//!
//! All constants are derived from the SPHINCS+ specification Table 3.
//! Reference: FIPS 205 / eprint 2019/1086.
//!
//! Parameter selection rationale:
//!   - n=32  → 256-bit security
//!   - w=16  → balanced sign/verify speed
//!   - d=8   → 8-layer hypertree
//!   - h=64  → total tree height
//!   - k=22  → 22 FORS trees
//!   - a=14  → 2^14 = 16384 leaves per FORS tree

// ── Core parameters ──────────────────────────────────────────────────────────

/// Security parameter n: output length of the hash function in bytes.
pub const N: usize = 32;

/// Winternitz parameter w: base for WOTS+ digit representation.
pub const W: usize = 16;

/// log₂(W). For W=16 this is 4.
pub const LOG_W: usize = 4;

/// Total hypertree height h.
pub const H: usize = 64;

/// Number of XMSS layers in the hypertree.
pub const D: usize = 8;

/// Height per XMSS layer h' = h / d.
pub const HP: usize = H / D; // = 8

/// Number of FORS trees k.
pub const K: usize = 22;

/// Height of each FORS tree a = log₂(t).
pub const A: usize = 14;

/// Number of leaves in each FORS tree t = 2^a.
pub const T: usize = 1 << A; // = 16384

// ── WOTS+ derived parameters ─────────────────────────────────────────────────

/// WOTS+ len₁ = ⌈8n / log₂(w)⌉ = ⌈256 / 4⌉ = 64.
/// Number of n-byte hash values encoding the message.
pub const WOTS_LEN1: usize = (8 * N + LOG_W - 1) / LOG_W; // = 64

/// WOTS+ len₂ = ⌊log₂(len₁·(w−1)) / log₂(w)⌋ + 1 = 3.
/// Number of n-byte hash values encoding the checksum.
/// Manually verified: ⌊log₂(64·15) / 4⌋ + 1 = ⌊9.906/4⌋ + 1 = 3.
pub const WOTS_LEN2: usize = 3;

/// Total WOTS+ signature length in hash values = len₁ + len₂ = 67.
pub const WOTS_LEN: usize = WOTS_LEN1 + WOTS_LEN2; // = 67

// ── Message digest layout ────────────────────────────────────────────────────
//
// The message digest of length M is split as:
//   [ md (MD_BYTES) | idx_tree (IDX_TREE_BYTES) | idx_leaf (IDX_LEAF_BYTES) ]
//
// md        → selects a set of FORS indices
// idx_tree  → selects the XMSS tree in the hypertree
// idx_leaf  → selects the WOTS+ leaf within that tree

/// Bytes used for FORS indices: ⌈k·a / 8⌉ = ⌈308 / 8⌉ = 39.
pub const MD_BYTES: usize = (K * A + 7) / 8; // = 39

/// Bytes used for the hypertree tree index: ⌈(h − h/d) / 8⌉ = ⌈56/8⌉ = 7.
pub const IDX_TREE_BYTES: usize = (H - H / D + 7) / 8; // = 7

/// Bytes used for the XMSS leaf index: ⌈(h/d) / 8⌉ = ⌈8/8⌉ = 1.
pub const IDX_LEAF_BYTES: usize = (HP + 7) / 8; // = 1

/// Total message digest length M = MD_BYTES + IDX_TREE_BYTES + IDX_LEAF_BYTES = 47.
pub const M: usize = MD_BYTES + IDX_TREE_BYTES + IDX_LEAF_BYTES; // = 47

// ── Sanity checks (evaluated at compile time) ─────────────────────────────────

const _: () = assert!(HP == H / D, "HP must equal H/D");
const _: () = assert!(WOTS_LEN1 == 64, "WOTS_LEN1 must be 64 for N=32, W=16");
const _: () = assert!(WOTS_LEN == 67, "WOTS_LEN must be 67 for N=32, W=16");
const _: () = assert!(M == 47, "M must be 47 for SHA2-256s");
