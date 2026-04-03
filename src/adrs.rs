//! SPHINCS+ address (ADRS) structure.
//!
//! An ADRS is a 32-byte value that encodes the position of a hash evaluation
//! within the overall SPHINCS+ key / signature structure. It is used as a
//! "tweak" to domain-separate every individual hash call.
//!
//! # Layout (32 bytes, all fields big-endian)
//!
//! ```text
//! ┌─────────────────┬──────────────────────┬──────────┬───────────────────────┐
//! │ layer_address   │ tree_address         │ type     │ type_bits             │
//! │ (4 bytes)       │ (12 bytes)           │ (4 bytes)│ (12 bytes)            │
//! └─────────────────┴──────────────────────┴──────────┴───────────────────────┘
//! bytes  0..4        4..16                  16..20     20..32
//! ```
//!
//! The `type_bits` field is interpreted differently for each [`AdrsType`]:
//!
//! | Type       | bytes 20..24        | bytes 24..28   | bytes 28..32   |
//! |------------|---------------------|----------------|----------------|
//! | Wots       | keypair_address     | chain_address  | hash_address   |
//! | WotsPk     | keypair_address     | 0000           | 0000           |
//! | TreeNode   | 00000000            | tree_height    | tree_index     |
//! | ForsTree   | keypair_address     | tree_height    | tree_index     |
//! | ForsPk     | keypair_address     | 00000000       | 00000000       |

// ── AdrsType ──────────────────────────────────────────────────────────────────

/// Discriminant for the five SPHINCS+ address types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdrsType {
    Wots     = 0,
    WotsPk   = 1,
    TreeNode = 2,
    ForsTree = 3,
    ForsPk   = 4,
}

impl AdrsType {
    pub fn to_u32(self) -> u32 {
        self as u32
    }
}

// ── Adrs ─────────────────────────────────────────────────────────────────────

/// A 32-byte SPHINCS+ address.
///
/// This is the main type used throughout the library. Use the helper methods
/// (`set_layer_address`, `set_chain_address`, etc.) to construct addresses
/// for specific contexts rather than manipulating the raw bytes directly.
#[derive(Clone, Copy, Debug)]
pub struct Adrs {
    pub layer_address: [u8; 4],  //  4 bytes – layer in the hypertree
    pub tree_address: [u8; 12],  // 12 bytes – tree within the layer (64-bit + 4 padding)
    pub adrs_type: AdrsType,     //  4 bytes – discriminant stored as u32
    pub type_bits: [u8; 12],     // 12 bytes – type-specific fields (see table above)
}

impl Adrs {
    // ── Constructors ─────────────────────────────────────────────────────────

    /// Create a zeroed ADRS with the given type.
    pub fn new(adrs_type: AdrsType) -> Self {
        Adrs {
            layer_address: [0u8; 4],
            tree_address: [0u8; 12],
            adrs_type,
            type_bits: [0u8; 12],
        }
    }

    /// Serialise the full 32-byte ADRS to bytes (big-endian).
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[0..4].copy_from_slice(&self.layer_address);
        out[4..16].copy_from_slice(&self.tree_address);
        out[16..20].copy_from_slice(&self.adrs_type.to_u32().to_be_bytes());
        out[20..32].copy_from_slice(&self.type_bits);
        out
    }

    // ── Outer-field setters ───────────────────────────────────────────────────

    /// Set the layer address (which XMSS layer in the hypertree).
    pub fn set_layer_address(&mut self, layer: u32) {
        self.layer_address = layer.to_be_bytes();
    }

    pub fn get_layer_address(&self) -> u32 {
        u32::from_be_bytes(self.layer_address)
    }

    /// Set the 64-bit tree address (index of the XMSS tree within its layer).
    ///
    /// The 12-byte `tree_address` field stores the 64-bit value right-aligned
    /// (bytes 0..4 are zero padding).
    pub fn set_tree_address(&mut self, tree: u64) {
        self.tree_address[0..4].fill(0); // padding
        self.tree_address[4..12].copy_from_slice(&tree.to_be_bytes());
    }

    pub fn get_tree_address(&self) -> u64 {
        u64::from_be_bytes(self.tree_address[4..12].try_into().unwrap())
    }

    /// Change the ADRS type and zero-fill all type-specific bits.
    ///
    /// Always call this before setting type-specific fields when reusing
    /// an ADRS across types (e.g. converting a WOTS ADRS to WOTS_PK ADRS).
    pub fn set_type_and_clear(&mut self, adrs_type: AdrsType) {
        self.adrs_type = adrs_type;
        self.type_bits = [0u8; 12];
    }

    // ── type_bits field helpers ───────────────────────────────────────────────
    //
    // The helpers below map to fixed byte positions within `type_bits`.
    // These positions are shared across multiple ADRS types (see the table
    // in the module doc), so it is the caller's responsibility to use only
    // the helpers relevant to the current `adrs_type`.

    /// Set `keypair_address` (bytes 20–23 of ADRS / bytes 0–3 of type_bits).
    ///
    /// Relevant for: [`AdrsType::Wots`], [`AdrsType::WotsPk`],
    ///               [`AdrsType::ForsTree`], [`AdrsType::ForsPk`].
    pub fn set_keypair_address(&mut self, kp: u32) {
        self.type_bits[0..4].copy_from_slice(&kp.to_be_bytes());
    }

    pub fn get_keypair_address(&self) -> u32 {
        u32::from_be_bytes(self.type_bits[0..4].try_into().unwrap())
    }

    /// Set `chain_address` (bytes 24–27 / type_bits[4..8]).
    ///
    /// Relevant for: [`AdrsType::Wots`].
    pub fn set_chain_address(&mut self, chain: u32) {
        self.type_bits[4..8].copy_from_slice(&chain.to_be_bytes());
    }

    pub fn get_chain_address(&self) -> u32 {
        u32::from_be_bytes(self.type_bits[4..8].try_into().unwrap())
    }

    /// Set `hash_address` (bytes 28–31 / type_bits[8..12]).
    ///
    /// Relevant for: [`AdrsType::Wots`].
    pub fn set_hash_address(&mut self, hash: u32) {
        self.type_bits[8..12].copy_from_slice(&hash.to_be_bytes());
    }

    pub fn get_hash_address(&self) -> u32 {
        u32::from_be_bytes(self.type_bits[8..12].try_into().unwrap())
    }

    /// Set `tree_height` (bytes 24–27 / type_bits[4..8]).
    ///
    /// Relevant for: [`AdrsType::TreeNode`], [`AdrsType::ForsTree`].
    /// This occupies the same bytes as `chain_address` — do not mix them.
    pub fn set_tree_height(&mut self, height: u32) {
        self.type_bits[4..8].copy_from_slice(&height.to_be_bytes());
    }

    pub fn get_tree_height(&self) -> u32 {
        u32::from_be_bytes(self.type_bits[4..8].try_into().unwrap())
    }

    /// Set `tree_index` (bytes 28–31 / type_bits[8..12]).
    ///
    /// Relevant for: [`AdrsType::TreeNode`], [`AdrsType::ForsTree`].
    /// This occupies the same bytes as `hash_address` — do not mix them.
    pub fn set_tree_index(&mut self, index: u32) {
        self.type_bits[8..12].copy_from_slice(&index.to_be_bytes());
    }

    pub fn get_tree_index(&self) -> u32 {
        u32::from_be_bytes(self.type_bits[8..12].try_into().unwrap())
    }
}

// ── Legacy typed views (kept for compatibility) ───────────────────────────────
//
// These structs were in the original skeleton. They remain here for reference
// but the helper methods on `Adrs` above are the preferred interface.

pub struct WotsAdrs {
    pub keypair_address: [u8; 4],
    pub chain_address:   [u8; 4],
    pub hash_address:    [u8; 4],
}

impl WotsAdrs {
    pub fn from_type_bits(bits: &[u8; 12]) -> Self {
        WotsAdrs {
            keypair_address: bits[0..4].try_into().unwrap(),
            chain_address:   bits[4..8].try_into().unwrap(),
            hash_address:    bits[8..12].try_into().unwrap(),
        }
    }
    pub fn to_type_bits(&self) -> [u8; 12] {
        let mut out = [0u8; 12];
        out[0..4].copy_from_slice(&self.keypair_address);
        out[4..8].copy_from_slice(&self.chain_address);
        out[8..12].copy_from_slice(&self.hash_address);
        out
    }
}

pub struct WotsPkAdrs {
    pub keypair_address: [u8; 4],
}

impl WotsPkAdrs {
    pub fn from_type_bits(bits: &[u8; 12]) -> Self {
        WotsPkAdrs { keypair_address: bits[0..4].try_into().unwrap() }
    }
    pub fn to_type_bits(&self) -> [u8; 12] {
        let mut out = [0u8; 12];
        out[0..4].copy_from_slice(&self.keypair_address);
        out
    }
}

pub struct TreeNodeAdrs {
    pub tree_height: [u8; 4],
    pub tree_index:  [u8; 4],
}

impl TreeNodeAdrs {
    pub fn from_type_bits(bits: &[u8; 12]) -> Self {
        TreeNodeAdrs {
            tree_height: bits[4..8].try_into().unwrap(),
            tree_index:  bits[8..12].try_into().unwrap(),
        }
    }
    pub fn to_type_bits(&self) -> [u8; 12] {
        let mut out = [0u8; 12];
        out[4..8].copy_from_slice(&self.tree_height);
        out[8..12].copy_from_slice(&self.tree_index);
        out
    }
}

pub struct ForsTreeAdrs {
    pub keypair_address: [u8; 4],
    pub tree_height:     [u8; 4],
    pub tree_index:      [u8; 4],
}

impl ForsTreeAdrs {
    pub fn from_type_bits(bits: &[u8; 12]) -> Self {
        ForsTreeAdrs {
            keypair_address: bits[0..4].try_into().unwrap(),
            tree_height:     bits[4..8].try_into().unwrap(),
            tree_index:      bits[8..12].try_into().unwrap(),
        }
    }
    pub fn to_type_bits(&self) -> [u8; 12] {
        let mut out = [0u8; 12];
        out[0..4].copy_from_slice(&self.keypair_address);
        out[4..8].copy_from_slice(&self.tree_height);
        out[8..12].copy_from_slice(&self.tree_index);
        out
    }
}

pub struct ForsPkAdrs {
    pub keypair_address: [u8; 4],
}

impl ForsPkAdrs {
    pub fn from_type_bits(bits: &[u8; 12]) -> Self {
        ForsPkAdrs { keypair_address: bits[0..4].try_into().unwrap() }
    }
    pub fn to_type_bits(&self) -> [u8; 12] {
        let mut out = [0u8; 12];
        out[0..4].copy_from_slice(&self.keypair_address);
        out
    }
}
