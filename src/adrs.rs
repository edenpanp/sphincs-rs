//Discriminant for the five SPHINCS+ address types
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdrsType {
    Wots = 0,
    WotsPk = 1,
    TreeNode = 2,
    ForsTree = 3,
    ForsPk = 4,
}

impl AdrsType {
    pub fn to_u32(self) -> u32 {
        self as u32
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Adrs {
    pub layer_address: [u8; 4], //  4 bytes – layer in the hypertree
    pub tree_address: [u8; 12], // 12 bytes – tree within the layer (64-bit + 4 padding)
    pub adrs_type: AdrsType,    //  4 bytes – discriminant stored as u32
    pub type_bits: [u8; 12],    // 12 bytes – type-specific fields (see table above)
}

impl Adrs {
    pub fn new(adrs_type: AdrsType) -> Self {
        Adrs {
            layer_address: [0u8; 4],
            tree_address: [0u8; 12],
            adrs_type,
            type_bits: [0u8; 12],
        }
    }

    //32-byte ADRS (big-endian)
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[0..4].copy_from_slice(&self.layer_address);
        out[4..16].copy_from_slice(&self.tree_address);
        out[16..20].copy_from_slice(&self.adrs_type.to_u32().to_be_bytes());
        out[20..32].copy_from_slice(&self.type_bits);
        out
    }

    //Set the layer address
    pub fn set_layer_address(&mut self, layer: u32) {
        self.layer_address = layer.to_be_bytes();
    }

    pub fn get_layer_address(&self) -> u32 {
        u32::from_be_bytes(self.layer_address)
    }

    //12-byte tree_address field
    pub fn set_tree_address(&mut self, tree: u64) {
        self.tree_address[0..4].fill(0); //zero padding
        self.tree_address[4..12].copy_from_slice(&tree.to_be_bytes());
    }

    pub fn get_tree_address(&self) -> u64 {
        u64::from_be_bytes(self.tree_address[4..12].try_into().unwrap())
    }

    pub fn set_type_and_clear(&mut self, adrs_type: AdrsType) {
        self.adrs_type = adrs_type;
        self.type_bits = [0u8; 12];
    }

    pub fn set_keypair_address(&mut self, kp: u32) {
        self.type_bits[0..4].copy_from_slice(&kp.to_be_bytes());
    }

    pub fn get_keypair_address(&self) -> u32 {
        u32::from_be_bytes(self.type_bits[0..4].try_into().unwrap())
    }

    pub fn set_chain_address(&mut self, chain: u32) {
        self.type_bits[4..8].copy_from_slice(&chain.to_be_bytes());
    }

    pub fn get_chain_address(&self) -> u32 {
        u32::from_be_bytes(self.type_bits[4..8].try_into().unwrap())
    }

    pub fn set_hash_address(&mut self, hash: u32) {
        self.type_bits[8..12].copy_from_slice(&hash.to_be_bytes());
    }

    pub fn get_hash_address(&self) -> u32 {
        u32::from_be_bytes(self.type_bits[8..12].try_into().unwrap())
    }

    pub fn set_tree_height(&mut self, height: u32) {
        self.type_bits[4..8].copy_from_slice(&height.to_be_bytes());
    }

    pub fn get_tree_height(&self) -> u32 {
        u32::from_be_bytes(self.type_bits[4..8].try_into().unwrap())
    }

    pub fn set_tree_index(&mut self, index: u32) {
        self.type_bits[8..12].copy_from_slice(&index.to_be_bytes());
    }

    pub fn get_tree_index(&self) -> u32 {
        u32::from_be_bytes(self.type_bits[8..12].try_into().unwrap())
    }
}

pub struct WotsAdrs {
    pub keypair_address: [u8; 4],
    pub chain_address: [u8; 4],
    pub hash_address: [u8; 4],
}

impl WotsAdrs {
    pub fn from_type_bits(bits: &[u8; 12]) -> Self {
        WotsAdrs {
            keypair_address: bits[0..4].try_into().unwrap(),
            chain_address: bits[4..8].try_into().unwrap(),
            hash_address: bits[8..12].try_into().unwrap(),
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
        WotsPkAdrs {
            keypair_address: bits[0..4].try_into().unwrap(),
        }
    }
    pub fn to_type_bits(&self) -> [u8; 12] {
        let mut out = [0u8; 12];
        out[0..4].copy_from_slice(&self.keypair_address);
        out
    }
}

pub struct TreeNodeAdrs {
    pub tree_height: [u8; 4],
    pub tree_index: [u8; 4],
}

impl TreeNodeAdrs {
    pub fn from_type_bits(bits: &[u8; 12]) -> Self {
        TreeNodeAdrs {
            tree_height: bits[4..8].try_into().unwrap(),
            tree_index: bits[8..12].try_into().unwrap(),
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
    pub tree_height: [u8; 4],
    pub tree_index: [u8; 4],
}

impl ForsTreeAdrs {
    pub fn from_type_bits(bits: &[u8; 12]) -> Self {
        ForsTreeAdrs {
            keypair_address: bits[0..4].try_into().unwrap(),
            tree_height: bits[4..8].try_into().unwrap(),
            tree_index: bits[8..12].try_into().unwrap(),
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
        ForsPkAdrs {
            keypair_address: bits[0..4].try_into().unwrap(),
        }
    }
    pub fn to_type_bits(&self) -> [u8; 12] {
        let mut out = [0u8; 12];
        out[0..4].copy_from_slice(&self.keypair_address);
        out
    }
}
