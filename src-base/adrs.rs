#[derive(Clone, Copy, Debug, Default)]

pub struct Adrs{
    pub layer_address: u32, //hypertree layer
    pub tree_address: u128, //only use the last 12 bytes
    pub address_type: u32,
    pub word_1: u32, //key pair address
    pub word_2: u32, //chain address/tree height
    pub word_3: u32, //hash address/tree index
}

impl Adrs{
    //different types, used in Adrs.address_type
    pub const wots_hash: u32 = 0;
    pub const wots_pk: u32 = 1;
    pub const tree: u32 = 2;
    pub const fors_tree: u32 = 3;
    pub const fors_roots: u32 = 4;

    pub fn new() -> Self{
        let adrs = Adrs::default();
        adrs
    }

    //build the ADRS 32B
    pub fn get_bytes(&self) -> [u8; 32]{
        let mut result = [0u8; 32];
    
        let layer_bytes = self.layer_address.to_be_bytes();
        for i in 0..4{
            result[i] = layer_bytes[i];
        }
    
        let tree_bytes = self.tree_address.to_be_bytes();
        for i in 0..12{
            result[4 + i] = tree_bytes[4 + i];
        }
    
        let type_bytes = self.address_type.to_be_bytes();
        for i in 0..4{
            result[16 + i] = type_bytes[i];
        }
    
        let word_1_bytes = self.word_1.to_be_bytes();
        for i in 0..4{
            result[20 + i] = word_1_bytes[i];
        }
    
        let word_2_bytes = self.word_2.to_be_bytes();
        for i in 0..4{
            result[24 + i] = word_2_bytes[i];
        }
    
        let word_3_bytes = self.word_3.to_be_bytes();
        for i in 0..4{
            result[28 + i] = word_3_bytes[i];
        }
    
        result
    }

    pub fn set_type(&mut self, adrs_type: u32){
        if adrs_type > 4{
            println!("address type out of range: {}", adrs_type);
            panic!("[adrs.rs:set_type]Address type out of range!");
        }

        //have to set the value as 0 when switching
        self.address_type = adrs_type;
        self.word_1 = 0;
        self.word_2 = 0;
        self.word_3 = 0;
    }

    pub fn set_layer_address(&mut self, val: u32){
        self.layer_address = val;
    }

    pub fn set_tree_address(&mut self, val: u128){
        self.tree_address = val;
    }

    //WOTS/FORS: key pair address
    pub fn set_key_pair_address(&mut self, val: u32){
        self.word_1 = val;
    }

    //WOTS: chain number
    pub fn set_chain_address(&mut self, val: u32){
        self.word_2 = val;
    }

    //WOTS: hash step
    pub fn set_hash_address(&mut self, val: u32){
        self.word_3 = val;
    }

    //node height
    pub fn set_tree_height(&mut self, val: u32){
        self.word_2 = val;
    }

    //node index
    pub fn set_tree_index(&mut self, val: u32){
        self.word_3 = val;
    }

    pub fn get_layer_address(&self) -> u32{
        self.layer_address
    }

    pub fn get_tree_address(&self) -> u128{
        self.tree_address
    }

    pub fn get_type(&self) -> u32{
        self.address_type
    }

    pub fn get_word_1(&self) -> u32{
        self.word_1
    }

    pub fn get_word_2(&self) -> u32{
        self.word_2
    }

    pub fn get_word_3(&self) -> u32{
        self.word_3
    }

    pub fn get_key_pair_address(&self) -> u32{
        self.word_1
    }

    pub fn get_tree_height(&self) -> u32{
        self.word_2
    }

    pub fn get_tree_index(&self) -> u32{
        self.word_3
    }
}
