//true: generate the random signature
//256s parameters
pub const randomize_signatures: bool = true;

pub const parameter_length_N: usize = 32; // main byte length n

pub const winternitz_parameter: usize = 16; //WOTS+ base parameter w

pub const hypertree_height: usize = 64; //total hypertree height h
pub const hypertree_layers: usize = 8;  //number of hypertree layers d

pub const fors_trees_number: usize = 22; //number of FORS trees k
pub const fors_tree_height: usize = 14; //height of each FORS tree a

pub const debug_mode: bool = true;

const log_w: usize = winternitz_parameter.ilog2() as usize; //log2(w)

//number of base-w digits needed to encode an n-byte message digest
pub const wots_length_1: usize = (8 * parameter_length_N + log_w - 1) / log_w; //ceil(8n / log2(w))
//number of extra chains needed for the checksum
pub const wots_length_2: usize = ((wots_length_1 * (winternitz_parameter - 1)).ilog2() as usize / log_w) + 1; //number of WOTS chains, for checksum
pub const wots_total_length: usize = wots_length_1 + wots_length_2; //total number of WOTS chains

pub const xmss_subtree_height: usize = hypertree_height / hypertree_layers; //XMSS subtree height

pub const fors_leaves: usize = 1 << fors_tree_height; //FORS tree leaves: 2^a
//k trees*(1 leaf + nodes)
pub const fors_signature_length: usize = fors_trees_number * (fors_tree_height + 1) * parameter_length_N; 

//WOTS signature + path
pub const xmss_signature_length: usize = (wots_total_length + xmss_subtree_height) * parameter_length_N; 

pub const hypertree_signature_length: usize = hypertree_layers * xmss_signature_length;

pub const total_signature_length: usize = parameter_length_N + fors_signature_length + hypertree_signature_length;

//PK seed + PK root
pub const public_key_length: usize = 2 * parameter_length_N;
//SK seed + SK prf + PK seed + PK root
pub const secret_key_length: usize = 4 * parameter_length_N;