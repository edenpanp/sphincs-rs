use crate::adrs::Adrs;
use crate::fors::{fors_pk_from_sig, fors_sign};
use crate::hypertree::{ht_pk_gen, ht_sign, ht_verify};
use crate::parameters::*;
use tiny_keccak::{Hasher, Shake};
use rand_core::{CryptoRng, RngCore};
use std::convert::TryInto;

fn shake(data: &[u8], out_len: usize) -> Vec<u8>{
    let mut hasher = Shake::v256();
    hasher.update(data);

    let mut out = vec![0u8; out_len];
    hasher.finalize(&mut out);

    out
}


fn hash_msg(r: &[u8], pk_seed: &[u8], pk_root: &[u8], m: &[u8], out_len: usize) -> Vec<u8>{
    let mut data = b"HASHMSG".to_vec();

    data.extend_from_slice(r);
    data.extend_from_slice(pk_seed);
    data.extend_from_slice(pk_root);
    data.extend_from_slice(m);

    shake(&data, out_len)
}


fn prf_msg(sk_prf: &[u8], opt_rand: &[u8], m: &[u8]) -> Vec<u8>{
    let mut data = b"PRF_MSG".to_vec();

    data.extend_from_slice(sk_prf);
    data.extend_from_slice(opt_rand);
    data.extend_from_slice(m);

    shake(&data, PARAMETER_LENGTH_N)
}


pub fn encode_sk(sk_seed: &[u8], sk_prf: &[u8], pk_seed: &[u8], pk_root: &[u8]) -> Vec<u8>{
    let mut sk = Vec::with_capacity(SECRET_KEY_LENGTH);

    sk.extend_from_slice(sk_seed);
    sk.extend_from_slice(sk_prf);
    sk.extend_from_slice(pk_seed);
    sk.extend_from_slice(pk_root);

    sk
}


pub fn decode_sk(sk_bytes: &[u8]) -> (&[u8], &[u8], &[u8], &[u8]){
    let n = PARAMETER_LENGTH_N;
    (&sk_bytes[0..n], &sk_bytes[n..2 * n], &sk_bytes[2 * n..3 * n], &sk_bytes[3 * n..4 * n])
}


pub fn encode_pk(pk_seed: &[u8], pk_root: &[u8]) -> Vec<u8>{
    let mut pk = Vec::with_capacity(PUBLIC_KEY_LENGTH);

    pk.extend_from_slice(pk_seed);
    pk.extend_from_slice(pk_root);

    pk
}


pub fn decode_pk(pk_bytes: &[u8]) -> (&[u8], &[u8]) {
    let n = PARAMETER_LENGTH_N;
    (&pk_bytes[0..n], &pk_bytes[n..2 * n])
}


pub fn encode_sig(r: &[u8], sig_fors: &Vec<Vec<u8>>, sig_ht: &[u8]) -> Vec<u8> {
    let mut sig = Vec::with_capacity(TOTAL_SIGNATURE_LENGTH);

    sig.extend_from_slice(r);

    for part in sig_fors {
        sig.extend_from_slice(part);
    }

    sig.extend_from_slice(sig_ht);

    sig
}


pub fn decode_sig(sig_bytes: Vec<u8>) -> (Vec<u8>, Vec<Vec<u8>>, Vec<u8>) {
    let n = PARAMETER_LENGTH_N;
    let r = sig_bytes[0..n].to_vec();

    let fors_end = n + FORS_SIGNATURE_LENGTH;
    let sig_fors_raw = sig_bytes[n..fors_end].to_vec();

    let mut sig_fors = Vec::new();
    let mut start = 0;
    while start < sig_fors_raw.len(){
        let end = start + n;
        let part = sig_fors_raw[start..end].to_vec();

        sig_fors.push(part.clone());
        start = end;
    }

    let sig_ht = sig_bytes[fors_end..TOTAL_SIGNATURE_LENGTH].to_vec();

    (r, sig_fors, sig_ht)
}

pub fn spx_keygen<R: RngCore + CryptoRng>(mut rng: R) -> (Vec<u8>, Vec<u8>) {
    if DEBUG_MODE{
        println!("--------------SPHINCS KEYGEN--------------------");
    }

    let n = PARAMETER_LENGTH_N;

    let mut sk_seed = vec![0u8; n]; 
    let mut sk_prf = vec![0u8; n];  
    let mut pk_seed = vec![0u8; n]; 

    rng.fill_bytes(&mut sk_seed);
    rng.fill_bytes(&mut sk_prf);
    rng.fill_bytes(&mut pk_seed);

    let pk_root = ht_pk_gen(&sk_seed, &pk_seed); 

    if DEBUG_MODE{
        println!("sk_seed: {:?}", sk_seed);
        println!("sk_prf: {:?}", sk_prf);
        println!("pk_seed: {:?}", pk_seed);
        println!("pk_root: {:?}", pk_root);
    }

    let sk = encode_sk(&sk_seed, &sk_prf, &pk_seed, &pk_root);
    let pk = encode_pk(&pk_seed, &pk_root);

    (sk, pk)
}

pub fn spx_sign<R: RngCore + CryptoRng>(m: &[u8], sk_bytes: &[u8], mut rng: R) -> Vec<u8> {
    let mut adrs = Adrs::new();

    if DEBUG_MODE{
        println!("---------------------SPHINCS SIGN----------------------");
        println!("message bytes: {:?}", m);
    }

    
    let (sk_seed, sk_prf, pk_seed, pk_root) = decode_sk(sk_bytes);

    
    let mut opt_rand = vec![0u8; PARAMETER_LENGTH_N];
    if RANDOMIZE_SIGNATURES {
        rng.fill_bytes(&mut opt_rand);
    }

    let r = prf_msg(sk_prf, &opt_rand, m);

    
    let h_prime = HYPERTREE_HEIGHT / HYPERTREE_LAYERS;
    let md_bytes = (FORS_TREES_NUMBER * FORS_TREE_HEIGHT + 7) / 8;
    let idx_tree_bytes = (HYPERTREE_HEIGHT - h_prime + 7) / 8;
    let idx_leaf_bytes = (h_prime + 7) / 8;

    let digest = hash_msg(&r, pk_seed, pk_root, m, md_bytes + idx_tree_bytes + idx_leaf_bytes);

    
    let mut offset = 0;
    let md = &digest[offset..offset + md_bytes];
    offset += md_bytes;

    let tmp_idx_tree = &digest[offset..offset + idx_tree_bytes];
    offset += idx_tree_bytes;

    let tmp_idx_leaf = &digest[offset..offset + idx_leaf_bytes];

    
    let mut idx_tree_vec = tmp_idx_tree.to_vec(); 
    while idx_tree_vec.len() < 8{
        idx_tree_vec.insert(0, 0);
    }
    

    let idx_tree_u64 = u64::from_be_bytes(idx_tree_vec[0..8].try_into().unwrap());
    let idx_tree = idx_tree_u64 >> (tmp_idx_tree.len() * 8 - (HYPERTREE_HEIGHT - h_prime));

    let mut idx_leaf_vec = tmp_idx_leaf.to_vec();
    while idx_leaf_vec.len() < 8{
        idx_leaf_vec.insert(0, 0);
    }
    

    let idx_leaf_u64 = u64::from_be_bytes(idx_leaf_vec[0..8].try_into().unwrap());
    let idx_leaf = (idx_leaf_u64 >> (tmp_idx_leaf.len() * 8 - h_prime)) as usize;

    if DEBUG_MODE{
        println!("R: {:?}", r);
        println!("md: {:?}", md);
        println!("idx_tree: {:?}", idx_tree);
        println!("idx_leaf: {:?}", idx_leaf);
        
    }

    
    adrs.set_layer_address(0);
    adrs.set_tree_address(idx_tree as u128);
    adrs.set_type(Adrs::FORS_TREE);
    adrs.set_key_pair_address(idx_leaf as u32);

    let md_vec = md.to_vec();
    
    let sig_fors = fors_sign(&md_vec, sk_seed, pk_seed, adrs);
    
    let pk_fors = fors_pk_from_sig(sig_fors.clone(), md_vec.clone(), pk_seed.to_vec(), adrs);
    adrs.set_type(Adrs::TREE);

    
    let sig_ht = ht_sign(&pk_fors, sk_seed, pk_seed, idx_tree as u128, idx_leaf);

    
    encode_sig(&r, &sig_fors, &sig_ht)
}

pub fn spx_verify(m: &[u8], sig_bytes: &[u8], pk_bytes: &[u8]) -> bool{
    let mut adrs = Adrs::new();

    if DEBUG_MODE{
        println!("--------------------SPHINCS+ VERIFY--------------------");
        println!("message bytes: {:?}", m);
    }

    
    let (pk_seed, pk_root) = decode_pk(pk_bytes);
    let (r, sig_fors, sig_ht) = decode_sig(sig_bytes.to_vec());

    
    let h_prime = HYPERTREE_HEIGHT / HYPERTREE_LAYERS;
    let md_bytes = (FORS_TREES_NUMBER * FORS_TREE_HEIGHT + 7) / 8;
    let idx_tree_bytes = (HYPERTREE_HEIGHT - h_prime + 7) / 8;
    let idx_leaf_bytes = (h_prime + 7) / 8;

    let digest = hash_msg(&r, pk_seed, pk_root, m, md_bytes + idx_tree_bytes + idx_leaf_bytes);

    let mut offset = 0;
    let md = &digest[offset..offset + md_bytes];
    offset += md_bytes;

    let tmp_idx_tree = &digest[offset..offset + idx_tree_bytes];
    offset += idx_tree_bytes;

    let tmp_idx_leaf = &digest[offset..offset + idx_leaf_bytes];

    let mut idx_tree_vec = tmp_idx_tree.to_vec();
    while idx_tree_vec.len() < 8{
        idx_tree_vec.insert(0, 0);
    }
    let idx_tree_u64 = u64::from_be_bytes(idx_tree_vec[0..8].try_into().unwrap());
    let idx_tree = idx_tree_u64 >> (tmp_idx_tree.len() * 8 - (HYPERTREE_HEIGHT - h_prime));

    let mut idx_leaf_vec = tmp_idx_leaf.to_vec();
    while idx_leaf_vec.len() < 8{
        idx_leaf_vec.insert(0, 0);
    }
    let idx_leaf_u64 = u64::from_be_bytes(idx_leaf_vec[0..8].try_into().unwrap());
    let idx_leaf = (idx_leaf_u64 >> (tmp_idx_leaf.len() * 8 - h_prime)) as usize;

    if DEBUG_MODE{
        println!("R: {:?}", r);
        println!("md: {:?}", md);
        println!("idx_tree: {:?}", idx_tree);
        println!("idx_leaf: {:?}", idx_leaf);
    }

    
    adrs.set_layer_address(0);
    adrs.set_tree_address(idx_tree as u128);
    adrs.set_type(Adrs::FORS_TREE);
    adrs.set_key_pair_address(idx_leaf as u32);

    let md_vec = md.to_vec();
    let pk_fors = fors_pk_from_sig(sig_fors.clone(), md_vec.clone(), pk_seed.to_vec(), adrs);

    
    adrs.set_type(Adrs::TREE);
    ht_verify(pk_fors.clone(), sig_ht.clone(), pk_seed.to_vec(), idx_tree as u128, idx_leaf, pk_root.to_vec())
    
}
