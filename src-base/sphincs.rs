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

//md + idx_tree + idx_leaf
fn hash_msg(r: &[u8], pk_seed: &[u8], pk_root: &[u8], m: &[u8], out_len: usize) -> Vec<u8>{
    let mut data = b"HASHMSG".to_vec();

    data.extend_from_slice(r);
    data.extend_from_slice(pk_seed);
    data.extend_from_slice(pk_root);
    data.extend_from_slice(m);

    shake(&data, out_len)
}

//randomness R
fn prf_msg(sk_prf: &[u8], opt_rand: &[u8], m: &[u8]) -> Vec<u8>{
    let mut data = b"PRF_MSG".to_vec();

    data.extend_from_slice(sk_prf);
    data.extend_from_slice(opt_rand);
    data.extend_from_slice(m);

    shake(&data, parameter_length_N)
}

pub fn spx_keygen<R: RngCore + CryptoRng>(mut rng: R) -> (Vec<u8>, Vec<u8>) {
    if debug_mode{
        println!("--------------SPHINCS KEYGEN--------------------");
    }

    let n = parameter_length_N;

    let mut sk_seed = vec![0u8; n]; //SK seed
    let mut sk_prf = vec![0u8; n];  //SK prf
    let mut pk_seed = vec![0u8; n]; //PK seed

    rng.fill_bytes(&mut sk_seed);
    rng.fill_bytes(&mut sk_prf);
    rng.fill_bytes(&mut pk_seed);

    let pk_root = ht_pk_gen(&sk_seed, &pk_seed); //PK root

    if debug_mode{
        println!("sk_seed: {:?}", sk_seed);
        println!("sk_prf: {:?}", sk_prf);
        println!("pk_seed: {:?}", pk_seed);
        println!("pk_root: {:?}", pk_root);
    }

    //pack key bytes
    let mut sk = Vec::with_capacity(secret_key_length);
    sk.extend_from_slice(&sk_seed);
    sk.extend_from_slice(&sk_prf);
    sk.extend_from_slice(&pk_seed);
    sk.extend_from_slice(&pk_root);

    let mut pk = Vec::with_capacity(public_key_length);
    pk.extend_from_slice(&pk_seed);
    pk.extend_from_slice(&pk_root);

    (sk, pk)
}

pub fn spx_sign<R: RngCore + CryptoRng>(m: &[u8], sk_bytes: &[u8], mut rng: R) -> Vec<u8> {
    let mut adrs = Adrs::new();

    if debug_mode{
        println!("---------------------SPHINCS SIGN----------------------");
        println!("message bytes: {:?}", m);
    }

    //MODIFICATION
    //split sk
    let n = parameter_length_N;
    let sk_seed = &sk_bytes[0..n];
    let sk_prf = &sk_bytes[n..2 * n];
    let pk_seed = &sk_bytes[2 * n..3 * n];
    let pk_root = &sk_bytes[3 * n..4 * n];

    //generate randomness R
    let mut opt_rand = vec![0u8; parameter_length_N];
    if randomize_signatures {
        rng.fill_bytes(&mut opt_rand);
    }

    let r = prf_msg(sk_prf, &opt_rand, m);

    //hash message: md, idx_tree, idx_leaf
    let h_prime = hypertree_height / hypertree_layers;
    let md_bytes = (fors_trees_number * fors_tree_height + 7) / 8;
    let idx_tree_bytes = (hypertree_height - h_prime + 7) / 8;
    let idx_leaf_bytes = (h_prime + 7) / 8;

    let digest = hash_msg(&r, pk_seed, pk_root, m, md_bytes + idx_tree_bytes + idx_leaf_bytes);

    let mut offset = 0;
    let md = &digest[offset..offset + md_bytes];
    offset += md_bytes;

    let tmp_idx_tree = &digest[offset..offset + idx_tree_bytes];
    offset += idx_tree_bytes;

    let tmp_idx_leaf = &digest[offset..offset + idx_leaf_bytes];

    let mut idx_tree_vec = tmp_idx_tree.to_vec(); //stuff zeros in front until it becomes 8 bytes, then convert it
    while idx_tree_vec.len() < 8{
        idx_tree_vec.insert(0, 0);
    }

    let idx_tree_u64 = u64::from_be_bytes(idx_tree_vec[0..8].try_into().unwrap());
    let idx_tree = idx_tree_u64 >> (tmp_idx_tree.len() * 8 - (hypertree_height - h_prime));

    let mut idx_leaf_vec = tmp_idx_leaf.to_vec();
    while idx_leaf_vec.len() < 8{
        idx_leaf_vec.insert(0, 0);
    }

    let idx_leaf_u64 = u64::from_be_bytes(idx_leaf_vec[0..8].try_into().unwrap());
    let idx_leaf = (idx_leaf_u64 >> (tmp_idx_leaf.len() * 8 - h_prime)) as usize;

    if debug_mode{
        println!("R: {:?}", r);
        println!("md: {:?}", md);
        println!("idx_tree: {:?}", idx_tree);
        println!("idx_leaf: {:?}", idx_leaf);
    }

    //recover FORS pk
    adrs.set_layer_address(0);
    adrs.set_tree_address(idx_tree as u128);
    adrs.set_type(Adrs::fors_tree);
    adrs.set_key_pair_address(idx_leaf as u32);

    let md_vec = md.to_vec();
    let sig_fors = fors_sign(&md_vec, sk_seed, pk_seed, adrs);
    let pk_fors = fors_pk_from_sig(sig_fors.clone(), md_vec.clone(), pk_seed.to_vec(), adrs);
    adrs.set_type(Adrs::tree);

    //use hypertree to sign FORS pk
    let sig_ht = ht_sign(&pk_fors, sk_seed, pk_seed, idx_tree as u128, idx_leaf);

    //MODIFICATION
    //pack sig
    let mut sig = Vec::with_capacity(total_signature_length);
    sig.extend_from_slice(&r);

    for part in &sig_fors{
        sig.extend_from_slice(part);
    }

    sig.extend_from_slice(&sig_ht);
    sig
}

pub fn spx_verify(m: &[u8], sig_bytes: &[u8], pk_bytes: &[u8]) -> bool{
    let mut adrs = Adrs::new();

    if debug_mode{
        println!("--------------------SPHINCS+ VERIFY--------------------");
        println!("message bytes: {:?}", m);
    }

    //MODIFICATION
    //split pk and sig
    let n = parameter_length_N;

    let pk_seed = &pk_bytes[0..n];
    let pk_root = &pk_bytes[n..2 * n];

    let r = sig_bytes[0..n].to_vec();

    let fors_end = n + fors_signature_length;
    let sig_fors_raw = sig_bytes[n..fors_end].to_vec();

    let mut sig_fors = Vec::new();
    let mut start = 0;
    while start < sig_fors_raw.len(){
        let end = start + n;
        sig_fors.push(sig_fors_raw[start..end].to_vec());
        start = end;
    }

    let sig_ht = sig_bytes[fors_end..total_signature_length].to_vec();

    //recompute md, idx_tree, idx_leaf from message and R
    let h_prime = hypertree_height / hypertree_layers;
    let md_bytes = (fors_trees_number * fors_tree_height + 7) / 8;
    let idx_tree_bytes = (hypertree_height - h_prime + 7) / 8;
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
    let idx_tree = idx_tree_u64 >> (tmp_idx_tree.len() * 8 - (hypertree_height - h_prime));

    let mut idx_leaf_vec = tmp_idx_leaf.to_vec();
    while idx_leaf_vec.len() < 8{
        idx_leaf_vec.insert(0, 0);
    }
    let idx_leaf_u64 = u64::from_be_bytes(idx_leaf_vec[0..8].try_into().unwrap());
    let idx_leaf = (idx_leaf_u64 >> (tmp_idx_leaf.len() * 8 - h_prime)) as usize;

    if debug_mode{
        println!("R: {:?}", r);
        println!("md: {:?}", md);
        println!("idx_tree: {:?}", idx_tree);
        println!("idx_leaf: {:?}", idx_leaf);
    }

    //rebuild FORS pk
    adrs.set_layer_address(0);
    adrs.set_tree_address(idx_tree as u128);
    adrs.set_type(Adrs::fors_tree);
    adrs.set_key_pair_address(idx_leaf as u32);

    let md_vec = md.to_vec();
    let pk_fors = fors_pk_from_sig(sig_fors, md_vec, pk_seed.to_vec(), adrs);

    //verify ht sig on that FORS pk
    adrs.set_type(Adrs::tree);
    ht_verify(pk_fors, sig_ht, pk_seed.to_vec(), idx_tree as u128, idx_leaf, pk_root.to_vec())
}