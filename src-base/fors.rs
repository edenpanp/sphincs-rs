use crate::adrs::Adrs;
use crate::parameters::*;
use tiny_keccak::{Hasher, Shake};

fn shake(data: &[u8], out_len: usize) -> Vec<u8>{
    let mut hasher = Shake::v256();
    hasher.update(data);
    let mut out = vec![0u8; out_len];
    hasher.finalize(&mut out);
    out
}

//for FORS nodes and key compression
fn hash(pk_seed: &[u8], adrs: &Adrs, m: &[u8], out_len: usize) -> Vec<u8>{
    let mut data = b"TREEHASH".to_vec();

    data.extend_from_slice(pk_seed);
    data.extend_from_slice(&adrs.get_bytes());
    data.extend_from_slice(m);

    shake(&data, out_len)
}

fn prf(sk_seed: &[u8], adrs: &Adrs) -> Vec<u8>{
    let mut data = b"SECRETSEED".to_vec();

    data.extend_from_slice(sk_seed);
    data.extend_from_slice(&adrs.get_bytes());

    shake(&data, parameter_length_N)
}

pub fn fors_treehash(sk_seed: &[u8], s: usize, z: usize, pk_seed: &[u8], mut adrs: Adrs) -> Vec<u8>{
    if s % (1 << z) != 0{
        println!("wrong start index: s = {}, z = {}", s, z);
        panic!("[fors.rs: fors_treehash] start index s error for height z");
    }

    let mut stack: Vec<(Vec<u8>, usize)> = Vec::new();

    for i in 0..(1 << z){
        adrs.set_tree_height(0);
        adrs.set_tree_index((s + i) as u32);

        let sk = prf(sk_seed, &adrs);
        let mut node = hash(pk_seed, &adrs, &sk, parameter_length_N);

        adrs.set_tree_height(1);
        adrs.set_tree_index((s + i) as u32);

        while !stack.is_empty() && stack.last().unwrap().1 == adrs.get_tree_height() as usize{
            adrs.set_tree_index((adrs.get_tree_index() - 1) / 2);

            let (stack_node, _) = stack.pop().unwrap();
            let mut combined = Vec::with_capacity(parameter_length_N * 2);

            combined.extend_from_slice(&stack_node);
            combined.extend_from_slice(&node);

            node = hash(&pk_seed, &adrs, &combined, parameter_length_N);

            adrs.set_tree_height(adrs.get_tree_height() + 1);
        }

        stack.push((node, adrs.get_tree_height() as usize));
    }

    stack.pop().unwrap().0
}

pub fn fors_sign(md: &[u8], sk_seed: &[u8], pk_seed: &[u8], mut adrs: Adrs) -> Vec<Vec<u8>>{
    if debug_mode{
        println!("---------------FORS SIGN------------------");
        println!("message digest bytes: {:?}", md);
    }

    let mut sig_fors = Vec::new();

    for i in 0..fors_trees_number{
        let idx = get_idx_from_digest(&md, i);

        if debug_mode{
            println!("tree {} -> idx {}", i, idx);
        }

        adrs.set_tree_height(0);
        adrs.set_tree_index((i * fors_leaves + idx) as u32);

    //compute fors sk
        let leaf_sk = prf(sk_seed, &adrs);

        sig_fors.push(leaf_sk);

        //compute path
        for j in 0..fors_tree_height{
            let mut s = idx / (1 << j); //get block index in j layer
            //get sibling index
            if s % 2 == 1{
                s -= 1;
            }
            else{
                s += 1;
            }

            let node = fors_treehash(sk_seed, i * fors_leaves + s * (1 << j), j, pk_seed, adrs);
            sig_fors.push(node);
        }
    }

    sig_fors
}

//get FORS root -> pk
pub fn fors_pk_from_sig(sig_fors: Vec<Vec<u8>>, md: Vec<u8>, pk_seed: Vec<u8>, mut adrs: Adrs) -> Vec<u8>{
    //-------------------MODIFICATION-------------------
    //split each [sk, auth path...]
    let step = fors_tree_height + 1;

    let mut roots = Vec::with_capacity(fors_trees_number * parameter_length_N);

    for i in 0..fors_trees_number{
        let idx = get_idx_from_digest(&md, i);
        let sk = &sig_fors[i * step];

        adrs.set_tree_height(0);
        adrs.set_tree_index((i * fors_leaves + idx) as u32);

        let mut node = hash(&pk_seed, &adrs, sk, parameter_length_N);

        for j in 0..fors_tree_height{
            let auth_node = &sig_fors[i * step + 1 + j];

            adrs.set_tree_height((j + 1) as u32);

            let mut combined = Vec::with_capacity(parameter_length_N * 2);
            //left node: node + auth
            if (idx / (1 << j)) % 2 == 0{
                adrs.set_tree_index(adrs.get_tree_index() / 2);
                combined.extend_from_slice(&node);
                combined.extend_from_slice(auth_node);
            }
            //right node: auth + node
            else{
                adrs.set_tree_index((adrs.get_tree_index() - 1) / 2);
                combined.extend_from_slice(auth_node);
                combined.extend_from_slice(&node);
            }
            node = hash(&pk_seed, &adrs, &combined, parameter_length_N);
        }

        roots.extend_from_slice(&node);
    }

    let mut fors_pk_adrs = adrs;
    fors_pk_adrs.set_type(Adrs::fors_roots);
    fors_pk_adrs.set_key_pair_address(adrs.get_key_pair_address());

    hash(&pk_seed, &fors_pk_adrs, &roots, parameter_length_N)
}

//digest is interpreted as 'fors_trees_number' chunks, each chunk of size 'fors_tree_height' bits.
fn get_idx_from_digest(md: &[u8], i: usize) -> usize{
    let bit_offset = (fors_trees_number - 1 - i) * fors_tree_height;
    let byte_offset = bit_offset / 8;
    let bit_in_byte = bit_offset % 8;

    let mut val = 0u64;
    for j in 0..((fors_tree_height + 7) / 8 + 1){
        if byte_offset + j < md.len(){
            val = (val << 8) | (md[md.len() - 1 - (byte_offset + j)] as u64);
        }
    }

    ((val >> bit_in_byte) as usize) & (fors_leaves - 1)
}