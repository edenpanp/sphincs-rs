use crate::adrs::Adrs;
use crate::parameters::*;
use crate::wots::*;
use tiny_keccak::{Hasher, Shake};

fn shake(data: &[u8], out_len: usize) -> Vec<u8>{
    let mut hasher = Shake::v256();
    hasher.update(data);

    let mut out = vec![0u8; out_len];
    hasher.finalize(&mut out);

    out
}

fn hash(pk_seed: &[u8], adrs: &Adrs, m: &[u8], out_len: usize) -> Vec<u8>{
    let mut data = b"TREEHASH".to_vec();

    data.extend_from_slice(pk_seed);
    data.extend_from_slice(&adrs.get_bytes());
    data.extend_from_slice(m);

    shake(&data, out_len)
}

//compute root: height z starting at leaf s
pub fn treehash(sk_seed: &[u8], s: usize, z: usize, pk_seed: &[u8], mut adrs: Adrs) -> Vec<u8>{
    if s % (1 << z) != 0{
        println!("[xmss.ra: treehash] treehash bad start index: s = {}, z = {}", s, z);
        panic!("[xmss.ra: treehash] start index s error (for height z)");
    }

    let mut stack: Vec<(Vec<u8>, u32)> = Vec::new();
    //generate leaves one by one
    for i in 0..(1 << z){
        //build leaf i
        adrs.set_type(Adrs::wots_hash);
        adrs.set_key_pair_address((s + i) as u32);

        let mut node = wots_pk_gen(sk_seed, pk_seed, adrs);

        adrs.set_type(Adrs::tree);
        adrs.set_tree_height(1);
        adrs.set_tree_index((s + i) as u32);

        //merge node
        while !stack.is_empty() && stack.last().unwrap().1 == adrs.get_tree_height(){
            adrs.set_tree_index((adrs.get_tree_index() - 1) / 2);

            let (stack_node, _) = stack.pop().unwrap();
            let mut combined = Vec::with_capacity(parameter_length_N * 2);
            combined.extend_from_slice(&stack_node);
            combined.extend_from_slice(&node);

            node = hash(pk_seed, &adrs, &combined, parameter_length_N);
            adrs.set_tree_height(adrs.get_tree_height() + 1);
        }

        stack.push((node, adrs.get_tree_height()));
        //println!("stack len after push = {}", stack.len());
    }

    stack.pop().unwrap().0
}

//xmss sig: wots sig + path
pub fn xmss_sign(m: &[u8], sk_seed: &[u8], idx: usize, pk_seed: &[u8], mut adrs: Adrs) -> Vec<Vec<u8>>{
    if debug_mode{
        println!("-----------------XMSS SIGN-------------------");
        println!("xmss message: {:?}", m);
        println!("leaf index = {}", idx);
    }

    let mut auth = Vec::new();

    //compute the sibling subtree root 
    for j in 0..xmss_subtree_height{
        let mut sibling = idx / (1 << j);

        if sibling % 2 == 1{
            sibling -= 1;
        }
        else{
            sibling += 1;
        }

        let node = treehash(sk_seed, sibling * (1 << j), j, pk_seed, adrs);

        if debug_mode{
            println!("auth level {}, sibling index = {}", j, sibling);
        }
        auth.push(node);
    }

    adrs.set_type(Adrs::wots_hash);
    adrs.set_key_pair_address(idx as u32);

    let sig_wots = wots_sign(m, sk_seed, pk_seed, adrs);
    let mut sig_xmss = sig_wots;
    sig_xmss.extend(auth);

    if debug_mode{
        println!("---------------xmss signature generated----------------");
    }

    sig_xmss
}

pub fn xmss_pk_from_sig(idx: usize, sig_xmss: Vec<Vec<u8>>, m: &[u8], pk_seed: &[u8], mut adrs: Adrs) -> Vec<u8>{
    let (sig_wots, auth) = sig_xmss.split_at(wots_total_length);
    let sig_wots_vec = sig_wots.to_vec();

    adrs.set_type(Adrs::wots_hash);
    adrs.set_key_pair_address(idx as u32);

    //recover the WOTS pk
    let mut node = wots_pk_from_sig(sig_wots_vec, m, pk_seed, adrs);

    //set as leaf
    adrs.set_type(Adrs::tree);
    adrs.set_tree_index(idx as u32);

    //walk the path
    for i in 0..xmss_subtree_height{
        adrs.set_tree_height((i + 1) as u32);

        let mut combined = Vec::with_capacity(parameter_length_N * 2);
        if (idx / (1 << i)) % 2 == 0{
            adrs.set_tree_index(adrs.get_tree_index() / 2);
            combined.extend_from_slice(&node);
            combined.extend_from_slice(&auth[i]);
        }
        else{
            adrs.set_tree_index((adrs.get_tree_index() - 1) / 2);
            combined.extend_from_slice(&auth[i]);
            combined.extend_from_slice(&node);
        }

        //get root
        node = hash(pk_seed, &adrs, &combined, parameter_length_N);
    }

    node
}