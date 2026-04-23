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

pub fn treehash(sk_seed: &[u8], s: usize, z: usize, pk_seed: &[u8], mut adrs: Adrs) -> Vec<u8>{
    if s % (1 << z) != 0{
        println!("[xmss.ra: treehash] treehash bad start index: s = {}, z = {}", s, z);
        panic!("[xmss.ra: treehash] start index s error (for height z)");
    }

    let mut stack: Vec<(Vec<u8>, u32)> = Vec::new();
    for i in 0..(1 << z){
        adrs.set_type(Adrs::WOTS_HASH);
        adrs.set_key_pair_address((s + i) as u32);

        let mut node = wots_pk_gen(sk_seed, pk_seed, adrs);

        adrs.set_type(Adrs::TREE);
        adrs.set_tree_height(1);
        adrs.set_tree_index((s + i) as u32);

        while !stack.is_empty() && stack.last().unwrap().1 == adrs.get_tree_height(){
            adrs.set_tree_index((adrs.get_tree_index() - 1) / 2);

            let (stack_node, _) = stack.pop().unwrap();
            let mut combined = Vec::with_capacity(PARAMETER_LENGTH_N * 2);
            combined.extend_from_slice(&stack_node);
            combined.extend_from_slice(&node);

            node = hash(pk_seed, &adrs, &combined, PARAMETER_LENGTH_N);
            adrs.set_tree_height(adrs.get_tree_height() + 1);
        }

        stack.push((node, adrs.get_tree_height()));
    }

    stack.pop().unwrap().0
}

pub fn xmss_sign(m: &[u8], sk_seed: &[u8], idx: usize, pk_seed: &[u8], mut adrs: Adrs) -> Vec<Vec<u8>>{
    if DEBUG_MODE{
        println!("-----------------XMSS SIGN-------------------");
        println!("xmss message: {:?}", m);
        println!("leaf index = {}", idx);
    }

    let mut auth = Vec::new();

    for j in 0..XMSS_SUBTREE_HEIGHT{
        let mut sibling = idx / (1 << j);

        if sibling % 2 == 1{
            sibling -= 1;
        }
        else{
            sibling += 1;
        }

        let node = treehash(sk_seed, sibling * (1 << j), j, pk_seed, adrs);

        if DEBUG_MODE{
            println!("auth level {}, sibling index = {}", j, sibling);
        }
        auth.push(node);
    }

    adrs.set_type(Adrs::WOTS_HASH);
    adrs.set_key_pair_address(idx as u32);

    let sig_wots = wots_sign(m, sk_seed, pk_seed, adrs);
    let mut sig_xmss = sig_wots;
    sig_xmss.extend(auth);

    if DEBUG_MODE{
        println!("---------------xmss signature generated----------------");
    }

    sig_xmss
}

pub fn xmss_pk_from_sig(idx: usize, sig_xmss: Vec<Vec<u8>>, m: &[u8], pk_seed: &[u8], mut adrs: Adrs) -> Vec<u8>{
    let (sig_wots, auth) = sig_xmss.split_at(WOTS_TOTAL_LENGTH);
    let sig_wots_vec = sig_wots.to_vec();

    adrs.set_type(Adrs::WOTS_HASH);
    adrs.set_key_pair_address(idx as u32);

    let mut node = wots_pk_from_sig(sig_wots_vec, m, pk_seed, adrs);

    adrs.set_type(Adrs::TREE);
    adrs.set_tree_index(idx as u32);

    for i in 0..XMSS_SUBTREE_HEIGHT{
        adrs.set_tree_height((i + 1) as u32);

        let mut combined = Vec::with_capacity(PARAMETER_LENGTH_N * 2);
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

        node = hash(pk_seed, &adrs, &combined, PARAMETER_LENGTH_N);
    }

    node
}