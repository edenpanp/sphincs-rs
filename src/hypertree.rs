use crate::adrs::Adrs;
use crate::parameters::*;
use crate::xmss::*;

pub fn ht_pk_gen(sk_seed: &[u8], pk_seed: &[u8]) -> Vec<u8> {
    let mut adrs = Adrs::new();
    adrs.set_layer_address((HYPERTREE_LAYERS - 1) as u32); //set as highest layer
    adrs.set_tree_address(0); //highest tree

    treehash(sk_seed, 0, XMSS_SUBTREE_HEIGHT, pk_seed, adrs)

}

pub fn ht_sign(m: &[u8], sk_seed: &[u8], pk_seed: &[u8], mut idx_tree: u128, mut idx_leaf: usize) -> Vec<u8>{
    let mut adrs = Adrs::new();
    if DEBUG_MODE{
        println!("-------------HYPERTREE SIGN---------------------");
        println!("input bytes: {:?}", m);
        println!("idx_tree = {}", idx_tree);
        println!("idx_leaf = {}", idx_leaf);
    }

    adrs.set_layer_address(0);
    adrs.set_tree_address(idx_tree);

    let first_sig_nodes = xmss_sign(m, sk_seed, idx_leaf, pk_seed, adrs);

    let mut sig_ht = Vec::with_capacity(HYPERTREE_SIGNATURE_LENGTH);
    for node in &first_sig_nodes{
        sig_ht.extend_from_slice(node);
    }


    let mut root = xmss_pk_from_sig(idx_leaf, first_sig_nodes, m, pk_seed, adrs);
    if DEBUG_MODE{
        println!("layer 0 root bytes: {:?}", root);
    }

    for layer in 1..HYPERTREE_LAYERS{
        idx_leaf = (idx_tree % (1 << XMSS_SUBTREE_HEIGHT)) as usize;
        idx_tree >>= XMSS_SUBTREE_HEIGHT;

        adrs.set_layer_address(layer as u32);
        adrs.set_tree_address(idx_tree);

        if DEBUG_MODE{
            println!("layer {}", layer);
            println!("  idx_tree = {}", idx_tree);
            println!("  idx_leaf = {}", idx_leaf);
        }

        let sig_nodes = xmss_sign(&root, sk_seed, idx_leaf, pk_seed, adrs);

        for node in &sig_nodes{
            sig_ht.extend_from_slice(node);
        }

        if layer < HYPERTREE_LAYERS - 1{
            root = xmss_pk_from_sig(idx_leaf, sig_nodes, &root, pk_seed, adrs);
            if DEBUG_MODE{
                println!("new root bytes: {:?}", root);
            }
        }
    }

    sig_ht
}

pub fn ht_verify(m: Vec<u8>, sig_ht: Vec<u8>, pk_seed: Vec<u8>, mut idx_tree: u128, mut idx_leaf: usize, pk_root: Vec<u8>) -> bool{
    let mut adrs = Adrs::new();

    let xmss_sig_len = (XMSS_SUBTREE_HEIGHT + WOTS_TOTAL_LENGTH) * PARAMETER_LENGTH_N;

    adrs.set_layer_address(0);
    adrs.set_tree_address(idx_tree);

    let mut first_sig = Vec::new();
    let mut start = 0;
    while start < xmss_sig_len{
        let end = start + PARAMETER_LENGTH_N;
        first_sig.push(sig_ht[start..end].to_vec());
        start = end;
    }

    let mut node = xmss_pk_from_sig(idx_leaf, first_sig, &m, &pk_seed, adrs);

    for layer in 1..HYPERTREE_LAYERS{
        idx_leaf = (idx_tree % (1 << XMSS_SUBTREE_HEIGHT)) as usize;
        idx_tree >>= XMSS_SUBTREE_HEIGHT;

        adrs.set_layer_address(layer as u32);
        adrs.set_tree_address(idx_tree);

        let part_start = layer * xmss_sig_len;
        let part_end = part_start + xmss_sig_len;

        let mut layer_sig = Vec::new();
        let mut pos = part_start;
        while pos < part_end{
            let end = pos + PARAMETER_LENGTH_N;
            layer_sig.push(sig_ht[pos..end].to_vec());
            pos = end;
        }


        node = xmss_pk_from_sig(idx_leaf, layer_sig, &node, &pk_seed, adrs);
    }

    node == pk_root
}