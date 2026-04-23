use crate::adrs::Adrs;
use crate::parameters::*;
use crate::xmss::*;


fn get_sigs_xmss_from_sig_ht(sig_ht: &[u8]) -> Vec<&[u8]>{
    let mut parts = Vec::new();

    let xmss_sig_len = (XMSS_SUBTREE_HEIGHT + WOTS_TOTAL_LENGTH) * PARAMETER_LENGTH_N;
    let mut start = 0;

    for _ in 0..HYPERTREE_LAYERS{
        let end = start + xmss_sig_len;
        parts.push(&sig_ht[start..end]);
        start = end;
    }

    parts
}

pub fn ht_pk_gen(sk_seed: &[u8], pk_seed: &[u8]) -> Vec<u8> {
    let mut adrs = Adrs::new();
    adrs.set_layer_address((HYPERTREE_LAYERS - 1) as u32);
    adrs.set_tree_address(0); 
    xmss_pk_gen(sk_seed, pk_seed, adrs)
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
    let mut sig_ht = flatten_nodes(first_sig_nodes.clone());

    
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
        sig_ht.extend(flatten_nodes(sig_nodes.clone()));

        if layer < HYPERTREE_LAYERS - 1{
            root = xmss_pk_from_sig(idx_leaf, sig_nodes.clone(), &root, pk_seed, adrs);
            if DEBUG_MODE{
                println!("new root bytes: {:?}", root);
            }
        }
    }

    sig_ht
}

pub fn ht_verify(m: Vec<u8>, sig_ht: Vec<u8>, pk_seed: Vec<u8>, mut idx_tree: u128, mut idx_leaf: usize, pk_root: Vec<u8>) -> bool{
    let mut adrs = Adrs::new();
    let xmss_parts = get_sigs_xmss_from_sig_ht(&sig_ht);

    adrs.set_layer_address(0);
    adrs.set_tree_address(idx_tree);

    let first_sig = unflatten_nodes(xmss_parts[0]);
    let mut node = xmss_pk_from_sig(idx_leaf, first_sig, &m, &pk_seed, adrs);

    for layer in 1..HYPERTREE_LAYERS{
        idx_leaf = (idx_tree % (1 << XMSS_SUBTREE_HEIGHT)) as usize;
        idx_tree >>= XMSS_SUBTREE_HEIGHT;

        adrs.set_layer_address(layer as u32);
        adrs.set_tree_address(idx_tree);

        let layer_sig = unflatten_nodes(xmss_parts[layer]);
        node = xmss_pk_from_sig(idx_leaf, layer_sig, &node, &pk_seed, adrs);
    }

    node == pk_root
}

fn flatten_nodes(nodes: Vec<Vec<u8>>) -> Vec<u8>{
    let mut out = Vec::with_capacity(nodes.len() * PARAMETER_LENGTH_N);
    for node in nodes{
        out.extend_from_slice(&node);
    }
    out
}

fn unflatten_nodes(data: &[u8]) -> Vec<Vec<u8>>{
    let mut out = Vec::new();
    let mut start = 0;

    while start < data.len(){
        let end = start + PARAMETER_LENGTH_N;
        out.push(data[start..end].to_vec());
        start = end;
    }

    out
}
