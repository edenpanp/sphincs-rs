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

//convert into base-w digits
fn base_w(input: &[u8], w: usize, out_len: usize) -> Vec<usize>{
    let mut in_idx = 0;
    let mut total = 0u32;
    let mut bits = 0u32;
    let mut output = Vec::with_capacity(out_len);

    let log_w = (w as f64).log2().floor() as u32;

    for _ in 0..out_len{
        if bits == 0{
            total = input[in_idx] as u32;
            in_idx += 1;
            bits += 8;
        }

        bits -= log_w;
        output.push(((total >> bits) % w as u32) as usize);
        //println!("base_w step -> total = {}, bits = {}", total, bits);
    }

    output
}

//message + checksum -> chain lengths
//wots sign and wots pk
fn get_chain_lengths(m: &[u8]) -> Vec<usize>{
    let mut msg_base_w = base_w(m, winternitz_parameter, wots_length_1);

    if debug_mode{
        println!("base_w message = {:?}", msg_base_w);
    }

    let mut csum = 0usize;
    for i in 0..wots_length_1{
        csum += winternitz_parameter - 1 - msg_base_w[i];
    }

    let log_w = winternitz_parameter.ilog2() as usize;
    let padding;
    if (wots_length_2 * log_w) % 8 != 0{
        padding = (wots_length_2 * log_w) % 8;
    }
    else{
        padding = 8;
    }

    csum <<= 8 - padding;

    let csum_bytes_len = (wots_length_2 * log_w + 7) / 8;
    let csum_be = (csum as u64).to_be_bytes();
    let csumb = &csum_be[8 - csum_bytes_len..8];
    let csum_base_w = base_w(csumb, winternitz_parameter, wots_length_2);

    msg_base_w.extend_from_slice(&csum_base_w);

    if debug_mode{
        println!("full chain lengths = {:?}", msg_base_w);
        //println!("csum bytes = {:?}", csumb);
    }

    msg_base_w
}

//compute hash s times from step i
pub fn chain(x: &[u8], i: usize, s: usize, pk_seed: &[u8], mut adrs: Adrs) -> Vec<u8>{
    if s == 0{
        return x.to_vec();
    }

    if (i + s) > (winternitz_parameter - 1){
        println!("[wots.rs: chain] i = {}, s = {}, w = {}", i, s, winternitz_parameter);
        panic!("[wots.rs: chain] parameters error: i+s exceeds w-1");
    }

    let mut tmp = x.to_vec();
    for j in i..(i + s){
        adrs.set_hash_address(j as u32);
        tmp = hash(pk_seed, &adrs, &tmp, parameter_length_N);
        //println!("chain step {} -> {:?}", j, tmp);
    }

    tmp
}

pub fn wots_pk_gen(sk_seed: &[u8], pk_seed: &[u8], mut adrs: Adrs) -> Vec<u8>{
    let mut wots_pk_adrs = adrs;
    let mut tmp = Vec::with_capacity(wots_total_length * parameter_length_N);

    for i in 0..wots_total_length{
        adrs.set_chain_address(i as u32);
        adrs.set_hash_address(0);

        let sk_i = prf(sk_seed, &adrs);
        let chain_end = chain(&sk_i, 0, winternitz_parameter - 1, pk_seed, adrs);
        tmp.extend_from_slice(&chain_end);
    }

    wots_pk_adrs.set_type(Adrs::wots_pk);
    wots_pk_adrs.set_key_pair_address(adrs.get_key_pair_address());

    hash(pk_seed, &wots_pk_adrs, &tmp, parameter_length_N)
}

pub fn wots_sign(m: &[u8], sk_seed: &[u8], pk_seed: &[u8], mut adrs: Adrs) -> Vec<Vec<u8>>{
    if debug_mode{
        println!("----------------WOTS SIGN---------------------");
        println!("message bytes: {:?}", m);
    }

    let chain_lengths = get_chain_lengths(m);

    let mut sig = Vec::with_capacity(wots_total_length);
    for i in 0..wots_total_length{
        adrs.set_chain_address(i as u32);
        adrs.set_hash_address(0);

        let sk_i = prf(sk_seed, &adrs); //get start value
        sig.push(chain(&sk_i, 0, chain_lengths[i], pk_seed, adrs)); //go chain_lengths[i] steps
    }

    sig
}

pub fn wots_pk_from_sig(sig: Vec<Vec<u8>>, m: &[u8], pk_seed: &[u8], mut adrs: Adrs) -> Vec<u8>{
    let mut wots_pk_adrs = adrs;

    let chain_lengths = get_chain_lengths(m);

    let mut tmp = Vec::with_capacity(wots_total_length * parameter_length_N);

    for i in 0..wots_total_length{
        adrs.set_chain_address(i as u32);
        let chain_end = chain(
            &sig[i],
            chain_lengths[i],
            winternitz_parameter - 1 - chain_lengths[i],
            pk_seed,
            adrs
        );
        tmp.extend_from_slice(&chain_end);
    }

    wots_pk_adrs.set_type(Adrs::wots_pk);
    wots_pk_adrs.set_key_pair_address(adrs.get_key_pair_address());

    hash(pk_seed, &wots_pk_adrs, &tmp, parameter_length_N)
}