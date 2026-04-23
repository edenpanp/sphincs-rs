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

    shake(&data, PARAMETER_LENGTH_N)
}




fn get_chain_lengths(m: &[u8]) -> Vec<usize>{
    if m.len() != PARAMETER_LENGTH_N{
        println!("message length = {}", m.len());
        panic!("[wots.rs: get_chain_lengths] bad message length");
    }

    let target_sum = WOTS_TOTAL_LENGTH * (WINTERNITZ_PARAMETER - 1) / 2;

    
    
    
    let mut dp = vec![vec![[0u8; 32]; target_sum + 1]; WOTS_TOTAL_LENGTH + 1];
    dp[0][0][31] = 1;

    let mut i = 1;
    while i <= WOTS_TOTAL_LENGTH{
        let mut j = 0;
        while j <= target_sum{
            let mut total = [0u8; 32];

            let mut k = 0;
            while k < WINTERNITZ_PARAMETER && k <= j{
                let val = dp[i - 1][j - k];

                
                let mut carry = 0u16;
                let mut p = 32;
                while p > 0{
                    p -= 1;
                    let sum = total[p] as u16 + val[p] as u16 + carry;
                    total[p] = (sum & 0xff) as u8;
                    carry = sum >> 8;
                }

                k += 1;
            }

            dp[i][j] = total;
            j += 1;
        }

        i += 1;
    }

    
    
    let mut x = [0u8; 32];
    let mut t = 0;
    while t < 32{
        x[t] = m[t];
        t += 1;
    }

    
    
    let mut out = vec![0usize; WOTS_TOTAL_LENGTH];
    let mut remain_sum = target_sum;
    let mut remain_len = WOTS_TOTAL_LENGTH;

    while remain_len > 0{
        let pos = WOTS_TOTAL_LENGTH - remain_len;

        let mut digit = 0usize;
        let mut found = false;

        while digit < WINTERNITZ_PARAMETER && digit <= remain_sum{
            let count = dp[remain_len - 1][remain_sum - digit];

            
            let mut ge = true;
            let mut p = 0;
            while p < 32{
                if x[p] > count[p]{
                    ge = true;
                    break;
                }
                if x[p] < count[p]{
                    ge = false;
                    break;
                }
                p += 1;
            }

            if ge{
                
                let mut borrow = 0i16;
                let mut q = 32;
                while q > 0{
                    q -= 1;

                    let mut cur = x[q] as i16 - count[q] as i16 - borrow;
                    if cur < 0{
                        cur += 256;
                        borrow = 1;
                    }
                    else{
                        borrow = 0;
                    }

                    x[q] = cur as u8;
                }
            }
            else{
                out[pos] = digit;
                found = true;
                break;
            }

            digit += 1;
        }

        if !found{
            println!("remain_len = {}", remain_len);
            println!("remain_sum = {}", remain_sum);
            panic!("[wots.rs: get_chain_lengths] failed to decode alpha chain lengths");
        }

        remain_sum -= out[pos];
        remain_len -= 1;
    }

    if DEBUG_MODE{
        println!("alpha chain lengths = {:?}", out);
    }

    out
}


pub fn chain(x: &[u8], i: usize, s: usize, pk_seed: &[u8], mut adrs: Adrs) -> Vec<u8>{
    if s == 0{
        return x.to_vec();
    }

    if (i + s) > (WINTERNITZ_PARAMETER - 1){
        println!("[wots.rs: chain] i = {}, s = {}, w = {}", i, s, WINTERNITZ_PARAMETER);
        panic!("[wots.rs: chain] parameters error: i+s exceeds w-1");
    }

    let mut tmp = x.to_vec();
    for j in i..(i + s){
        adrs.set_hash_address(j as u32);
        tmp = hash(pk_seed, &adrs, &tmp, PARAMETER_LENGTH_N);
    }

    tmp
}

pub fn wots_pk_gen(sk_seed: &[u8], pk_seed: &[u8], mut adrs: Adrs) -> Vec<u8>{
    let mut wots_pk_adrs = adrs;

    
    
    let mut sk_adrs = adrs;
    sk_adrs.set_type(Adrs::WOTS_PRF);
    sk_adrs.set_key_pair_address(adrs.get_key_pair_address());

    let mut tmp = Vec::with_capacity(WOTS_TOTAL_LENGTH * PARAMETER_LENGTH_N);

    for i in 0..WOTS_TOTAL_LENGTH{
        sk_adrs.set_chain_address(i as u32);
        sk_adrs.set_hash_address(0);

        let sk_i = prf(sk_seed, &sk_adrs);

        adrs.set_chain_address(i as u32);
        adrs.set_hash_address(0);

        let chain_end = chain(&sk_i, 0, WINTERNITZ_PARAMETER - 1, pk_seed, adrs);
        tmp.extend_from_slice(&chain_end);
    }

    wots_pk_adrs.set_type(Adrs::WOTS_PK);
    wots_pk_adrs.set_key_pair_address(adrs.get_key_pair_address());

    hash(pk_seed, &wots_pk_adrs, &tmp, PARAMETER_LENGTH_N)
}

pub fn wots_sign(m: &[u8], sk_seed: &[u8], pk_seed: &[u8], mut adrs: Adrs) -> Vec<Vec<u8>>{
    if DEBUG_MODE{
        println!("----------------WOTS SIGN---------------------");
        println!("message bytes: {:?}", m);
    }

    let chain_lengths = get_chain_lengths(m);

    
    let mut sk_adrs = adrs;
    sk_adrs.set_type(Adrs::WOTS_PRF);
    sk_adrs.set_key_pair_address(adrs.get_key_pair_address());

    let mut sig = Vec::with_capacity(WOTS_TOTAL_LENGTH);
    for i in 0..WOTS_TOTAL_LENGTH{
        sk_adrs.set_chain_address(i as u32);
        sk_adrs.set_hash_address(0);

        let sk_i = prf(sk_seed, &sk_adrs);

        adrs.set_chain_address(i as u32);
        adrs.set_hash_address(0);

        sig.push(chain(&sk_i, 0, chain_lengths[i], pk_seed, adrs));
    }

    sig
}

pub fn wots_pk_from_sig(sig: Vec<Vec<u8>>, m: &[u8], pk_seed: &[u8], mut adrs: Adrs) -> Vec<u8>{
    let mut wots_pk_adrs = adrs;

    let chain_lengths = get_chain_lengths(m);

    let mut tmp = Vec::with_capacity(WOTS_TOTAL_LENGTH * PARAMETER_LENGTH_N);

    for i in 0..WOTS_TOTAL_LENGTH{
        adrs.set_chain_address(i as u32);
        adrs.set_hash_address(0);

        let chain_end = chain(
            &sig[i],
            chain_lengths[i],
            WINTERNITZ_PARAMETER - 1 - chain_lengths[i],
            pk_seed,
            adrs
        );
        tmp.extend_from_slice(&chain_end);
    }

    wots_pk_adrs.set_type(Adrs::WOTS_PK);
    wots_pk_adrs.set_key_pair_address(adrs.get_key_pair_address());

    hash(pk_seed, &wots_pk_adrs, &tmp, PARAMETER_LENGTH_N)
}