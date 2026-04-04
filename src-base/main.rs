mod parameters;
mod adrs;
mod wots;
mod xmss;
mod fors;
mod hypertree;
mod sphincs;

use rand::thread_rng;
use crate::parameters::debug_mode;
use crate::sphincs::{spx_keygen, spx_sign, spx_verify};

fn main() {
    let message = b"Hello SPHINCS+! This is a test message for post-quantum signatures.";
    println!("message: {:?}", String::from_utf8_lossy(message));

     //1: generate key pair
    println!("\n[1] key generation");
    let (sk, pk) = spx_keygen(thread_rng());

    if debug_mode{
        println!("pk bytes: {:?}", pk);
        //println!("full sk bytes: {:?}", sk);
    }
    println!("sk size: {} bytes", sk.len());

    //2: sign the message
    println!("\n[2] signing");
    let signature = spx_sign(message, &sk, thread_rng());

    if debug_mode{
        println!("sig bytes: {:?}", signature);
    }
    println!("sig size: {} bytes", signature.len());

    //3: verify the signature
    println!("\n[3] verification");
    let ok = spx_verify(message, &signature, &pk);

    if ok{
        println!("signature is valid");
    }
    else{
        println!("signature is invalid");
    }

    // let mut bad_sig = signature.clone();
    // bad_sig[0] ^= 0xFF;
    // println!("tampered verify = {}", spx_verify(message, &bad_sig, &pk));
}
