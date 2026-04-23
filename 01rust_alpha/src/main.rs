mod parameters;
mod adrs;
mod wots;
mod xmss;
mod fors;
mod hypertree;
mod sphincs;

use rand::thread_rng;
use crate::parameters::DEBUG_MODE;
use crate::sphincs::{spx_keygen, spx_sign, spx_verify};

fn main() {
    let message = b"Hello SPHINCS+! This is a test message for post-quantum signatures.";
    println!("message: {:?}", String::from_utf8_lossy(message));

     
    println!("\n[1] key generation");
    let (sk, pk) = spx_keygen(thread_rng());

    if DEBUG_MODE{
        println!("pk bytes: {:?}", pk);
        
    }
    println!("sk size: {} bytes", sk.len());

    
    println!("\n[2] signing");
    let signature = spx_sign(message, &sk, thread_rng());

    if DEBUG_MODE{
        println!("sig bytes: {:?}", signature);
    }
    println!("sig size: {} bytes", signature.len());

    
    println!("\n[3] verification");
    let ok = spx_verify(message, &signature, &pk);

    if ok{
        println!("signature is valid");
    }
    else{
        println!("signature is invalid");
    }

    
    
    
}
