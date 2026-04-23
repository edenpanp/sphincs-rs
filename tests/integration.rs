#[path = "../src/parameters.rs"]
mod parameters;

#[path = "../src/adrs.rs"]
mod adrs;

#[path = "../src/wots.rs"]
mod wots;

#[path = "../src/xmss.rs"]
mod xmss;

#[path = "../src/fors.rs"]
mod fors;

#[path = "../src/hypertree.rs"]
mod hypertree;

#[path = "../src/sphincs.rs"]
mod sphincs;

use rand::thread_rng;
use std::io::{self, Write};
use std::time::{Duration, Instant};

use sphincs::{spx_keygen, spx_sign, spx_verify};

fn ad(tot: Duration, n: u32) -> Duration {
    if n == 0 { Duration::from_secs(0) } else { tot / n }
}

fn pbk(s: &str) {
    println!("{}", s);
    let _ = io::stdout().flush();
}

fn p_i() -> String {
    format!(
        "PARAMS : signature = {} bytes | WOTS chains = {} | w = {} | FORS trees = {} | FORS height = {} | HT height = {} | HT layers = {}",
        parameters::TOTAL_SIGNATURE_LENGTH,
        parameters::WOTS_TOTAL_LENGTH,
        parameters::WINTERNITZ_PARAMETER,
        parameters::FORS_TREES_NUMBER,
        parameters::FORS_TREE_HEIGHT,
        parameters::HYPERTREE_HEIGHT,
        parameters::HYPERTREE_LAYERS
    )
}

fn rc(tn: &str, tt: &str, sm: &[u8], vm: &[u8], wpk: bool, ts: bool, ex: bool) {
    let st = Instant::now();

    let (sk1, pk1) = spx_keygen(thread_rng());

    let vp = if wpk {
        let (_, pk2) = spx_keygen(thread_rng());
        pk2
    } else {
        pk1.clone()
    };

    let mut sg = spx_sign(sm, &sk1, thread_rng());

    if ts && !sg.is_empty() {
        sg[0] ^= 0x01;
    }

    let ac = spx_verify(vm, &sg, &vp);
    let el = st.elapsed();

    let ok = ac == ex && sg.len() == parameters::TOTAL_SIGNATURE_LENGTH;

    pbk(&format!(
        "\nTEST   : {}\nTYPE   : {}\n{}\nTIME   : {:?}\nVERIFY : {}\nEXPECT : {}\nPASS   : {}\n--------------------------------------------------",
        tn, tt, p_i(), el, ac, ex, ok
    ));

    assert_eq!(ac, ex, "unexpected verification result");
    assert_eq!(sg.len(), parameters::TOTAL_SIGNATURE_LENGTH, "unexpected signature length");
}

#[test]
fn t1() {
    let m = b"SPHINCS correctness test message";
    rc("t1", "normal sign and verify", m, m, false, false, true);
}

#[test]
fn t2() {
    let a = b"original message";
    let b = b"original message but changed";
    rc("t2", "modified message", a, b, false, false, false);
}

#[test]
fn t3() {
    let m = b"message for signature tamper test";
    rc("t3", "modified signature", m, m, false, true, false);
}

#[test]
fn t4() {
    let m = b"message for wrong public key test";
    rc("t4", "wrong public key", m, m, true, false, false);
}

#[test]
fn t5() {
    let st = Instant::now();
    let m = b"size consistency test";
    let (sk, pk) = spx_keygen(thread_rng());
    let sg = spx_sign(m, &sk, thread_rng());

    let ok = sk.len() == parameters::SECRET_KEY_LENGTH
        && pk.len() == parameters::PUBLIC_KEY_LENGTH
        && sg.len() == parameters::TOTAL_SIGNATURE_LENGTH;

    let el = st.elapsed();

    pbk(&format!(
        "\nTEST   : t5\nTYPE   : size consistency\n{}\nTIME   : {:?}\nVERIFY : {}\nEXPECT : true\nPASS   : {}\n--------------------------------------------------",
        p_i(), el, ok, ok
    ));

    assert_eq!(sk.len(), parameters::SECRET_KEY_LENGTH);
    assert_eq!(pk.len(), parameters::PUBLIC_KEY_LENGTH);
    assert_eq!(sg.len(), parameters::TOTAL_SIGNATURE_LENGTH);
}

#[test]
fn t6() {
    let c = parameters::SECRET_KEY_LENGTH > 0
        && parameters::PUBLIC_KEY_LENGTH > 0
        && parameters::TOTAL_SIGNATURE_LENGTH > 0
        && parameters::WOTS_TOTAL_LENGTH > 0
        && parameters::WINTERNITZ_PARAMETER > 0
        && parameters::FORS_TREES_NUMBER > 0
        && parameters::FORS_TREE_HEIGHT > 0
        && parameters::HYPERTREE_HEIGHT > 0
        && parameters::HYPERTREE_LAYERS > 0;

    pbk(&format!(
        "\nTEST   : t6\nTYPE   : parameter summary\n{}\nTIME   : 0ns\nVERIFY : {}\nEXPECT : true\nPASS   : {}\n--------------------------------------------------",
        p_i(), c, c
    ));

    assert!(c, "parameter values should all be positive");
}

#[test]
fn t7() {
    let n: u32 = 3;
    let base = b"multi-round correctness test";
    let mut tot = Duration::from_secs(0);

    pbk(&format!(
        "\nTEST   : t7\nTYPE   : repeated correctness\n{}",
        p_i()
    ));

    for i in 0..n {
        let mut m = base.to_vec();
        m.extend_from_slice(&[i as u8]);

        let st = Instant::now();
        let (sk, pk) = spx_keygen(thread_rng());
        let sg = spx_sign(&m, &sk, thread_rng());
        let v = spx_verify(&m, &sg, &pk);
        let d = st.elapsed();
        tot += d;

        let ok = v && sg.len() == parameters::TOTAL_SIGNATURE_LENGTH;

        pbk(&format!(
            "ROUND  {} | TIME = {:?} | VERIFY = {} | SIG = {} | PASS = {}",
            i + 1, d, v, sg.len(), ok
        ));

        assert!(v, "verification failed at round {}", i + 1);
        assert_eq!(sg.len(), parameters::TOTAL_SIGNATURE_LENGTH);
    }

    pbk(&format!("AVERAGE: {:?}\n--------------------------------------------------", ad(tot, n)));
}

#[test]
fn b1() {
    let n: u32 = 3;
    let m = b"SPHINCS performance benchmark test message";
    let mut tot = Duration::from_secs(0);

    pbk(&format!(
        "\nTEST   : b1\nTYPE   : simple benchmark\n{}",
        p_i()
    ));

    for i in 0..n {
        let st = Instant::now();
        let (sk, pk) = spx_keygen(thread_rng());
        let sg = spx_sign(m, &sk, thread_rng());
        let v = spx_verify(m, &sg, &pk);
        let d = st.elapsed();
        tot += d;

        let ok = v && sg.len() == parameters::TOTAL_SIGNATURE_LENGTH;

        pbk(&format!(
            "ROUND  {} | TIME = {:?} | VERIFY = {} | SIG = {} | PASS = {}",
            i + 1, d, v, sg.len(), ok
        ));

        assert!(v, "verification failed during benchmark round {}", i + 1);
        assert_eq!(sg.len(), parameters::TOTAL_SIGNATURE_LENGTH);
    }

    pbk(&format!("AVERAGE: {:?}\n--------------------------------------------------", ad(tot, n)));
}