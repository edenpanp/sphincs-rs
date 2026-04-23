use std::io::{self, Write};
use std::time::{Duration, Instant};

use sphincs_rs::group::{
    GroupRevocationList, derive_member_key, group_keygen, group_open, group_sign,
    group_verify, group_verify_not_revoked,
};
use sphincs_rs::hash::{RawSha256, Sha256Hasher, SphincsHasher};
use sphincs_rs::params::{A, D, H, HP, K, N, W, WOTS_LEN};
use sphincs_rs::sphincs::{
    SIG_BYTES, serialise_sig, slh_keygen_fast, slh_sign_fast, slh_verify, slh_verify_raw,
};

fn main() -> io::Result<()> {
    print_header();

    let message = prompt_message()?;
    let backend = prompt_backend()?;

    match backend {
        Backend::FastDemo => run_signature_demo::<RawSha256>("RawSha256 demo backend", &message),
        Backend::Sha256 => {
            run_signature_demo::<Sha256Hasher>("Sha256Hasher implementation", &message)
        }
    }

    if prompt_group_demo()? {
        run_group_demo::<RawSha256>(&message);
    } else {
        println!();
        println!("Part B skipped by user. The report documents the group tests and benchmarks.");
    }
    print_close();

    Ok(())
}

#[derive(Clone, Copy)]
enum Backend {
    FastDemo,
    Sha256,
}

fn print_header() {
    println!();
    println!("SPHINCS+ Rust Demo");
    println!("UNSW COMP3453 Applied Cryptography");
    println!("============================================================");
    println!("Motivation:");
    println!("  Classical signatures such as RSA/ECDSA are vulnerable to");
    println!("  large-scale quantum computers. SPHINCS+ / SLH-DSA is a");
    println!("  stateless hash-based post-quantum signature scheme.");
    println!();
    println!("This demo shows:");
    println!("  1. key generation, signing, verification");
    println!("  2. rejection after message and signature tampering");
    println!("  3. raw signature size and parameter choices");
    println!("  4. optimised signing path used by this implementation");
    println!("  5. experimental group-signature verify + manager open/revoke check");
    println!("============================================================");
    println!("Recommended command:");
    println!("  cargo run --release --example demo");
    println!();
    if cfg!(debug_assertions) {
        println!("Note: this is a debug build, so signing is much slower.");
        println!("Use --release for the live demo.");
        println!();
    }
    println!("============================================================");
    println!();
}

fn prompt_message() -> io::Result<Vec<u8>> {
    print!("Message to sign [default: UNSW SPHINCS+ demo]: ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let trimmed = input.trim_end();

    if trimmed.is_empty() {
        Ok(b"UNSW SPHINCS+ demo".to_vec())
    } else {
        Ok(trimmed.as_bytes().to_vec())
    }
}

fn prompt_backend() -> io::Result<Backend> {
    println!();
    println!("Choose hash backend:");
    println!("  1. RawSha256 demo backend: faster, useful for live marking");
    println!("  2. Sha256Hasher implementation: closer to the project path, slower");
    print!("Selection [1]: ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    match input.trim() {
        "2" => Ok(Backend::Sha256),
        _ => Ok(Backend::FastDemo),
    }
}

fn prompt_group_demo() -> io::Result<bool> {
    println!();
    print!("Run experimental group extension demo? [Y/n]: ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    Ok(!matches!(input.trim(), "n" | "N" | "no" | "No" | "NO"))
}

fn run_signature_demo<S: SphincsHasher>(backend_name: &str, message: &[u8]) {
    println!();
    println!("Part A - SPHINCS+ Signature");
    println!("------------------------------------------------------------");
    println!("Backend: {backend_name}");
    println!("Input message: {:?}", String::from_utf8_lossy(message));
    println!("Message length: {} bytes", message.len());
    print_parameters();

    let (keygen_time, (sk, pk)) = timed(slh_keygen_fast::<S>);
    println!("Key generation: {}", fmt_duration(keygen_time));
    println!("Public key size: {} bytes", N * 2);
    println!("Secret key size: {} bytes", N * 4);

    let (sign_time, sig) = timed(|| slh_sign_fast::<S>(message, &sk));
    let sig_bytes = serialise_sig(&sig);
    println!("Signing using optimised path: {}", fmt_duration(sign_time));
    println!("Signature size: {} bytes", sig_bytes.len());

    let (verify_time, valid) = timed(|| slh_verify::<S>(message, &sig, &pk));
    println!(
        "Verification on original message: {} ({})",
        pass(valid),
        fmt_duration(verify_time)
    );

    let mut wrong_message = message.to_vec();
    wrong_message.extend_from_slice(b" [tampered]");
    let wrong_message_valid = slh_verify::<S>(&wrong_message, &sig, &pk);
    println!(
        "Verification after message tampering: {}",
        pass(!wrong_message_valid)
    );

    let mut tampered_sig = sig_bytes.clone();
    if let Some(byte) = tampered_sig.get_mut(SIG_BYTES / 2) {
        *byte ^= 0xff;
    }
    let tampered_sig_valid = slh_verify_raw::<S>(message, &tampered_sig, &pk);
    println!(
        "Verification after signature bit flip: {}",
        pass(!tampered_sig_valid)
    );

    let raw_valid = slh_verify_raw::<S>(message, &sig_bytes, &pk);
    println!("Raw-byte signature round trip: {}", pass(raw_valid));
}

fn run_group_demo<S: SphincsHasher>(message: &[u8]) {
    println!();
    println!("Part B - Experimental Group Extension");
    println!("------------------------------------------------------------");
    println!("Scope note: this is an experimental group-style extension,");
    println!("not the full DGSP protocol with join, public revocation, judge,");
    println!("and certificate lifecycle support.");
    println!("Backend: RawSha256 demo backend for live demonstration speed.");

    let member_index = 7u32;
    let (setup_time, (manager, gpk)) = timed(group_keygen::<S>);
    let member_sk = derive_member_key::<S>(&manager, member_index);

    let (sign_time, group_sig) = timed(|| group_sign::<S>(message, &member_sk));
    let (verify_time, group_valid) = timed(|| group_verify::<S>(message, &group_sig, &gpk));
    let (open_time, opened) = timed(|| group_open::<S>(message, &group_sig, &manager));
    let mut revocations = GroupRevocationList::new();
    let verify_before_revoke =
        group_verify_not_revoked::<S>(message, &group_sig, &gpk, &manager, &revocations);
    revocations.revoke(member_index);
    let verify_after_revoke =
        group_verify_not_revoked::<S>(message, &group_sig, &gpk, &manager, &revocations);

    println!("Group setup capacity: {} members", manager.max_members);
    println!("Chosen signer: member #{member_index}");
    println!("Group setup time: {}", fmt_duration(setup_time));
    println!("Group signing time: {}", fmt_duration(sign_time));
    println!(
        "Public group verification: {} ({})",
        pass(group_valid),
        fmt_duration(verify_time)
    );
    println!(
        "Manager opens signer: {} ({})",
        match opened {
            Some(idx) if idx == member_index => format!("PASS -> member #{idx}"),
            Some(idx) => format!("FAIL -> member #{idx}"),
            None => "FAIL -> no member found".to_string(),
        },
        fmt_duration(open_time)
    );
    println!(
        "Manager verify_not_revoked before revoke: {}",
        pass(verify_before_revoke)
    );
    println!(
        "Manager verify_not_revoked after revoke: {}",
        pass(!verify_after_revoke)
    );
}

fn print_parameters() {
    println!("Parameter set: SPHINCS+-SHA2-256s-simple style");
    println!("Parameters: n={N}, w={W}, h={H}, d={D}, h'={HP}, k={K}, a={A}, WOTS_LEN={WOTS_LEN}");
}

fn print_close() {
    println!();
    println!("Summary");
    println!("------------------------------------------------------------");
    println!("The demo exercised the main project deliverables: modular");
    println!("SPHINCS+ signing, raw serialisation, tamper rejection, the");
    println!("optimised tree path, and the experimental group extension.");
    println!();
    println!("For benchmarks, run:");
    println!("  cargo bench --features test-utils");
    println!("  cargo bench --features \"test-utils parallel\"");
    println!();
}

fn timed<T>(f: impl FnOnce() -> T) -> (Duration, T) {
    let start = Instant::now();
    let out = f();
    (start.elapsed(), out)
}

fn pass(ok: bool) -> &'static str {
    if ok { "PASS" } else { "FAIL" }
}

fn fmt_duration(d: Duration) -> String {
    if d.as_secs() > 0 {
        format!("{:.2}s", d.as_secs_f64())
    } else if d.as_millis() > 0 {
        format!("{}ms", d.as_millis())
    } else if d.as_micros() > 0 {
        format!("{}us", d.as_micros())
    } else {
        format!("{}ns", d.as_nanos())
    }
}
