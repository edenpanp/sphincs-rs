use std::io::{self, Write};
use std::time::{Duration, Instant};

use sphincs_rs::group::{
    CertificateValidationPolicy, add_member, certify_new_keys_for_member, group_identify_member,
    group_keygen, group_sign, group_verify, group_verify_with_policy, serialise_group_sig,
    set_manager_epoch, set_member_role,
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
        run_group_demo(&message);
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
    println!("  5. experimental group extension: verify + identify + policy checks");
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

fn run_group_demo(message: &[u8]) {
    println!();
    println!("Part B - Experimental Group Extension");
    println!("------------------------------------------------------------");
    println!("Scope note: this is an experimental group-style extension,");
    println!("not the full DGSP protocol with join, public revocation infrastructure,");
    println!("judge, or stateful certificate lifecycle support.");
    println!("Backend: manager-signed certificates over one-time WOTS+ member keys.");

    let (setup_time, (mut manager, gpk)) = timed(group_keygen);
    set_manager_epoch(&mut manager, 3);
    let (member_time, mut member) = timed(|| {
        let mut member = add_member(&mut manager, 0).expect("member should be created");
        let member_id = member.member_id;
        set_member_role(&mut manager, member_id, 4).expect("role should be assigned");
        certify_new_keys_for_member(&mut manager, &mut member, 1)
            .expect("new key should be certified");
        member
    });

    let member_id = member.member_id;
    let (sign_time, group_sig) =
        timed(|| group_sign(message, &mut member).expect("group signing should succeed"));
    let raw = serialise_group_sig(&group_sig);
    let (verify_time, group_valid) = timed(|| group_verify(message, &group_sig, &gpk));
    let (identify_time, identified) =
        timed(|| group_identify_member(message, &group_sig, &manager));

    let mut allow_policy = CertificateValidationPolicy::new(3);
    allow_policy.check_role = true;
    allow_policy.required_role = 4;
    let allow_valid = group_verify_with_policy(message, &group_sig, &gpk, &allow_policy);

    let mut deny_policy = allow_policy.clone();
    deny_policy.revoked_members.push(member_id);
    let deny_valid = group_verify_with_policy(message, &group_sig, &gpk, &deny_policy);

    println!("Member created: #{member_id}");
    println!("Manager setup time: {}", fmt_duration(setup_time));
    println!("Member provisioning time: {}", fmt_duration(member_time));
    println!("Group signing time: {}", fmt_duration(sign_time));
    println!(
        "Public group verification: {} ({})",
        pass(group_valid),
        fmt_duration(verify_time)
    );
    println!(
        "Manager identifies signer: {} ({})",
        match identified {
            Some(idx) if idx == member_id => format!("PASS -> member #{idx}"),
            Some(idx) => format!("FAIL -> member #{idx}"),
            None => "FAIL -> no member found".to_string(),
        },
        fmt_duration(identify_time)
    );
    println!("Raw group signature length: {} bytes", raw.len());
    println!("Policy check with required role=4: {}", pass(allow_valid));
    println!(
        "Policy check after member revocation: {}",
        pass(!deny_valid)
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
    println!("optimised tree path, and the experimental certificate-backed");
    println!("group extension.");
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
