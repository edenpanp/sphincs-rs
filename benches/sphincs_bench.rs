//! SPHINCS+ benchmarks — baseline vs optimised vs parallel.
//!
//! # Run
//!
//! ```sh
//! # Sequential (no Rayon) — compares recursive vs iterative:
//! cargo bench --features test-utils
//!
//! # Parallel (Rayon enabled) — compares sequential iterative vs parallel:
//! cargo bench --features "test-utils parallel"
//!
//! # Save a baseline, then compare after a change:
//! cargo bench --features test-utils -- --save-baseline before
//! cargo bench --features test-utils -- --baseline before
//! ```
//!
//! HTML reports are written to `target/criterion/`.
//!
//! # Groups and what they measure
//!
//! | Group              | Description                                       |
//! |--------------------|---------------------------------------------------|
//! | `keygen`           | Full keygen (builds D × 2^HP XMSS leaves)         |
//! | `sign`             | Sign a 64-byte message                            |
//! | `verify`           | Verify a signature (path walk only, no leaf gen)  |
//! | `xmss_root`        | Compute one XMSS tree root (HP=8, 256 leaves)     |
//! | `wots_keygen`      | Isolated WOTS+ PK generation (67 chains × 15)     |
//! | `fors_sign`        | FORS sign (22 trees × 14 levels)                  |
//! | `alpha_comparison` | Print parameter-set size/security table (1 iter)  |

use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use rand::{RngCore, rngs::OsRng};

use sphincs_rs::adrs::{Adrs, AdrsType};
use sphincs_rs::hash::{RawSha256, Sha256Hasher};
use sphincs_rs::params::{MD_BYTES, N};
use sphincs_rs::params_alpha::{Alpha128sFast, Alpha128sSmall, ParamSet, Sha2_256s};
use sphincs_rs::sphincs::{
    SIG_BYTES, slh_keygen, slh_keygen_fast, slh_sign, slh_sign_fast, slh_verify,
};

fn rng_n() -> [u8; N] {
    let mut b = [0u8; N];
    OsRng.fill_bytes(&mut b);
    b
}

// ── keygen ────────────────────────────────────────────────────────────────────

fn bench_keygen(c: &mut Criterion) {
    let mut g = c.benchmark_group("keygen");
    g.sample_size(10);

    g.bench_function("baseline/RawSha256",    |b| b.iter(|| slh_keygen::<RawSha256>()));
    g.bench_function("fast/RawSha256",        |b| b.iter(|| slh_keygen_fast::<RawSha256>()));
    g.bench_function("baseline/Sha256Hasher", |b| b.iter(|| slh_keygen::<Sha256Hasher>()));
    g.bench_function("fast/Sha256Hasher",     |b| b.iter(|| slh_keygen_fast::<Sha256Hasher>()));
    g.finish();
}

// ── sign ──────────────────────────────────────────────────────────────────────

fn bench_sign(c: &mut Criterion) {
    let msg = b"UNSW 26T1 Applied Cryptography - SPHINCS+ benchmark message.";
    let mut g = c.benchmark_group("sign");
    g.sample_size(10);

    g.bench_function("baseline/RawSha256", |b| {
        b.iter_batched(
            || slh_keygen::<RawSha256>(),
            |(sk, _pk)| slh_sign::<RawSha256>(msg, &sk),
            BatchSize::SmallInput,
        )
    });

    g.bench_function("fast/RawSha256", |b| {
        b.iter_batched(
            || slh_keygen_fast::<RawSha256>(),
            |(sk, _pk)| slh_sign_fast::<RawSha256>(msg, &sk),
            BatchSize::SmallInput,
        )
    });

    g.bench_function("baseline/Sha256Hasher", |b| {
        b.iter_batched(
            || slh_keygen::<Sha256Hasher>(),
            |(sk, _pk)| slh_sign::<Sha256Hasher>(msg, &sk),
            BatchSize::SmallInput,
        )
    });

    g.bench_function("fast/Sha256Hasher", |b| {
        b.iter_batched(
            || slh_keygen_fast::<Sha256Hasher>(),
            |(sk, _pk)| slh_sign_fast::<Sha256Hasher>(msg, &sk),
            BatchSize::SmallInput,
        )
    });

    g.finish();
}

// ── verify ────────────────────────────────────────────────────────────────────

fn bench_verify(c: &mut Criterion) {
    let msg = b"UNSW 26T1 Applied Cryptography - verify benchmark.";
    let mut g = c.benchmark_group("verify");
    g.sample_size(20);

    g.bench_function("RawSha256", |b| {
        b.iter_batched(
            || {
                let (sk, pk) = slh_keygen_fast::<RawSha256>();
                let sig = slh_sign_fast::<RawSha256>(msg, &sk);
                (sig, pk)
            },
            |(sig, pk)| slh_verify::<RawSha256>(msg, &sig, &pk),
            BatchSize::SmallInput,
        )
    });

    g.bench_function("Sha256Hasher", |b| {
        b.iter_batched(
            || {
                let (sk, pk) = slh_keygen_fast::<Sha256Hasher>();
                let sig = slh_sign_fast::<Sha256Hasher>(msg, &sk);
                (sig, pk)
            },
            |(sig, pk)| slh_verify::<Sha256Hasher>(msg, &sig, &pk),
            BatchSize::SmallInput,
        )
    });

    g.finish();
}

// ── xmss tree root ───────────────────────────────────────────────────────────

fn bench_xmss_root(c: &mut Criterion) {
    use sphincs_rs::params::HP;
    use sphincs_rs::xmss::{xmss_node, xmss_node_fast};

    let mut g = c.benchmark_group("xmss_root");
    g.sample_size(10);

    g.bench_function("baseline_recursive/RawSha256", |b| {
        let sk = rng_n(); let pk = rng_n();
        let adrs = Adrs::new(AdrsType::TreeNode);
        b.iter(|| xmss_node::<RawSha256>(&sk, 0, HP, &pk, adrs))
    });

    g.bench_function("fast_iterative/RawSha256", |b| {
        let sk = rng_n(); let pk = rng_n();
        let adrs = Adrs::new(AdrsType::TreeNode);
        b.iter(|| xmss_node_fast::<RawSha256>(&sk, 0, HP, &pk, adrs))
    });

    g.bench_function("baseline_recursive/Sha256Hasher", |b| {
        let sk = rng_n(); let pk = rng_n();
        let adrs = Adrs::new(AdrsType::TreeNode);
        b.iter(|| xmss_node::<Sha256Hasher>(&sk, 0, HP, &pk, adrs))
    });

    g.bench_function("fast_iterative/Sha256Hasher", |b| {
        let sk = rng_n(); let pk = rng_n();
        let adrs = Adrs::new(AdrsType::TreeNode);
        b.iter(|| xmss_node_fast::<Sha256Hasher>(&sk, 0, HP, &pk, adrs))
    });

    g.finish();
}

// ── WOTS+ leaf ────────────────────────────────────────────────────────────────

fn bench_wots_keygen(c: &mut Criterion) {
    use sphincs_rs::wots::wots_pk_gen;
    let mut g = c.benchmark_group("wots_keygen");

    g.bench_function("RawSha256", |b| {
        let sk = rng_n(); let pk = rng_n();
        let adrs = Adrs::new(AdrsType::Wots);
        b.iter(|| wots_pk_gen::<RawSha256>(&sk, &pk, &adrs))
    });
    g.bench_function("Sha256Hasher", |b| {
        let sk = rng_n(); let pk = rng_n();
        let adrs = Adrs::new(AdrsType::Wots);
        b.iter(|| wots_pk_gen::<Sha256Hasher>(&sk, &pk, &adrs))
    });

    g.finish();
}

// ── FORS sign ─────────────────────────────────────────────────────────────────

fn bench_fors_sign(c: &mut Criterion) {
    use sphincs_rs::fors::fors_sign;
    let mut g = c.benchmark_group("fors_sign");
    g.sample_size(20);

    g.bench_function("RawSha256", |b| {
        let sk = rng_n(); let pk = rng_n();
        let mut md = [0u8; MD_BYTES]; OsRng.fill_bytes(&mut md);
        let mut adrs = Adrs::new(AdrsType::ForsTree);
        adrs.set_keypair_address(0);
        b.iter(|| fors_sign::<RawSha256>(&md, &sk, &pk, &adrs))
    });
    g.bench_function("Sha256Hasher", |b| {
        let sk = rng_n(); let pk = rng_n();
        let mut md = [0u8; MD_BYTES]; OsRng.fill_bytes(&mut md);
        let mut adrs = Adrs::new(AdrsType::ForsTree);
        adrs.set_keypair_address(0);
        b.iter(|| fors_sign::<Sha256Hasher>(&md, &sk, &pk, &adrs))
    });

    g.finish();
}

// ── SPHINCS-alpha parameter comparison ───────────────────────────────────────

fn bench_alpha_comparison(c: &mut Criterion) {
    let mut g = c.benchmark_group("alpha_comparison");
    // Single iteration — just to record the parameter data as a benchmark output.
    g.sample_size(10);

    // These "benchmarks" run in nanoseconds (just a println + arithmetic).
    // Their value is in the numbers printed, which appear in the Criterion report.
    g.bench_function("standard_SHA2-256s", |b| {
        b.iter(|| {
            let _ts = Sha2_256s::total_sig_bytes();
            let _fs = Sha2_256s::fors_sig_bytes();
            let _hs = Sha2_256s::ht_sig_bytes();
            let _sec = Sha2_256s::fors_security_bits();
        })
    });

    g.bench_function("alpha_128s_small", |b| {
        b.iter(|| {
            let _ts = Alpha128sSmall::total_sig_bytes();
            let _fs = Alpha128sSmall::fors_sig_bytes();
            let _hs = Alpha128sSmall::ht_sig_bytes();
            let _sec = Alpha128sSmall::fors_security_bits();
        })
    });

    g.bench_function("alpha_128s_fast", |b| {
        b.iter(|| {
            let _ts = Alpha128sFast::total_sig_bytes();
            let _fs = Alpha128sFast::fors_sig_bytes();
            let _hs = Alpha128sFast::ht_sig_bytes();
            let _sec = Alpha128sFast::fors_security_bits();
        })
    });

    g.finish();

    // Also print the human-readable table to stdout.
    println!();
    println!("=== SPHINCS-alpha parameter set comparison ===");
    println!("{:28} {:>12} {:>12} {:>12} {:>10}",
             "variant", "FORS (B)", "HT (B)", "total (B)", "FORS sec");
    let sets: &[(&str, usize, usize, usize, f64)] = &[
        ("SHA2-256s (standard)",
         Sha2_256s::fors_sig_bytes(), Sha2_256s::ht_sig_bytes(),
         Sha2_256s::total_sig_bytes(), Sha2_256s::fors_security_bits()),
        ("Alpha-128s-small (K=14,A=17)",
         Alpha128sSmall::fors_sig_bytes(), Alpha128sSmall::ht_sig_bytes(),
         Alpha128sSmall::total_sig_bytes(), Alpha128sSmall::fors_security_bits()),
        ("Alpha-128s-fast  (K=35,A=9)",
         Alpha128sFast::fors_sig_bytes(), Alpha128sFast::ht_sig_bytes(),
         Alpha128sFast::total_sig_bytes(), Alpha128sFast::fors_security_bits()),
    ];
    let std_total = Sha2_256s::total_sig_bytes();
    for (name, fors, ht, total, sec) in sets {
        let delta = (*total as isize - std_total as isize) * 100 / std_total as isize;
        let sign = if delta >= 0 { "+" } else { "" };
        println!("{:28} {:>12} {:>12} {:>10} ({sign}{delta:+}%)  {:>8.1}b",
                 name, fors, ht, total, sec);
    }
    println!();
    println!("SIG_BYTES constant (in code): {SIG_BYTES}");
    println!();
}

// ── Register ──────────────────────────────────────────────────────────────────

criterion_group!(
    benches,
    bench_keygen,
    bench_sign,
    bench_verify,
    bench_xmss_root,
    bench_wots_keygen,
    bench_fors_sign,
    bench_alpha_comparison,
    bench_group,
);
criterion_main!(benches);

// ── Group signature benchmarks ────────────────────────────────────────────────

fn bench_group(c: &mut Criterion) {
    use sphincs_rs::group::{derive_member_key, group_keygen, group_sign, group_verify,
                             group_identify_member};

    let mut g = c.benchmark_group("group");
    g.sample_size(10);

    // group_keygen: same cost as slh_keygen_fast (builds one XMSS tree)
    g.bench_function("keygen/RawSha256", |b| {
        b.iter(|| group_keygen::<RawSha256>())
    });

    // group_sign for a single member (no extra overhead vs slh_sign_fast)
    g.bench_function("sign/RawSha256", |b| {
        b.iter_batched(
            || {
                let (mgr, _gpk) = group_keygen::<RawSha256>();
                let msk = derive_member_key(&mgr, 0);
                msk
            },
            |msk| group_sign::<RawSha256>(b"bench message", &msk),
            BatchSize::SmallInput,
        )
    });

    // group_verify: same as slh_verify
    g.bench_function("verify/RawSha256", |b| {
        b.iter_batched(
            || {
                let (mgr, gpk) = group_keygen::<RawSha256>();
                let msk = derive_member_key(&mgr, 0);
                let sig = group_sign::<RawSha256>(b"bench message", &msk);
                (sig, gpk)
            },
            |(sig, gpk)| group_verify::<RawSha256>(b"bench message", &sig, &gpk),
            BatchSize::SmallInput,
        )
    });

    // group_identify: linear scan over all members (O(M) WOTS+ verifications)
    g.bench_function("identify/RawSha256", |b| {
        b.iter_batched(
            || {
                let (mgr, _gpk) = group_keygen::<RawSha256>();
                let msk = derive_member_key(&mgr, 7);
                let sig = group_sign::<RawSha256>(b"identify bench", &msk);
                (mgr, sig)
            },
            |(mgr, sig)| group_identify_member::<RawSha256>(b"identify bench", &sig, &mgr),
            BatchSize::SmallInput,
        )
    });

    g.finish();
}