//! SPHINCS+ benchmarks — baseline vs optimised vs parallel
//!
//! how to run:
//!
//! cargo bench --features test-utils
//! cargo bench --features "test-utils parallel"
//!
//! optional:
//! save baseline → compare later
//! cargo bench --features test-utils -- --save-baseline before
//! cargo bench --features test-utils -- --baseline before
//!
//! results go to: target/criterion/
//!
//! quick idea of groups:
//! - keygen: full key generation
//! - sign: sign a message
//! - verify: verify signature
//! - xmss_root: single XMSS tree root computation
//! - wots_keygen: WOTS+ pk generation only
//! - fors_sign: FORS signing cost
//! - alpha_comparison: just prints parameter stats

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
    // small helper: generate random N-byte array
    let mut buf = [0u8; N];
    OsRng.fill_bytes(&mut buf);
    buf
}

// ── keygen ─────────────────────────────────────────────

fn bench_keygen(c: &mut Criterion) {
    let mut g = c.benchmark_group("keygen");
    g.sample_size(10); // keygen is expensive, keep sample small

    g.bench_function("baseline/RawSha256", |b| b.iter(|| slh_keygen::<RawSha256>()));
    g.bench_function("fast/RawSha256",     |b| b.iter(|| slh_keygen_fast::<RawSha256>()));

    g.bench_function("baseline/Sha256Hasher", |b| b.iter(|| slh_keygen::<Sha256Hasher>()));
    g.bench_function("fast/Sha256Hasher",     |b| b.iter(|| slh_keygen_fast::<Sha256Hasher>()));

    g.finish();
}

// ── sign ───────────────────────────────────────────────

fn bench_sign(c: &mut Criterion) {
    let msg = b"SPHINCS+ benchmark message (fixed input)";
    let mut g = c.benchmark_group("sign");
    g.sample_size(10);

    g.bench_function("baseline/RawSha256", |b| {
        b.iter_batched(
            || slh_keygen::<RawSha256>(), // fresh key each time (avoid reuse bias)
            |(sk, _)| slh_sign::<RawSha256>(msg, &sk),
            BatchSize::SmallInput,
        )
    });

    g.bench_function("fast/RawSha256", |b| {
        b.iter_batched(
            || slh_keygen_fast::<RawSha256>(),
            |(sk, _)| slh_sign_fast::<RawSha256>(msg, &sk),
            BatchSize::SmallInput,
        )
    });

    g.bench_function("baseline/Sha256Hasher", |b| {
        b.iter_batched(
            || slh_keygen::<Sha256Hasher>(),
            |(sk, _)| slh_sign::<Sha256Hasher>(msg, &sk),
            BatchSize::SmallInput,
        )
    });

    g.bench_function("fast/Sha256Hasher", |b| {
        b.iter_batched(
            || slh_keygen_fast::<Sha256Hasher>(),
            |(sk, _)| slh_sign_fast::<Sha256Hasher>(msg, &sk),
            BatchSize::SmallInput,
        )
    });

    g.finish();
}

// ── verify ─────────────────────────────────────────────

fn bench_verify(c: &mut Criterion) {
    let msg = b"verify benchmark msg";
    let mut g = c.benchmark_group("verify");

    g.sample_size(20); // verify is cheaper → more samples

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

// ── xmss root ──────────────────────────────────────────

fn bench_xmss_root(c: &mut Criterion) {
    use sphincs_rs::params::HP;
    use sphincs_rs::xmss::{xmss_node, xmss_node_fast};

    let mut g = c.benchmark_group("xmss_root");
    g.sample_size(10);

    g.bench_function("baseline_recursive/RawSha256", |b| {
        let sk = rng_n();
        let pk = rng_n();
        let adrs = Adrs::new(AdrsType::TreeNode);

        b.iter(|| xmss_node::<RawSha256>(&sk, 0, HP, &pk, adrs))
    });

    g.bench_function("fast_iterative/RawSha256", |b| {
        let sk = rng_n();
        let pk = rng_n();
        let adrs = Adrs::new(AdrsType::TreeNode);

        b.iter(|| xmss_node_fast::<RawSha256>(&sk, 0, HP, &pk, adrs))
    });

    g.finish();
}

// ── WOTS ───────────────────────────────────────────────

fn bench_wots_keygen(c: &mut Criterion) {
    use sphincs_rs::wots::wots_pk_gen;

    let mut g = c.benchmark_group("wots_keygen");

    g.bench_function("RawSha256", |b| {
        let sk = rng_n();
        let pk = rng_n();
        let adrs = Adrs::new(AdrsType::Wots);

        b.iter(|| wots_pk_gen::<RawSha256>(&sk, &pk, &adrs))
    });

    g.finish();
}

// ── FORS ───────────────────────────────────────────────

fn bench_fors_sign(c: &mut Criterion) {
    use sphincs_rs::fors::fors_sign;

    let mut g = c.benchmark_group("fors_sign");
    g.sample_size(20);

    g.bench_function("RawSha256", |b| {
        let sk = rng_n();
        let pk = rng_n();

        let mut md = [0u8; MD_BYTES];
        OsRng.fill_bytes(&mut md);

        let mut adrs = Adrs::new(AdrsType::ForsTree);
        adrs.set_keypair_address(0);

        b.iter(|| fors_sign::<RawSha256>(&md, &sk, &pk, &adrs))
    });

    g.finish();
}

// ── alpha comparison ───────────────────────────────────

fn bench_alpha_comparison(c: &mut Criterion) {
    let mut g = c.benchmark_group("alpha_comparison");
    g.sample_size(10);

    g.bench_function("standard", |b| {
        b.iter(|| {
            let _ = Sha2_256s::total_sig_bytes();
        })
    });

    g.finish();

    // print table (main point of this section)
    println!("\n=== parameter comparison ===");

    let sets = [
        ("standard", Sha2_256s::total_sig_bytes()),
        ("small", Alpha128sSmall::total_sig_bytes()),
        ("fast", Alpha128sFast::total_sig_bytes()),
    ];

    for (name, val) in sets {
        println!("{name}: {val} bytes");
    }
}

// ── group sig ──────────────────────────────────────────

fn bench_group(c: &mut Criterion) {
    use sphincs_rs::group::{
        derive_member_key, group_keygen, group_sign, group_verify, group_identify_member
    };

    let mut g = c.benchmark_group("group");
    g.sample_size(10);

    g.bench_function("keygen", |b| {
        b.iter(|| group_keygen::<RawSha256>())
    });

    g.bench_function("sign", |b| {
        b.iter_batched(
            || {
                let (mgr, _) = group_keygen::<RawSha256>();
                derive_member_key(&mgr, 0)
            },
            |msk| group_sign::<RawSha256>(b"bench", &msk),
            BatchSize::SmallInput,
        )
    });

    g.bench_function("verify", |b| {
        b.iter_batched(
            || {
                let (mgr, gpk) = group_keygen::<RawSha256>();
                let msk = derive_member_key(&mgr, 0);
                let sig = group_sign::<RawSha256>(b"bench", &msk);
                (sig, gpk)
            },
            |(sig, gpk)| group_verify::<RawSha256>(b"bench", &sig, &gpk),
            BatchSize::SmallInput,
        )
    });

    g.bench_function("identify", |b| {
        b.iter_batched(
            || {
                let (mgr, _) = group_keygen::<RawSha256>();
                let msk = derive_member_key(&mgr, 3);
                let sig = group_sign::<RawSha256>(b"id", &msk);
                (mgr, sig)
            },
            |(mgr, sig)| group_identify_member::<RawSha256>(b"id", &sig, &mgr),
            BatchSize::SmallInput,
        )
    });

    g.finish();
}

// ── register ───────────────────────────────────────────

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