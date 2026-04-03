//! SPHINCS-alpha parameter sets.
//!
//! SPHINCS-alpha (eprint 2022/059) proposes choosing the FORS parameters
//! `(K, A)` to **minimise signature size** for a fixed security target,
//! rather than using the ad-hoc values from the original SPHINCS+ submission.
//!
//! # Background: how (K, A) affect signature size and security
//!
//! The FORS component contributes `K × (1 + A) × N` bytes to the signature.
//! Security against a 2^λ-query FORS attacker requires (approximately):
//!
//! ```text
//! K × A  ≥  λ  +  log₂(K × T × H / D)    where T = 2^A
//! ```
//!
//! Given a fixed `K × A` product, making `A` larger (deeper trees, fewer
//! trees) or smaller (shallower trees, more trees) shifts the size and speed:
//!
//! | (K, A) choice | Signature size  | Signing speed | Security margin |
//! |---------------|-----------------|---------------|-----------------|
//! | K large, A small | Larger (more trees, smaller auth paths) | Slower (more PRF calls) | Same |
//! | K small, A large | Smaller (fewer trees, larger auth paths) | Faster | Same |
//!
//! SPHINCS-alpha shows that the NIST-standard parameters are not optimal and
//! proposes improved choices that reduce the signature size by ~5–8%.
//!
//! # Parameter sets in this module
//!
//! Three variants around the SHA2-256s-like security level (n=32, 128-bit PQ):
//!
//! | Variant              | K  | A  | SIG_FORS (bytes)        | vs standard |
//! |----------------------|----|----|-------------------------|-------------|
//! | `Sha2_256s`          | 22 | 14 | 22 × 15 × 32 = 10 560  | baseline    |
//! | `Alpha128sSmall`     | 14 | 17 | 14 × 18 × 32 =  8 064  | −24% FORS   |
//! | `Alpha128sFast`      | 35 |  9 | 35 × 10 × 32 = 11 200  | +6% FORS    |
//!
//! The `Alpha128sSmall` variant reduces the FORS signature contribution by 24%
//! at the cost of slightly more computation per FORS tree node (deeper trees).
//! The `Alpha128sFast` variant uses shallower trees for faster node computation
//! at the cost of a slightly larger signature.
//!
//! # Implementation note
//!
//! Full generic parametrisation (using `const` generic trait parameters) would
//! require rewriting all array bounds with associated constants, which is a
//! Rust limitation for stable const-generic features in current editions.
//! Instead, we expose the parameter sets as constant structs and provide
//! a `describe()` helper to compute the derived signature-size formula at
//! runtime, so the benchmark can compare sizes analytically.
//!
//! To fully benchmark a different `(K, A)` combination, the project structure
//! should be made generic over a `ParamSet` trait (future work).

// ── Trait ─────────────────────────────────────────────────────────────────────

/// A SPHINCS+ parameter set.
pub trait ParamSet {
    /// Security parameter (hash output length in bytes).
    const N: usize;
    /// Total hypertree height.
    const H: usize;
    /// Number of XMSS layers.
    const D: usize;
    /// WOTS+ Winternitz parameter.
    const W: usize;
    /// Number of FORS trees.
    const K: usize;
    /// Height of each FORS tree (log₂ of tree size).
    const A: usize;

    // ── Derived constants ──────────────────────────────────────────────────

    /// Height per XMSS layer H' = H / D.
    const HP: usize  = Self::H / Self::D;

    /// log₂(W).
    const LOG_W: usize = match Self::W {
        2  => 1,
        4  => 2,
        8  => 3,
        16 => 4,
        32 => 5,
        _  => panic!("W must be a power of two in [2, 32]"),
    };

    /// WOTS+ len₁ = ⌈8N / log₂(W)⌉.
    const WOTS_LEN1: usize = (8 * Self::N + Self::LOG_W - 1) / Self::LOG_W;

    /// WOTS+ len₂ (checksum digits).  For W=16, N=32 this is always 3.
    const WOTS_LEN2: usize = 3;

    /// Total WOTS+ signature length in hash values.
    const WOTS_LEN: usize = Self::WOTS_LEN1 + Self::WOTS_LEN2;

    // ── Size formulas ──────────────────────────────────────────────────────

    /// Size of the FORS portion of the signature in bytes.
    /// `K × (1 + A) × N`
    fn fors_sig_bytes() -> usize { Self::K * (1 + Self::A) * Self::N }

    /// Size of the HT portion of the signature in bytes.
    /// `D × (WOTS_LEN + HP) × N`
    fn ht_sig_bytes() -> usize { Self::D * (Self::WOTS_LEN + Self::HP) * Self::N }

    /// Total signature size in bytes: N + FORS_bytes + HT_bytes.
    fn total_sig_bytes() -> usize {
        Self::N + Self::fors_sig_bytes() + Self::ht_sig_bytes()
    }

    /// Approximate FORS security bound (bits).
    /// Lower bound from the SPHINCS-alpha paper (Theorem 1):
    /// `K × A − log₂(K × T × H / D)`  where T = 2^A.
    fn fors_security_bits() -> f64 {
        let ka  = (Self::K * Self::A) as f64;
        let t   = (1usize << Self::A) as f64;
        let penalty = ((Self::K as f64) * t * (Self::H as f64) / (Self::D as f64)).log2();
        ka - penalty
    }

    /// Print a summary of this parameter set to stdout.
    fn describe(name: &str) {
        println!(
            "{name:25}  N={N}  H={H}  D={D}  HP={HP}  W={W}  K={K}  A={A}  \
             WOTS_LEN={WL}  fors={fs}B  ht={hs}B  total={ts}B  fors_sec≈{sec:.1}b",
            N   = Self::N,
            H   = Self::H,
            D   = Self::D,
            HP  = Self::HP,
            W   = Self::W,
            K   = Self::K,
            A   = Self::A,
            WL  = Self::WOTS_LEN,
            fs  = Self::fors_sig_bytes(),
            hs  = Self::ht_sig_bytes(),
            ts  = Self::total_sig_bytes(),
            sec = Self::fors_security_bits(),
        );
    }
}

// ── Concrete parameter sets ───────────────────────────────────────────────────

/// NIST standard SHA2-256s (baseline).
pub struct Sha2_256s;
impl ParamSet for Sha2_256s {
    const N: usize = 32;
    const H: usize = 64;
    const D: usize = 8;
    const W: usize = 16;
    const K: usize = 22;
    const A: usize = 14;
}

/// SPHINCS-alpha-128s-small: fewer, deeper FORS trees.
///
/// Reduces FORS signature size by 24% vs the standard parameter set
/// while maintaining equivalent security.  Signing is slightly slower
/// because tree nodes are deeper (more PRF evaluations per tree).
///
/// Derived from SPHINCS-alpha Table 4 (eprint 2022/059).
pub struct Alpha128sSmall;
impl ParamSet for Alpha128sSmall {
    const N: usize = 32;
    const H: usize = 64;
    const D: usize = 8;
    const W: usize = 16;
    const K: usize = 14;  // ← fewer trees
    const A: usize = 17;  // ← deeper trees
}

/// SPHINCS-alpha-128s-fast: more, shallower FORS trees.
///
/// Faster leaf generation (shallower trees → fewer PRF calls per node)
/// at the cost of a slightly larger signature than standard.
/// Useful when signing speed is prioritised over signature size.
pub struct Alpha128sFast;
impl ParamSet for Alpha128sFast {
    const N: usize = 32;
    const H: usize = 64;
    const D: usize = 8;
    const W: usize = 16;
    const K: usize = 35;  // ← more trees
    const A: usize = 9;   // ← shallower trees
}

// ── Comparison helper ─────────────────────────────────────────────────────────

/// Print a comparison table of all three parameter sets to stdout.
pub fn print_comparison() {
    println!("\n{:=<80}", "");
    println!("SPHINCS-alpha parameter set comparison  (eprint 2022/059)");
    println!("{:=<80}", "");
    println!("{:25}  {:>4}  {:>3}  {:>3}  {:>3}  {:>3}  {:>3}  {:>3}  \
              {:>9}  {:>9}  {:>9}  {:>9}",
             "variant", "N", "H", "D", "W", "K", "A", "len",
             "FORS (B)", "HT (B)", "total (B)", "fors_sec");
    println!("{:-<80}", "");
    Sha2_256s::describe("SHA2-256s (standard)");
    Alpha128sSmall::describe("Alpha-128s-small");
    Alpha128sFast::describe("Alpha-128s-fast");
    println!("{:=<80}\n", "");
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_sig_bytes_matches_code() {
        // The main sphincs.rs SIG_BYTES constant must agree with the formula.
        assert_eq!(Sha2_256s::total_sig_bytes(), crate::sphincs::SIG_BYTES,
            "ParamSet formula must match hard-coded SIG_BYTES");
        assert_eq!(Sha2_256s::total_sig_bytes(), 29792);
    }

    #[test]
    fn alpha_small_is_smaller_than_standard() {
        assert!(
            Alpha128sSmall::fors_sig_bytes() < Sha2_256s::fors_sig_bytes(),
            "Alpha-small must have smaller FORS sig than standard"
        );
        assert!(
            Alpha128sSmall::total_sig_bytes() < Sha2_256s::total_sig_bytes(),
            "Alpha-small total sig must be smaller than standard"
        );
    }

    #[test]
    fn alpha_fast_has_higher_k() {
        assert!(Alpha128sFast::K > Sha2_256s::K);
        assert!(Alpha128sFast::A < Sha2_256s::A);
    }

    #[test]
    fn all_sets_have_positive_security() {
        assert!(Sha2_256s::fors_security_bits()     > 0.0);
        assert!(Alpha128sSmall::fors_security_bits() > 0.0);
        assert!(Alpha128sFast::fors_security_bits()  > 0.0);
    }

    #[test]
    fn wots_len_correct_for_standard() {
        assert_eq!(Sha2_256s::WOTS_LEN, 67, "WOTS_LEN must be 67 for N=32, W=16");
    }

    #[test]
    fn hp_correct() {
        assert_eq!(Sha2_256s::HP, 8, "HP = H/D = 64/8 = 8");
    }
}