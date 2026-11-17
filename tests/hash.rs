//! The two random-oracle fixes: `hashout` must be *exactly* uniform on `Z_q`, and the pairwise
//! mask must use the paper's `sgn(i - j)`.

use bicycl::Mpz;

use threshold_bbs::algebra::Scalar;
use threshold_bbs::bls381::{generator_g1, Scalar255, SCALAR_MODULUS_DECIMAL};
use threshold_bbs::hash::{hashout, in_unbiased_window, mask_scalar, mask_sign, window_threshold};
use threshold_bbs::util::{mpz_lt, pow2, scalar_to_mpz};

/// Approximate `value` as an `f64` from its leading bytes, for ratio assertions only.
fn to_f64(value: &Mpz) -> f64 {
    let bytes = threshold_bbs::util::mpz_bytes(value);
    if bytes.is_empty() {
        return 0.0;
    }
    let take = bytes.len().min(8);
    let mut mantissa: u64 = 0;
    for byte in &bytes[..take] {
        mantissa = (mantissa << 8) | u64::from(*byte);
    }
    mantissa as f64 * 2f64.powi(8 * (bytes.len() - take) as i32)
}

fn ratio(numerator: &Mpz, denominator: &Mpz) -> f64 {
    to_f64(numerator) / to_f64(denominator)
}

/// `q`, and the width `r = 2^256 - 2q` of the interval that a raw 256-bit reduction favours.
fn modulus_and_r() -> (Mpz, Mpz) {
    let q = Mpz::from(SCALAR_MODULUS_DECIMAL);
    let r = pow2(256) - Mpz::from(2u64) * q.clone();
    (q, r)
}

/// The 256-bit construction this crate used to have lands in `[0, r)` with probability
/// `3r/2^256 = 0.2844`; a uniform field element does so with probability `r/q = 0.2083`, and a
/// 512-bit reduction with rejection is uniform. With `n = 20000` the standard deviation is
/// 0.0029, so the two hypotheses are ~26 sigma apart and this test pins the fix.
#[test]
fn hashout_is_uniform_on_the_low_interval() {
    let (q, r) = modulus_and_r();
    let expected = ratio(&r, &q);
    assert!(
        (expected - 0.2083).abs() < 0.002,
        "r/q sanity: {expected}"
    );

    let n = 20_000usize;
    let base = generator_g1();
    let mut low = 0usize;
    for index in 0..n {
        let (e, _phi) = hashout(&(index as u64).to_be_bytes(), b"msg", &[1, 2, 3], &base);
        if mpz_lt(&scalar_to_mpz(&e), &r) {
            low += 1;
        }
    }
    let frequency = low as f64 / n as f64;
    assert!(
        (frequency - expected).abs() < 0.012,
        "P[e < r] = {frequency}, expected ~{expected} (the biased 256-bit reduction gives 0.2844)"
    );
}

#[test]
fn hashout_is_deterministic_and_domain_separated() {
    let base = generator_g1();
    let first = hashout(b"sid", b"msg", &[1, 2, 3], &base);
    let second = hashout(b"sid", b"msg", &[1, 2, 3], &base);
    assert_eq!(first.0, second.0, "hashout must be deterministic");
    assert_eq!(first.1, second.1, "hashout must be deterministic");
    assert_ne!(first.0, first.1, "e and phi come from independent tags");
    assert_ne!(
        first.0,
        hashout(b"sid2", b"msg", &[1, 2, 3], &base).0,
        "the session id must change the output"
    );
    assert_ne!(
        first.0,
        hashout(b"sid", b"msg", &[1, 2], &base).0,
        "the quorum must change the output"
    );
}

/// `2^512 - (2^512 mod q)` must be a multiple of `q` just below `2^512`: the gap to `2^512` is
/// exactly `2^512 mod q`, which is smaller than `q`, and the threshold itself is in the window.
#[test]
fn window_threshold_bounds_the_rejection_window() {
    let (q, _) = modulus_and_r();
    let threshold = window_threshold();
    let top = pow2(512);
    let gap = top.clone() - threshold.clone();
    assert!(mpz_lt(&gap, &q), "the gap must be 2^512 mod q < q");
    assert!(mpz_lt(threshold, &top), "the threshold must be below 2^512");
    assert!(mpz_lt(&(top.clone() - q.clone()), threshold), "and within q of it");
    // A value one below the threshold is accepted, the threshold itself is not.
    assert!(in_unbiased_window(&(threshold.clone() - Mpz::from(1u64))));
    assert!(!in_unbiased_window(threshold));
}

/// The mask sign must follow the paper's `sgn(i - j)`, be antisymmetric, and cancel over an
/// unordered pair so that the shares of all signers add up.
#[test]
fn mask_sign_matches_the_paper_and_cancels() {
    assert_eq!(mask_sign(1, 2), -1, "sgn(1-2) = -1");
    assert_eq!(mask_sign(2, 1), 1, "sgn(2-1) = 1");
    assert_eq!(mask_sign(2, 3), -1);
    assert_eq!(mask_sign(3, 2), 1);

    let quorum = [1usize, 2, 3, 4];
    for i in quorum {
        for j in quorum {
            if i != j {
                assert_eq!(
                    mask_sign(i, j),
                    -mask_sign(j, i),
                    "antisymmetry for ({i}, {j})"
                );
            }
        }
    }

    // Sum over the ordered pairs of a symmetric mask table, exactly as `u_i` and `S_i` do:
    // every unordered pair contributes `+m` and `-m` of the *same* value.
    let mut total = Scalar255::zero();
    for i in quorum {
        for j in quorum {
            if i == j {
                continue;
            }
            let low = [i.min(j) as u8; 32];
            let high = [i.max(j) as u8; 32];
            let value = mask_scalar(&low, &high);
            let signed = if mask_sign(i, j) > 0 {
                value
            } else {
                Scalar255::zero().sub(&value)
            };
            total = total.add(&signed);
        }
    }
    assert_eq!(total, Scalar255::zero(), "pairwise masks must cancel");
}

fn hex(value: &Scalar255) -> String {
    value
        .to_be_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The derivation this crate used before the fix: one SHA-512, split into two 256-bit halves,
/// each reduced modulo `q`. It is kept here so the regression test above is demonstrably able
/// to tell the two designs apart.
fn biased_derivation(session: &[u8], vrf_output: &threshold_bbs::bls381::G1) -> Scalar255 {
    let mut transcript = threshold_bbs::hash::Transcript::new(b"threshold-bbs/v03/hashout");
    transcript
        .absorb_bytes(b"sid", session)
        .absorb_bytes(b"msg", b"msg")
        .absorb_quorum(&[1, 2, 3])
        .absorb_g1(b"W", vrf_output);
    let digest = transcript.digest();
    Scalar255::from_be_bytes_mod_order(&digest[..32])
}

/// The old construction lands in `[0, r)` with probability `3r/2^256 = 0.2844`, far outside the
/// tolerance the test above allows; this pins that the fix changed the distribution, not just
/// the code.
#[test]
fn the_old_256_bit_derivation_would_fail_the_uniformity_test() {
    let (q, r) = modulus_and_r();
    let expected = ratio(&r, &q);
    let n = 20_000usize;
    let base = generator_g1();
    let mut low = 0usize;
    for index in 0..n {
        let e = biased_derivation(&(index as u64).to_be_bytes(), &base);
        if mpz_lt(&scalar_to_mpz(&e), &r) {
            low += 1;
        }
    }
    let frequency = low as f64 / n as f64;
    assert!(
        (frequency - 0.2844).abs() < 0.012,
        "the old derivation should sit near 3r/2^256 = 0.2844, got {frequency}"
    );
    assert!(
        (frequency - expected).abs() > 0.03,
        "and it must be far from the uniform value {expected}"
    );
}

/// Reference values for the fixed oracle. Regenerate only together with an intentional change
/// of the derivation; the two hex strings are what every signer must derive from the same
/// transcript.
#[test]
fn reference_vector() {
    let base = generator_g1();
    let (e, phi) = hashout(b"reference-sid", b"reference-msg", &[1, 2, 3], &base);
    assert_eq!(
        hex(&e),
        "4266cc0c9046081290c796f0eb663ca48df12b505bc9c42d3eef1b113845313c",
        "reference e changed"
    );
    assert_eq!(
        hex(&phi),
        "08ccb46fc11f966aad0292729d770d64c3a689b1c377118c7ab7607797de3caf",
        "reference phi changed"
    );
}
