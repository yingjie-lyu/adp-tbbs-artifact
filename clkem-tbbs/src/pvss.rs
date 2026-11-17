//! Publicly verifiable secret sharing in the class group (paper §2.4).
//!
//! Braun et al.'s Feldman-style construction over `Cl(Delta)`, used to distribute each
//! party's contribution `v_i` to the *implicit* CL secret key `sk = sum_j v_j`:
//!
//! ```text
//! h(x) = Delta v + sum_{k=1}^{t-1} a_k x^k,   y_i = h(i),   Delta = n!
//! C_0 = g_q^{v},  C_k = g_qDelta^{a_k},  g_qDelta = g_q^Delta
//! SScheck_i:  g_q^{Delta y_i} = C_0^{Delta^2} * prod_{k=1}^{t-1} C_k^{i^k}
//! ```
//!
//! `sk` itself is never formed: the shares `y_i` are integers (not residues, since `s'` is
//! unknown) and any `t` of them reconstruct `sk` as `Delta^{-2} sum_i (Delta L_i(0)) y_i`.
//! The `Delta^2` is what the `Delta^2` in `pd_i` cancels against.

use bicycl::{Mpz, QFI, RandGen};

use threshold_bbs::util::{mpz_bits, pow2};

use crate::cl::ClParameters;
use crate::params::PublicParameters;
use crate::stats::Meter;
use crate::util::{add, index_pow, mul};
use crate::zkp::{self, DlProof};

pub const DOMAIN_PVSS: &[u8] = b"clkem-tbbs/v01/zkp/pvss";

/// A dealt share: public commitments and proofs plus the private shares.
#[derive(Clone, Debug)]
pub struct Deal {
    /// `C_0 .. C_{t-1}`.
    pub commitments: Vec<QFI>,
    pub proofs: Vec<DlProof>,
    /// `shares[i-1]` is party `i`'s share `y_i`.
    pub shares: Vec<Mpz>,
}

/// `ell_0 = ceil(log2 B_q) + 1 + ceil(log2(t (t-1) n^n))`, the paper's coefficient length.
pub fn coefficient_bits(pp: &PublicParameters, n: usize, t: usize) -> usize {
    let spread = (t.max(1) * t.saturating_sub(1)).max(1) as u128;
    // n^n as a bit length without computing it.
    let nn_bits: f64 = if n == 0 {
        0.0
    } else {
        (n as f64).ln() * n as f64 / std::f64::consts::LN_2
    };
    let spread_bits = bits_of_u128(spread);
    mpz_bits(pp.cl.bound_bq()) + 1 + spread_bits + nn_bits.ceil() as usize
}

fn bits_of_u128(value: u128) -> usize {
    if value <= 1 {
        0
    } else {
        128 - (value - 1).leading_zeros() as usize
    }
}

/// `2^{ell_0 + lambda_d}`, the bound on the polynomial coefficients `a_k`.
pub fn coefficient_bound(pp: &PublicParameters, n: usize, t: usize) -> Mpz {
    pow2(coefficient_bits(pp, n, t) + pp.config.lambda_d)
}

/// Deal `value` to parties `1..=n` with threshold `t`.
pub fn deal(
    pp: &PublicParameters,
    ctx: &[u8],
    value: &Mpz,
    n: usize,
    t: usize,
    delta: &Mpz,
    rng: &mut RandGen,
    meter: &mut Meter,
) -> Deal {
    let cl = &pp.cl;
    let bound = coefficient_bound(pp, n, t);
    let coefficients: Vec<Mpz> = (1..t).map(|_| rng.random_mpz(&bound)).collect();
    let gq_delta = cl.gq_pow_delta(delta, meter);

    let mut commitments = Vec::with_capacity(t);
    let mut proofs = Vec::with_capacity(t);

    let first = cl.exp(cl.gq(), value, meter);
    proofs.push(zkp::prove_dl(
        pp,
        DOMAIN_PVSS,
        ctx,
        cl.gq(),
        &first,
        value,
        cl.bound_bq(),
        rng,
        meter,
    ));
    commitments.push(first);

    for coefficient in &coefficients {
        let commitment = cl.exp(&gq_delta, coefficient, meter);
        proofs.push(zkp::prove_dl(
            pp,
            DOMAIN_PVSS,
            ctx,
            &gq_delta,
            &commitment,
            coefficient,
            &bound,
            rng,
            meter,
        ));
        commitments.push(commitment);
    }

    let shares = (1..=n)
        .map(|index| {
            let mut share = mul(delta, value);
            for (position, coefficient) in coefficients.iter().enumerate() {
                share = add(&share, &mul(coefficient, &index_pow(index, position + 1)));
            }
            share
        })
        .collect();

    Deal {
        commitments,
        proofs,
        shares,
    }
}

/// `SScheck_i`: verify the share `y_i` against the dealer's public commitments.
pub fn check_share(
    cl: &ClParameters,
    commitments: &[QFI],
    delta: &Mpz,
    index: usize,
    share: &Mpz,
    meter: &mut Meter,
) -> bool {
    if commitments.is_empty() {
        return false;
    }
    let left = cl.exp(cl.gq(), &mul(delta, share), meter);
    let mut right = cl.exp(&commitments[0], &mul(delta, delta), meter);
    for (position, commitment) in commitments.iter().enumerate().skip(1) {
        let term = cl.exp(commitment, &index_pow(index, position), meter);
        right = cl.compose(&right, &term, meter);
    }
    left == right
}

/// Verify a dealer's commitments and their proofs.
pub fn verify_deal(
    pp: &PublicParameters,
    ctx: &[u8],
    delta: &Mpz,
    commitments: &[QFI],
    proofs: &[DlProof],
    n: usize,
    t: usize,
    meter: &mut Meter,
) -> bool {
    if commitments.len() != t || proofs.len() != t {
        return false;
    }
    let cl = &pp.cl;
    let gq_delta = cl.gq_pow_delta(delta, meter);
    let bound = coefficient_bound(pp, n, t);

    if !zkp::verify_dl(
        pp,
        DOMAIN_PVSS,
        ctx,
        cl.gq(),
        &commitments[0],
        &proofs[0],
        cl.bound_bq(),
        meter,
    ) {
        return false;
    }
    (1..t).all(|position| {
        zkp::verify_dl(
            pp,
            DOMAIN_PVSS,
            ctx,
            &gq_delta,
            &commitments[position],
            &proofs[position],
            &bound,
            meter,
        )
    })
}

/// `Delta * L_i^T(0)`, the integer Lagrange coefficient of party `id` in `quorum`.
///
/// `L_i^T(0) = prod_{j != i} (0 - j) / (j - i)` can be fractional, but `Delta = n!` clears
/// every denominator, so the product is an integer and exact division applies.
pub fn delta_lagrange(delta: &Mpz, id: usize, quorum: &[usize]) -> Mpz {
    let mut numerator = Mpz::from(1u64);
    let mut denominator = Mpz::from(1u64);
    // `L_i(0) = prod_{j != i} (-j) / (i - j)`. The `t-1` factors of `-1` in the numerator and
    // the `t-1` in `(i - j) = -(j - i)` cancel, so the sign of the coefficient is
    // `prod_j sign(j - i)`: negative exactly when an odd number of peers sit below `i`.
    let mut negative = false;

    for &peer in quorum {
        if peer == id {
            continue;
        }
        numerator = numerator * Mpz::from(peer as u64);
        let difference = peer as i64 - id as i64;
        if difference < 0 {
            negative = !negative;
        }
        denominator = denominator * Mpz::from(difference.unsigned_abs());
    }

    let magnitude = (delta.clone() * numerator) / denominator;
    if negative {
        Mpz::from(0u64) - magnitude
    } else {
        magnitude
    }
}

/// `sum_{i in T} Delta L_i(0) = Delta` when `T` is a `(t, n)` share set with `t >= 1`.
pub fn check_lagrange_unit(delta: &Mpz, quorum: &[usize]) -> bool {
    let mut total = Mpz::from(0u64);
    for &id in quorum {
        total = add(&total, &delta_lagrange(delta, id, quorum));
    }
    // sum_i L_i(0) = 1, so sum_i Delta L_i(0) = Delta.
    total == *delta
}
