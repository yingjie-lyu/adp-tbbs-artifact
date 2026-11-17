//! Secret sharing: Shamir over `Z_q` (for the discrete-log keys), Shamir over the integers
//! (Z-SS, with `Delta = n!`) for the class-group key, Lagrange coefficients, and the dual-code
//! consistency check both papers use.

use bicycl::{Mpz, RandGen};

use threshold_bbs::algebra::Scalar;
use threshold_bbs::bls381::Scalar255;
use threshold_bbs::util::mpz_to_scalar;

use crate::error::{Error, Result};
use crate::util::{add, ceil_log2, factorial, index_pow, mul, pow};

/// Shamir over `Z_q`: shares `F(i)` with `F(0) = secret`, so plain Lagrange reconstructs.
pub fn shamir_scalar(
    secret: &Scalar255,
    n: usize,
    t: usize,
    rng: &mut impl rand_core::RngCore,
) -> Vec<Scalar255> {
    let coefficients: Vec<Scalar255> = (1..t).map(|_| Scalar255::random(rng)).collect();
    (1..=n)
        .map(|index| {
            let mut value = secret.clone();
            let mut power = Scalar255::from_u64(index as u64);
            for coefficient in &coefficients {
                value = value.add(&power.mul(coefficient));
                power = power.mul(&Scalar255::from_u64(index as u64));
            }
            value
        })
        .collect()
}

/// `sum_d coefficients[d] * point^d` in `Z_q`.
pub fn eval_scalar(coefficients: &[Scalar255], point: usize) -> Scalar255 {
    let mut value = <Scalar255 as Scalar>::zero();
    let base = Scalar255::from_u64(point as u64);
    let mut power = Scalar255::from_u64(1);
    for coefficient in coefficients {
        value = value.add(&power.mul(coefficient));
        power = power.mul(&base);
    }
    value
}

/// `L_i(0)` in `Z_q`, for plain Shamir shares.
pub fn lagrange_scalar(id: usize, quorum: &[usize]) -> Scalar255 {
    let mut numerator = Scalar255::from_u64(1);
    let mut denominator = Scalar255::from_u64(1);
    for &peer in quorum {
        if peer == id {
            continue;
        }
        let j = Scalar255::from_u64(peer as u64);
        let d = Scalar255::from_u64((peer as i64 - id as i64).unsigned_abs());
        numerator = numerator.mul(&j);
        denominator = denominator.mul(&d);
        if peer < id {
            // (0 - j)/(id - j) with id - j > 0
            numerator = <Scalar255 as Scalar>::zero().sub(&numerator);
        }
    }
    numerator.mul(
        &denominator
            .invert()
            .expect("distinct evaluation points keep the denominator invertible"),
    )
}

/// `sum_i L_i(0) x_i` for plain Shamir shares.
pub fn reconstruct_scalar(quorum: &[usize], shares: &[(usize, Scalar255)]) -> Scalar255 {
    let mut total = <Scalar255 as Scalar>::zero();
    for (id, share) in shares {
        total = total.add(&lagrange_scalar(*id, quorum).mul(share));
    }
    total
}

/// `Delta L_i(0)` as an integer, for Z-SS shares.
pub fn delta_lagrange(delta: &Mpz, id: usize, quorum: &[usize]) -> Mpz {
    let mut numerator = Mpz::from(1u64);
    let mut denominator = Mpz::from(1u64);
    // `L_i(0) = prod_{j != i} (-j)/(i-j)`; the `t-1` minus signs cancel, leaving
    // `prod_j sign(j - i)`.
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

/// Shamir sharing over the integers (Z-SS).
///
/// `F(z) = Delta x + sum_{d=1}^{t-1} a_d z^d` with `a_d <- [0, 2^{l^* + lambda_d})`, shares
/// `F(i)`. Any `t` shares reconstruct `Delta^2 x`, not `x` — the modulus `s` is unknown, so
/// division is not available.
#[derive(Clone, Debug)]
pub struct Zss {
    pub delta: Mpz,
    /// `l^* = (l + 1) + 2 log t + n log n`, the coefficient-length parameter.
    pub l_star: usize,
    pub lambda_d: usize,
}

impl Zss {
    pub fn new(n: usize, t: usize, bound_bits: usize, lambda_d: usize) -> Self {
        let l_star = bound_bits
            + 1
            + 2 * ceil_log2(t.max(1) as u128)
            + n * ceil_log2(n.max(1) as u128);
        Self {
            delta: factorial(n),
            l_star,
            lambda_d,
        }
    }

    /// `2^{l^* + lambda_d}`, the bound on the polynomial coefficients.
    pub fn coefficient_bound(&self) -> Mpz {
        threshold_bbs::util::pow2(self.l_star + self.lambda_d)
    }

    /// Honest share bound: `n^t 2^{l^* + lambda_d}`.
    pub fn share_bound(&self, n: usize, t: usize) -> Mpz {
        mul(&pow(&Mpz::from(n as u64), t), &self.coefficient_bound())
    }

    /// `{F(i)}_{i in 1..=n}` with `F(0) = Delta * secret`, using caller-supplied
    /// coefficients `a_1..a_{t-1}` so that the commitments and the shares agree.
    pub fn shares_from(&self, secret: &Mpz, coefficients: &[Mpz], n: usize) -> Vec<Mpz> {
        (1..=n)
            .map(|index| {
                let mut value = mul(&self.delta, secret);
                for (position, coefficient) in coefficients.iter().enumerate() {
                    value = add(&value, &mul(coefficient, &index_pow(index, position + 1)));
                }
                value
            })
            .collect()
    }

    /// Fresh coefficients `a_1..a_{t-1}` in `[0, 2^{l^* + lambda_d})`.
    pub fn coefficients(&self, t: usize, rng: &mut RandGen) -> Vec<Mpz> {
        let bound = self.coefficient_bound();
        (1..t).map(|_| rng.random_mpz(&bound)).collect()
    }

    /// `sum_i (Delta L_i) x_i = Delta^2 secret`.
    pub fn reconstruct(&self, quorum: &[usize], shares: &[(usize, Mpz)]) -> Mpz {
        let mut total = Mpz::from(0u64);
        for (id, share) in shares {
            total = add(&total, &mul(&delta_lagrange(&self.delta, *id, quorum), share));
        }
        total
    }

    /// `secret` from `Delta^2 secret`.
    pub fn unscale(&self, value: &Mpz) -> Result<Scalar255> {
        let squared = mul(&self.delta, &self.delta);
        let inverse = mpz_to_scalar(&squared)
            .invert()
            .ok_or(Error::Arithmetic("Delta^2 is not invertible mod q"))?;
        Ok(mpz_to_scalar(value).mul(&inverse))
    }

    /// `Z-SS.Dual(P)`: weights `x_i^perp = Delta * P(i) / prod_{j != i} (i - j)` with a
    /// random `P` of degree `n - t - 1`.
    ///
    /// The division is exact: `prod_{j != i} |i - j| = (i-1)! (n-i)! <= (n-1)!`, which divides
    /// `Delta = n!`. For shares of a degree-`(t-1)` polynomial and `deg P <= n - t - 1` the
    /// product has degree `<= n - 2`, and `sum_i f(i) / prod_{j != i}(i - j) = 0` for any such
    /// `f`, so valid shares always pass `verify_dual`.
    pub fn dual_weights(&self, parties: &[usize], t: usize, rng: &mut RandGen) -> Vec<Mpz> {
        let n = parties.len();
        let degree = n.saturating_sub(t + 1);
        let bound = self.coefficient_bound();
        let coefficients: Vec<Mpz> = (0..=degree).map(|_| rng.random_mpz(&bound)).collect();

        parties
            .iter()
            .map(|id| {
                let value = eval(&coefficients, *id);
                let mut denominator = Mpz::from(1u64);
                let mut negative = false;
                for &peer in parties {
                    if peer == *id {
                        continue;
                    }
                    let difference = *id as i64 - peer as i64;
                    if difference < 0 {
                        negative = !negative;
                    }
                    denominator = denominator * Mpz::from(difference.unsigned_abs());
                }
                let magnitude = (mul(&self.delta, &value)) / denominator;
                if negative {
                    Mpz::from(0u64) - magnitude
                } else {
                    magnitude
                }
            })
            .collect()
    }

    /// `prod_i PC_i^{x_i^perp} == 1`: the dual-code consistency check on committed shares.
    pub fn verify_dual(
        &self,
        commitments: &[bicycl::QFI],
        weights: &[Mpz],
        cl: &crate::cl::ClParameters,
        meter: &mut crate::meter::Meter,
    ) -> bool {
        if commitments.len() != weights.len() {
            return false;
        }
        let powered: Vec<bicycl::QFI> = commitments
            .iter()
            .zip(weights)
            .map(|(commitment, weight)| cl.exp(commitment, weight, meter))
            .collect();
        cl.compose_many(&powered, meter) == *cl.identity()
    }
}

fn eval(coefficients: &[Mpz], point: usize) -> Mpz {
    let mut total = Mpz::from(0u64);
    for (degree, coefficient) in coefficients.iter().enumerate() {
        total = add(&total, &mul(coefficient, &index_pow(point, degree)));
    }
    total
}
