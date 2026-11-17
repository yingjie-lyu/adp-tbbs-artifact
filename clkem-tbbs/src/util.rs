//! Small `bicycl::Mpz` conveniences.
//!
//! `Mpz` implements its operators on owned values only, so a protocol full of `&Mpz` reads
//! badly without these wrappers. Nothing here is clever; the point is that the call sites in
//! `pvss`, `keygen` and `sign` look like the paper's formulas.

use bicycl::Mpz;


pub fn add(lhs: &Mpz, rhs: &Mpz) -> Mpz {
    lhs.clone() + rhs.clone()
}

pub fn mul(lhs: &Mpz, rhs: &Mpz) -> Mpz {
    lhs.clone() * rhs.clone()
}

pub fn neg(value: &Mpz) -> Mpz {
    Mpz::from(0u64) - value.clone()
}

pub fn square(value: &Mpz) -> Mpz {
    value.clone() * value.clone()
}

/// `value^exponent` for a small non-negative exponent.
pub fn pow(value: &Mpz, exponent: usize) -> Mpz {
    value.clone().pow(exponent as u64)
}

/// `n!`, the interpolation factor `Delta` of the PVSS.
pub fn factorial(n: usize) -> Mpz {
    let mut value = Mpz::from(1u64);
    for factor in 2..=n.max(1) {
        value = value * Mpz::from(factor as u64);
    }
    value
}

/// `i^k` for party index `i` and degree `k`.
pub fn index_pow(index: usize, degree: usize) -> Mpz {
    Mpz::from(index as u64).pow(degree as u64)
}

