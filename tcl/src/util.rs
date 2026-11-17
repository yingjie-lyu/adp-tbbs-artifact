//! `Mpz` conveniences and small integer helpers.

use bicycl::Mpz;

use threshold_bbs::util::mpz_bits;

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

pub fn pow(value: &Mpz, exponent: usize) -> Mpz {
    value.clone().pow(exponent as u64)
}

/// `i^k`.
pub fn index_pow(index: usize, degree: usize) -> Mpz {
    Mpz::from(index as u64).pow(degree as u64)
}

pub fn factorial(n: usize) -> Mpz {
    let mut value = Mpz::from(1u64);
    for factor in 2..=n.max(1) {
        value = value * Mpz::from(factor as u64);
    }
    value
}

pub fn lt(value: &Mpz, bound: &Mpz) -> bool {
    use threshold_bbs::util::mpz_bytes;
    let (lhs, rhs) = (mpz_bytes(value), mpz_bytes(bound));
    if lhs.len() != rhs.len() {
        return lhs.len() < rhs.len();
    }
    lhs < rhs
}

pub fn bits(value: &Mpz) -> usize {
    mpz_bits(value)
}

/// `ceil(log2(x))`, zero for `x <= 1`.
pub fn ceil_log2(value: u128) -> usize {
    if value <= 1 {
        0
    } else {
        128 - (value - 1).leading_zeros() as usize
    }
}
