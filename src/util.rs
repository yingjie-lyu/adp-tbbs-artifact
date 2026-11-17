//! Small helpers bridging the class-group integers (`bicycl::Mpz`) and the scalar field.

use bicycl::Mpz;

use crate::algebra::Scalar;
use crate::bls381::Scalar255;

/// `2^bits` as a class-group integer.
pub fn pow2(bits: usize) -> Mpz {
    Mpz::from(2u64).pow(bits as u64)
}

/// Big-endian magnitude of a non-negative `Mpz`. The empty vector encodes zero.
pub fn mpz_bytes(value: &Mpz) -> Vec<u8> {
    let bytes = value.to_bytes();
    if bytes.iter().all(|byte| *byte == 0) {
        Vec::new()
    } else if bytes.first() == Some(&0) {
        bytes.into_iter().skip_while(|byte| *byte == 0).collect()
    } else {
        bytes
    }
}

pub fn mpz_from_bytes(bytes: &[u8]) -> Mpz {
    let trimmed: Vec<u8> = bytes
        .iter()
        .copied()
        .skip_while(|byte| *byte == 0)
        .collect();
    if trimmed.is_empty() {
        Mpz::from(0u64)
    } else {
        Mpz::from_bytes(&trimmed)
    }
}

/// Bit length of a non-negative `Mpz` (zero has length 0).
pub fn mpz_bits(value: &Mpz) -> usize {
    let bytes = mpz_bytes(value);
    match bytes.first() {
        None => 0,
        Some(first) => (bytes.len() - 1) * 8 + (8 - first.leading_zeros() as usize),
    }
}

/// Sign of an `Mpz` as `-1`, `0`, or `1`.
///
/// `Mpz::to_bytes` returns the magnitude only, so the sign has to be recovered from the
/// decimal form. This matters wherever a group element is hashed or transmitted: the forms
/// `(a, b, c)` and `(a, -b, c)` share a discriminant but are different elements.
pub fn mpz_sign(value: &Mpz) -> i8 {
    if mpz_is_zero(value) {
        0
    } else if value.to_string().starts_with('-') {
        -1
    } else {
        1
    }
}

pub fn mpz_neg(value: &Mpz) -> Mpz {
    Mpz::from(0u64) - value.clone()
}

pub fn mpz_is_zero(value: &Mpz) -> bool {
    mpz_bytes(value).is_empty()
}

/// Order non-negative `Mpz` values by magnitude, most significant byte first.
pub fn mpz_lt(lhs: &Mpz, rhs: &Mpz) -> bool {
    let (a, b) = (mpz_bytes(lhs), mpz_bytes(rhs));
    if a.len() != b.len() {
        return a.len() < b.len();
    }
    a < b
}

/// Reduce a non-negative `Mpz` into `Z_q`.
pub fn mpz_to_scalar(value: &Mpz) -> Scalar255 {
    Scalar255::from_be_bytes_mod_order(&mpz_bytes(value))
}

/// Embed a scalar into `[0, q)` as a class-group integer.
pub fn scalar_to_mpz(value: &Scalar255) -> Mpz {
    mpz_from_bytes(&value.to_be_bytes())
}

pub fn scalar_zero() -> Scalar255 {
    <Scalar255 as Scalar>::zero()
}
