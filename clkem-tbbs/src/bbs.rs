//! BBS+ signatures: the object the threshold protocol produces, and a single-signer
//! reference for comparison.
//!
//! `A = (G_1 + s H_1 + sum_k m_k H_{k+1}) / (x + e)` with verification
//! `e(A, X + e G_2) = e(B, G_2)`.

use threshold_bbs::algebra::{Group, PairingGroup, Scalar};
use threshold_bbs::bls381::{Scalar255, G1, G2};

use crate::error::{Error, Result};
use crate::params::{Bases, PublicParameters};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Signature {
    pub a: G1,
    pub e: Scalar255,
    pub s: Scalar255,
}

/// `B = G_1 + s H_1 + sum_k m_k H_{k+1}`.
pub fn big_b(
    pp: &PublicParameters,
    bases: &Bases,
    s: &Scalar255,
    message: &[Scalar255],
) -> Result<G1> {
    if message.len() != bases.message.len() {
        return Err(Error::Protocol("message length does not match the base vector"));
    }
    Ok(bases.big_b(pp, s, message))
}

/// `e(A, X + e G_2) = e(B, G_2)`.
pub fn verify(
    pp: &PublicParameters,
    bases: &Bases,
    x_g2: &G2,
    message: &[Scalar255],
    signature: &Signature,
) -> bool {
    if message.len() != bases.message.len() || signature.e.is_zero() {
        return false;
    }
    let b = match big_b(pp, bases, &signature.s, message) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let denominator = x_g2.combine(&pp.g2.scale(&signature.e));
    G1::pairing(&denominator, &signature.a) == G1::pairing(&pp.g2, &b)
}

/// Single-signer signing, for fixtures and cross-checks.
pub fn sign(
    pp: &PublicParameters,
    bases: &Bases,
    secret: &Scalar255,
    message: &[Scalar255],
) -> Result<Signature> {
    let mut rng = rand_core::OsRng;
    let e = Scalar255::random(&mut rng);
    let s = Scalar255::random(&mut rng);
    sign_with(pp, bases, secret, message, &e, &s)
}

/// Signing with prescribed nonces, i.e. the exact signature a threshold run must reconstruct.
pub fn sign_with(
    pp: &PublicParameters,
    bases: &Bases,
    secret: &Scalar255,
    message: &[Scalar255],
    e: &Scalar255,
    s: &Scalar255,
) -> Result<Signature> {
    let b = big_b(pp, bases, s, message)?;
    let denominator = secret
        .add(e)
        .invert()
        .ok_or(Error::Arithmetic("x + e is not invertible"))?;
    Ok(Signature {
        a: b.scale(&denominator),
        e: e.clone(),
        s: s.clone(),
    })
}
