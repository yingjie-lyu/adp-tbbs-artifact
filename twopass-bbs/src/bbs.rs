//! The BBS+ signature object produced by the two-party protocol, and its verification.

use threshold_bbs::algebra::{Group, PairingGroup, Scalar};
use threshold_bbs::bls381::{Scalar255, G1, G2};

use crate::error::{Error, Result};
use crate::params::PublicParameters;
use crate::wire::{self, Reader};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Signature {
    pub a: G1,
    pub e: Scalar255,
    pub s: Scalar255,
}

impl Signature {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        wire::put_g1(&mut out, &self.a);
        wire::put_scalar(&mut out, &self.e);
        wire::put_scalar(&mut out, &self.s);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        let signature = Self {
            a: reader.g1()?,
            e: reader.scalar()?,
            s: reader.scalar()?,
        };
        reader.finish()?;
        Ok(signature)
    }

    pub fn encoded_len(&self) -> usize {
        48 + 32 + 32
    }
}

/// `e(A, X + e G_2) = e(B, G_2)` with `B = G_1 + s H_0 + sum_i m_i H_i`.
pub fn verify(
    pp: &PublicParameters,
    x_g2: &G2,
    message: &[Scalar255],
    signature: &Signature,
) -> bool {
    if message.len() != pp.config.message_len || signature.e.is_zero() {
        return false;
    }
    let b = match pp.big_b(&signature.s, message) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let denominator = x_g2.combine(&pp.g2.scale(&signature.e));
    G1::pairing(&denominator, &signature.a) == G1::pairing(&pp.g2, &b)
}

/// Single-key signing, for fixtures and cross-checks. The two-party protocol must produce a
/// signature that verifies under exactly this routine.
pub fn sign_with(
    pp: &PublicParameters,
    secret: &Scalar255,
    message: &[Scalar255],
    e: &Scalar255,
    s: &Scalar255,
) -> Result<Signature> {
    let b = pp.big_b(s, message)?;
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
