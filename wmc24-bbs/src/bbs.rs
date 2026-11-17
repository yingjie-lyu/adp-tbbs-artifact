//! BBS+ verification and the public parameters.
//!
//! `pp = (G_1, G_2, g_1, g_2, q, e, h_0, ..., h_ell)`; the bases are hash-derived from fixed
//! tags here, where the paper has them distributively sampled.

use std::sync::Arc;

use tcl::cl::ClParameters;

use threshold_bbs::algebra::{Group, PairingGroup, Scalar};
use threshold_bbs::bls381::{hash_to_g1, Scalar255, G1, G2};

use tcl::Error;

pub const DST_BASE: &[u8] = b"wmc24-bbs/v01/setup/h";

pub struct PublicParameters {
    pub cl: Arc<ClParameters>,
    pub message_len: usize,
    /// `h_0 .. h_ell`; `h_0` is the base of `s`.
    pub bases: Vec<G1>,
}

impl PublicParameters {
    pub fn new(cl: Arc<ClParameters>, message_len: usize) -> Arc<Self> {
        let bases = (0..=message_len)
            .map(|index| hash_to_g1(DST_BASE, &(index as u64).to_be_bytes()))
            .collect();
        Arc::new(Self {
            cl,
            message_len,
            bases,
        })
    }

    /// `D = g_1 h_0^s prod_k h_k^{m_k}`.
    pub fn big_d(&self, s: &Scalar255, message: &[Scalar255]) -> Result<G1, Error> {
        big_b(&self.bases, s, message)
    }
}

/// `g_1 * h_0^s * prod_k h_k^{m_k}` with an explicit base vector.
pub fn big_b(bases: &[G1], s: &Scalar255, message: &[Scalar255]) -> Result<G1, Error> {
    if message.len() + 1 != bases.len() {
        return Err(Error::Protocol("message length does not match the bases"));
    }
    let mut value = threshold_bbs::bls381::generator_g1().combine(&bases[0].scale(s));
    for (base, scalar) in bases[1..].iter().zip(message) {
        value = value.combine(&base.scale(scalar));
    }
    Ok(value)
}

/// `e(A, X g_2^e) = e(g_1 h_0^s prod h_k^{m_k}, g_2)`.
pub fn verify(
    bases: &[G1],
    x_g2: &G2,
    message: &[Scalar255],
    signature: &Signature,
) -> bool {
    if signature.e.is_zero() {
        return false;
    }
    let d = match big_b(bases, &signature.s, message) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let g2 = threshold_bbs::bls381::generator_g2();
    let denominator = x_g2.combine(&g2.scale(&signature.e));
    G1::pairing(&denominator, &signature.a) == G1::pairing(&g2, &d)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Signature {
    pub a: G1,
    pub e: Scalar255,
    pub s: Scalar255,
}

pub fn encode_message(message: &[Scalar255]) -> Vec<u8> {
    let mut out = Vec::with_capacity(message.len() * 32);
    for value in message {
        out.extend_from_slice(&value.to_be_bytes());
    }
    out
}
