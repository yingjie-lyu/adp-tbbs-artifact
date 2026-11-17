//! BBS+ verification and the BBS+ bases.
//!
//! The paper derives the `ell + 1` bases deterministically from `X`, so every signer computes
//! the same vector without extra communication.

use std::sync::Arc;

use tcl::cl::ClParameters;

use threshold_bbs::algebra::{Group, PairingGroup, Scalar};
use threshold_bbs::bls381::{hash_to_g1, Scalar255, G1, G2};

use tcl::Error;
use threshold_bbs::hash::Transcript;

pub const DST_BASE: &[u8] = b"robot-bbs/v01/setup/H";
pub const DST_VRF: &[u8] = b"robot-bbs/v01/vrf/Y";
pub const DST_NONCE: &[u8] = b"robot-bbs/v01/nonce";

pub struct PublicParameters {
    pub cl: Arc<ClParameters>,
    pub message_len: usize,
}

impl PublicParameters {
    pub fn new(cl: Arc<ClParameters>, message_len: usize) -> Arc<Self> {
        Arc::new(Self { cl, message_len })
    }
}

/// `H = (H_0, ..., H_ell)`, derived from `X` by hash-to-curve.
#[derive(Clone, Debug)]
pub struct Bases {
    pub h: Vec<G1>,
}

impl Bases {
    pub fn derive(x_g2: &G2, message_len: usize) -> Self {
        use threshold_bbs::algebra::Encodable;
        let seed = x_g2.to_bytes();
        let h = (0..=message_len)
            .map(|index| {
                let mut buffer = seed.clone();
                buffer.extend_from_slice(&(index as u64).to_be_bytes());
                hash_to_g1(DST_BASE, &buffer)
            })
            .collect();
        Self { h }
    }

    pub fn encoded_len(&self) -> usize {
        self.h.len() * 48
    }
}

/// `D = G_1 + sum_k m_k H_k`, the message part of the BBS+ base.
pub fn message_part(
    bases: &Bases,
    x_g2: &G2,
    message: &[Scalar255],
) -> Result<G1, Error> {
    if message.len() + 1 != bases.h.len() {
        return Err(Error::Protocol("message length does not match the bases"));
    }
    let mut value = threshold_bbs::bls381::generator_g1();
    for (base, scalar) in bases.h[1..].iter().zip(message) {
        value = value.combine(&base.scale(scalar));
    }
    let _ = x_g2;
    Ok(value)
}

/// `B = G_1 + s H_0 + sum_k m_k H_k`.
pub fn big_b(bases: &Bases, s: &Scalar255, message: &[Scalar255]) -> Result<G1, Error> {
    if message.len() + 1 != bases.h.len() {
        return Err(Error::Protocol("message length does not match the bases"));
    }
    let mut value = threshold_bbs::bls381::generator_g1().combine(&bases.h[0].scale(s));
    for (base, scalar) in bases.h[1..].iter().zip(message) {
        value = value.combine(&base.scale(scalar));
    }
    Ok(value)
}

/// `Y = H_0(m, sid)`: the threshold-VRF input.
pub fn vrf_input(message_bytes: &[u8], session: &[u8]) -> G1 {
    let mut transcript = Transcript::new(DST_VRF);
    transcript
        .absorb_bytes(b"msg", message_bytes)
        .absorb_bytes(b"sid", session);
    hash_to_g1(DST_VRF, &transcript.digest32())
}

/// `e = H_1(Z, 0)`, `s = H_1(Z, 1)`.
pub fn nonces(z: &G1) -> (Scalar255, Scalar255) {
    use threshold_bbs::algebra::Encodable;
    let point = z.to_bytes();
    let mut first = Transcript::new(DST_NONCE);
    first.absorb_bytes(b"Z", &point).absorb_u64(b"tag", 0);
    let mut second = Transcript::new(DST_NONCE);
    second.absorb_bytes(b"Z", &point).absorb_u64(b"tag", 1);
    let e = Scalar255::from_be_bytes_mod_order(&first.digest()[..32]);
    let s = Scalar255::from_be_bytes_mod_order(&second.digest()[..32]);
    (e, s)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Signature {
    pub a: G1,
    pub e: Scalar255,
    pub s: Scalar255,
}

/// `e(A, X + e G_2) = e(G_1 + s H_0 + sum m_k H_k, G_2)`.
pub fn verify(
    bases: &Bases,
    x_g2: &G2,
    message: &[Scalar255],
    signature: &Signature,
) -> bool {
    if signature.e.is_zero() {
        return false;
    }
    let b = match big_b(bases, &signature.s, message) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let g2 = threshold_bbs::bls381::generator_g2();
    let denominator = x_g2.combine(&g2.scale(&signature.e));
    G1::pairing(&denominator, &signature.a) == G1::pairing(&g2, &b)
}

/// `encode_message` for the VRF input and transcripts.
pub fn encode_message(message: &[Scalar255]) -> Vec<u8> {
    let mut out = Vec::with_capacity(message.len() * 32);
    for value in message {
        out.extend_from_slice(&value.to_be_bytes());
    }
    out
}
