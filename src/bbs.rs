//! BBS+ signatures: the object the threshold protocol produces.
//!
//! `A = (g_1 h_0^phi prod_k h_k^{m_k})^{1/(x+e)}` with verification
//! `e(g_2^{x+e}, A) = e(g_2, U)`. The threshold protocol never learns `x`; it assembles
//! `A = S^{1/u}` from shares, and this module is what the final pair check runs through.

use crate::algebra::{Group, PairingGroup, Scalar};
use crate::bls381::{Scalar255, G1, G2};
use crate::params::PublicParameters;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Signature<G: PairingGroup> {
    pub a: G,
    pub e: G::Scalar,
    pub phi: G::Scalar,
}

/// Generic verification against explicit bases.
pub fn verify<G: PairingGroup>(
    g1: &G,
    g2: &G::G2,
    h0: &G,
    message_bases: &[G],
    messages: &[G::Scalar],
    public_key: &G::G2,
    signature: &Signature<G>,
) -> bool {
    if message_bases.len() != messages.len() || signature.e == G::Scalar::zero() {
        return false;
    }
    let mut u = g1.combine(&h0.scale(&signature.phi));
    for (base, message) in message_bases.iter().zip(messages) {
        u = u.combine(&base.scale(message));
    }
    let denominator = public_key.combine(&g2.scale(&signature.e));
    G::pairing(&denominator, &signature.a) == G::pairing(g2, &u)
}

/// Verification against this crate's public parameters.
pub fn verify_with(
    pp: &PublicParameters,
    public_key: &G2,
    messages: &[Scalar255],
    signature: &Signature<G1>,
) -> bool {
    if messages.len() != pp.message_bases.len() {
        return false;
    }
    verify(
        &pp.g1,
        &pp.g2,
        &pp.h0,
        &pp.message_bases,
        messages,
        public_key,
        signature,
    )
}

/// Single-signer reference implementation: `e, phi` random, `A = U^{1/(x+e)}`.
///
/// The threshold protocol instead fixes `(e, phi)` to `hashout(...)` so that the pairing
/// check is deterministic; this function exists for comparison tests and fixtures.
pub fn sign(
    pp: &PublicParameters,
    secret: &Scalar255,
    messages: &[Scalar255],
) -> Option<Signature<G1>> {
    if messages.len() != pp.message_bases.len() {
        return None;
    }
    let mut rng = rand_core::OsRng;
    let e = Scalar255::random(&mut rng);
    let phi = Scalar255::random(&mut rng);
    let u = pp.compute_u(&phi, messages);
    let denominator = secret.add(&e).invert()?;
    Some(Signature {
        a: u.scale(&denominator),
        e,
        phi,
    })
}

/// Sign with prescribed scalars `(e, phi)`, i.e. the exact signature the threshold run must
/// reconstruct for a given session.
pub fn sign_with(
    pp: &PublicParameters,
    secret: &Scalar255,
    messages: &[Scalar255],
    e: &Scalar255,
    phi: &Scalar255,
) -> Option<Signature<G1>> {
    if messages.len() != pp.message_bases.len() || e.is_zero() {
        return None;
    }
    let u = pp.compute_u(phi, messages);
    let denominator = secret.add(e).invert()?;
    Some(Signature {
        a: u.scale(&denominator),
        e: e.clone(),
        phi: phi.clone(),
    })
}
