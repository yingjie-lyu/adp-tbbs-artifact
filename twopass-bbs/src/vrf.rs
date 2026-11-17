//! The ECVRF of RFC 9381, over `G_1`.
//!
//! Paper §2.4. Key pair `(vk, sk) = (sk·E, sk)`; on input `alpha` the evaluator hashes to a
//! curve point `H`, sets `Gamma = sk·H`, and proves in zero knowledge that `vk` and `Gamma`
//! share the same discrete logarithm. The output is `beta = Hash(vk, Gamma)`, so it is
//! deterministic in `(vk, alpha)` and unpredictable without `sk` — which is exactly what
//! stops `P_2` from steering `(e, s) = H_2(beta_1 || beta_2)` after seeing `beta_1`.
//!
//! The proof is the 3-move Chaum–Pedersen transcript (`U = k·E`, `V = k·H`, `s = k - c·sk`)
//! compiled with Fiat–Shamir, i.e. the same shape as RFC 9381's `(Gamma, c, s)`.
//!
//! Only `P_2` needs a VRF: `P_1` moves first and cannot react to anything, so its `beta_1` is
//! just a random string in `Y = {0,1}^256`.

use threshold_bbs::algebra::{Encodable, Group, Scalar};
use threshold_bbs::bls381::{hash_to_g1, Scalar255, G1};
use threshold_bbs::hash::Transcript;

use crate::meter::{Meter, Op};
use crate::params::PublicParameters;

pub const DST_HASH_TO_CURVE: &[u8] = b"twopass-bbs/v01/vrf/h2c";
pub const DST_BETA: &[u8] = b"twopass-bbs/v01/vrf/beta";
pub const DOMAIN_PROOF: &[u8] = b"twopass-bbs/v01/vrf/proof";

/// The VRF output space `Y`. With `Y = {0,1}^256` the protocol's "check `beta_1 in Y`" is the
/// length check that the decoder already performs.
pub type VrfOutput = [u8; 32];

#[derive(Clone)]
pub struct VrfKey {
    pub vk: G1,
    sk: Scalar255,
}

impl VrfKey {
    /// `VRF-KeyGen`. The key pair is over `G_1` with the standard generator.
    pub fn generate(pp: &PublicParameters, rng: &mut impl rand_core::RngCore) -> Self {
        let sk = Scalar255::random(rng);
        let vk = pp.g1.scale(&sk);
        Self { vk, sk }
    }

    pub fn secret(&self) -> &Scalar255 {
        &self.sk
    }
}

#[derive(Clone, Debug)]
pub struct VrfProof {
    /// `Gamma = sk · H`.
    pub gamma: G1,
    pub challenge: Scalar255,
    pub response: Scalar255,
}

impl VrfProof {
    pub fn encoded_len(&self) -> usize {
        48 + 16 + 32
    }
}

/// `H_1(m || sid)` in the paper's notation: hash to the VRF input space.
pub fn input(pp: &PublicParameters, message_bytes: &[u8], session: &[u8]) -> [u8; 32] {
    let mut transcript = Transcript::new(b"twopass-bbs/v01/vrf/input");
    pp.absorb(&mut transcript);
    transcript
        .absorb_bytes(b"msg", message_bytes)
        .absorb_bytes(b"sid", session);
    transcript.digest32()
}

fn hash_to_curve(alpha: &[u8]) -> G1 {
    hash_to_g1(DST_HASH_TO_CURVE, alpha)
}

fn beta_of(vk: &G1, gamma: &G1) -> VrfOutput {
    let mut transcript = Transcript::new(DST_BETA);
    transcript
        .absorb_bytes(b"vk", &vk.to_bytes())
        .absorb_bytes(b"gamma", &gamma.to_bytes());
    transcript.digest32()
}

fn challenge(
    pp: &PublicParameters,
    vk: &G1,
    point: &G1,
    gamma: &G1,
    u: &G1,
    v: &G1,
) -> Scalar255 {
    let mut transcript = Transcript::new(DOMAIN_PROOF);
    pp.absorb(&mut transcript);
    transcript
        .absorb_g1(b"vk", vk)
        .absorb_g1(b"H", point)
        .absorb_g1(b"gamma", gamma)
        .absorb_g1(b"U", u)
        .absorb_g1(b"V", v);
    pp.challenge(&transcript)
}

/// `VRF-Eval(sk, alpha) -> (beta, pi)`.
pub fn eval(
    pp: &PublicParameters,
    key: &VrfKey,
    alpha: &[u8],
    rng: &mut impl rand_core::RngCore,
    meter: &mut Meter,
) -> (VrfOutput, VrfProof) {
    let point = hash_to_curve(alpha);
    meter.add(Op::G1Exp);
    let gamma = point.scale(&key.sk);

    let nonce = Scalar255::random(rng);
    meter.add_n(Op::G1Exp, 2);
    let u = pp.g1.scale(&nonce);
    let v = point.scale(&nonce);

    let challenge = challenge(pp, &key.vk, &point, &gamma, &u, &v);
    let response = nonce.sub(&challenge.mul(&key.sk));

    meter.add(Op::Prove);
    (beta_of(&key.vk, &gamma), VrfProof {
        gamma,
        challenge,
        response,
    })
}

/// `VRF-Verify(vk, alpha, pi) -> beta` or `None`.
pub fn verify(
    pp: &PublicParameters,
    vk: &G1,
    alpha: &[u8],
    proof: &VrfProof,
    meter: &mut Meter,
) -> Option<VrfOutput> {
    let point = hash_to_curve(alpha);

    // U = s E + c vk,  V = s H + c Gamma
    meter.add_n(Op::G1Exp, 4);
    let u = pp
        .g1
        .scale(&proof.response)
        .combine(&vk.scale(&proof.challenge));
    let v = point
        .scale(&proof.response)
        .combine(&proof.gamma.scale(&proof.challenge));

    meter.add(Op::Verify);
    if challenge(pp, vk, &point, &proof.gamma, &u, &v) != proof.challenge {
        return None;
    }
    Some(beta_of(vk, &proof.gamma))
}
