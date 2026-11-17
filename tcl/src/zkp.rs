//! The Σ-protocols the two threshold BBS+ signing protocols need.
//!
//! | proof | statement | witness | used by |
//! |---|---|---|---|
//! | [`prove_ddh`] | `X̂_i = x̂_i B`, `Z_i = x̂_i Y` | `x̂_i` | ROBOT's `pi_ddh`, ElGamal partial decryptions |
//! | [`prove_enc`] | `C = CL.Enc(ek, m; rho)`, optionally `X = m G_2` | `(m, rho)` | `C_x`, and WMC24's `e_i`, `s_i` |
//! | [`prove_part_dec`] | `pk_i = A^{k_i}`, `pd = B^{k_i}` | `k_i` | t-CL partial decryption (WMC24 `R_PartDec`, ROBOT `R_clddh`) |
//! | [`prove_el_cl`] | ElGamal ciphertext of `gamma D` + CL scaling of a ciphertext by `gamma` | `(gamma, r)` | WMC24 `R_El-CL` |
//! | [`prove_con`] | `gamma` in two CL ciphertexts and two ElGamal ciphertexts | `(gamma, rho, r_0, r_1)` | ROBOT `R_con` |
//!
//! # The cross-group trick
//!
//! `R_El-CL` and `R_con` have to show that one `gamma in Z_q` appears both as a CL exponent
//! (unknown-order group) and as an ElGamal exponent (prime-order `G_1`). The two papers do it
//! the same way: **one response, many groups**. The prover masks `gamma` once with an integer
//! nonce `a_gamma`, uses `a_gamma` in every group's commitments, and answers with a single
//! integer `z_gamma = a_gamma + ch * gamma`. Every verification equation then checks the same
//! `z_gamma`, so two accepting transcripts with different challenges extract *one* `gamma` that
//! satisfies all the equations at once — which is exactly what a conjunction needs. Keeping
//! separate responses per group would be unsound: a cheating prover could open different
//! witnesses in each group.
//!
//! All proofs are Fiat–Shamir over a 128-bit challenge and carry no first message: the verifier
//! recomputes every commitment from the responses and re-derives the challenge.

use bicycl::{Mpz, QFI, RandGen};

use threshold_bbs::algebra::{Encodable, Group, Scalar};
use threshold_bbs::bls381::{Scalar255, G1, G2};
use threshold_bbs::hash::Transcript;
use threshold_bbs::util::{mpz_to_scalar, pow2, scalar_to_mpz};

use crate::cl::{Cipher, ClParameters, ThresholdCl};
use crate::eg::EgCipher;
use crate::error::Result;
use crate::meter::{Meter, Op};
use crate::util::{lt, mul, neg};
use crate::wire::{self, Reader};

pub const DOMAIN_DDH: &[u8] = b"tcl/v01/zkp/ddh";
pub const DOMAIN_ENC: &[u8] = b"tcl/v01/zkp/enc";
pub const DOMAIN_PART_DEC: &[u8] = b"tcl/v01/zkp/part-dec";
pub const DOMAIN_EL_CL: &[u8] = b"tcl/v01/zkp/el-cl";
pub const DOMAIN_CON: &[u8] = b"tcl/v01/zkp/con";

pub const CHALLENGE_BITS: usize = 128;

/// `ctx = sid || tag || ids`.
pub fn context(session: &[u8], tag: &[u8], ids: &[usize]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(session.len() + tag.len() + 8 * ids.len());
    bytes.extend_from_slice(&(session.len() as u32).to_be_bytes());
    bytes.extend_from_slice(session);
    bytes.extend_from_slice(&(tag.len() as u32).to_be_bytes());
    bytes.extend_from_slice(tag);
    for id in ids {
        bytes.extend_from_slice(&(*id as u64).to_be_bytes());
    }
    bytes
}

fn transcript(domain: &[u8], ctx: &[u8]) -> Transcript {
    let mut transcript = Transcript::new(domain);
    transcript.absorb_bytes(b"ctx", ctx);
    transcript
}

fn challenge(transcript: &Transcript) -> Scalar255 {
    let digest = transcript.digest32();
    Scalar255::from_be_bytes_mod_order(&digest[..CHALLENGE_BITS / 8])
}

fn neg_scalar(value: &Scalar255) -> Scalar255 {
    <Scalar255 as Scalar>::zero().sub(value)
}

/// `2^{lambda+lambda_d} * bound`: the masking interval.
fn mask_bound_of(cl: &ClParameters, bound: &Mpz) -> Mpz {
    pow2(cl.lambda() + cl.lambda_d()) * bound.clone()
}

/// `(2^{lambda+lambda_d} + 2^{lambda}) * bound`: the honest response bound.
fn response_bound_of(cl: &ClParameters, bound: &Mpz) -> Mpz {
    (pow2(cl.lambda() + cl.lambda_d()) + pow2(cl.lambda())) * bound.clone()
}

fn mask_bound(tc: &ThresholdCl, bound: &Mpz) -> Mpz {
    mask_bound_of(&tc.cl, bound)
}

fn response_bound(tc: &ThresholdCl, bound: &Mpz) -> Mpz {
    response_bound_of(&tc.cl, bound)
}

fn bound_q(tc: &ThresholdCl) -> Mpz {
    tc.cl.modulus().clone()
}

fn bound_dq(tc: &ThresholdCl) -> Mpz {
    tc.cl.bound_dq().clone()
}

// ---------------------------------------------------------------------------------------
// R_ddh
// ---------------------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct DdhProof {
    pub challenge: Scalar255,
    pub response: Scalar255,
}

impl DdhProof {
    pub fn encode(&self, out: &mut Vec<u8>) {
        wire::put_challenge(out, &self.challenge);
        wire::put_scalar(out, &self.response);
    }

    pub fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            challenge: reader.challenge()?,
            response: reader.scalar()?,
        })
    }

    pub fn encoded_len(&self) -> usize {
        48
    }
}

/// `R_ddh`: `X̂_i = w B` and `Z = w Y`.
pub fn prove_ddh<G: Group<Scalar = Scalar255> + Encodable>(
    ctx: &[u8],
    base: &G,
    public_share: &G,
    y: &G,
    z: &G,
    witness: &Scalar255,
    rng: &mut impl rand_core::RngCore,
    meter: &mut Meter,
) -> DdhProof {
    let nonce = Scalar255::random(rng);
    meter.add_n(Op::G1Exp, 2);
    let u = base.scale(&nonce);
    let v = y.scale(&nonce);

    let mut transcript = transcript(DOMAIN_DDH, ctx);
    transcript
        .absorb_bytes(b"B", &base.to_bytes())
        .absorb_bytes(b"X", &public_share.to_bytes())
        .absorb_bytes(b"Y", &y.to_bytes())
        .absorb_bytes(b"Z", &z.to_bytes())
        .absorb_bytes(b"U", &u.to_bytes())
        .absorb_bytes(b"V", &v.to_bytes());
    let challenge = challenge(&transcript);

    meter.add(Op::Prove);
    DdhProof {
        response: nonce.add(&challenge.mul(witness)),
        challenge,
    }
}

pub fn verify_ddh<G: Group<Scalar = Scalar255> + Encodable>(
    ctx: &[u8],
    base: &G,
    public_share: &G,
    y: &G,
    z: &G,
    proof: &DdhProof,
    meter: &mut Meter,
) -> bool {
    meter.add_n(Op::G1Exp, 2);
    let u = base
        .scale(&proof.response)
        .combine(&public_share.scale(&neg_scalar(&proof.challenge)));
    let v = y
        .scale(&proof.response)
        .combine(&z.scale(&neg_scalar(&proof.challenge)));

    let mut transcript = transcript(DOMAIN_DDH, ctx);
    transcript
        .absorb_bytes(b"B", &base.to_bytes())
        .absorb_bytes(b"X", &public_share.to_bytes())
        .absorb_bytes(b"Y", &y.to_bytes())
        .absorb_bytes(b"Z", &z.to_bytes())
        .absorb_bytes(b"U", &u.to_bytes())
        .absorb_bytes(b"V", &v.to_bytes());
    meter.add(Op::Verify);
    challenge(&transcript) == proof.challenge
}

// ---------------------------------------------------------------------------------------
// R_enc: CL plaintext consistency
// ---------------------------------------------------------------------------------------

pub struct EncStatement<'a> {
    pub ek: &'a QFI,
    pub cipher: &'a Cipher,
    /// When present, the same `m` must also satisfy `X = m G_2`.
    pub point: Option<&'a G2>,
}

#[derive(Clone, Debug)]
pub struct EncProof {
    pub challenge: Scalar255,
    pub response_m: Scalar255,
    pub response_rho: Mpz,
}

impl EncProof {
    pub fn encode(&self, out: &mut Vec<u8>) {
        wire::put_challenge(out, &self.challenge);
        wire::put_scalar(out, &self.response_m);
        wire::put_mpz(out, &self.response_rho);
    }

    pub fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            challenge: reader.challenge()?,
            response_m: reader.scalar()?,
            response_rho: reader.mpz()?,
        })
    }

    pub fn encoded_len(&self) -> usize {
        16 + 32 + 3 + wire::mpz_len(&self.response_rho)
    }
}

fn enc_challenge(
    ctx: &[u8],
    base_c0: &QFI,
    statement: &EncStatement<'_>,
    t0: &QFI,
    t1: &QFI,
    point: Option<&G2>,
) -> Scalar255 {
    let mut transcript = transcript(DOMAIN_ENC, ctx);
    transcript
        .absorb_qfi(b"base", base_c0)
        .absorb_qfi(b"ek", statement.ek)
        .absorb_qfi(b"c0", &statement.cipher.c0)
        .absorb_qfi(b"c1", &statement.cipher.c1)
        .absorb_qfi(b"T0", t0)
        .absorb_qfi(b"T1", t1);
    if let (Some(statement_point), Some(point)) = (statement.point, point) {
        transcript
            .absorb_bytes(b"X", &statement_point.to_bytes())
            .absorb_bytes(b"T", &point.to_bytes());
    }
    challenge(&transcript)
}

pub fn prove_enc_with_base(
    cl: &ClParameters,
    ctx: &[u8],
    base_c0: &QFI,
    statement: &EncStatement<'_>,
    message: &Scalar255,
    rho: &Mpz,
    rng: &mut RandGen,
    meter: &mut Meter,
) -> EncProof {
    let nonce_m = Scalar255::random(&mut rand_core::OsRng);
    let nonce_rho = rng.random_mpz(&mask_bound_of(cl, cl.bound_dq()));

    let t0 = cl.exp(base_c0, &nonce_rho, meter);
    let mask = cl.exp(statement.ek, &nonce_rho, meter);
    let t1 = cl.compose(&mask, &cl.f_exp(&nonce_m), meter);
    let commitment_point = if statement.point.is_some() {
        Some(point_g2(&nonce_m, meter))
    } else {
        None
    };
    let challenge = enc_challenge(ctx, base_c0, statement, &t0, &t1, commitment_point.as_ref());

    meter.add(Op::Prove);
    EncProof {
        response_m: nonce_m.add(&challenge.mul(message)),
        response_rho: nonce_rho + scalar_to_mpz(&challenge) * rho.clone(),
        challenge,
    }
}

pub fn verify_enc_with_base(
    cl: &ClParameters,
    ctx: &[u8],
    base_c0: &QFI,
    statement: &EncStatement<'_>,
    proof: &EncProof,
    meter: &mut Meter,
) -> bool {
    if !cl.is_form(statement.ek)
        || !cl.is_form(&statement.cipher.c0)
        || !cl.is_form(&statement.cipher.c1)
    {
        return false;
    }
    if !lt(&proof.response_rho, &response_bound_of(cl, cl.bound_dq())) {
        return false;
    }

    let negative = neg(&scalar_to_mpz(&proof.challenge));
    let t0 = cl.compose(
        &cl.exp(base_c0, &proof.response_rho, meter),
        &cl.exp(&statement.cipher.c0, &negative, meter),
        meter,
    );
    let mask = cl.exp(statement.ek, &proof.response_rho, meter);
    let t1 = cl.compose(
        &cl.compose(&mask, &cl.f_exp(&proof.response_m), meter),
        &cl.exp(&statement.cipher.c1, &negative, meter),
        meter,
    );
    let commitment_point = statement.point.map(|point| {
        meter.add(Op::G2Exp);
        let forward = point_g2(&proof.response_m, meter);
        forward.combine(&point.scale(&neg_scalar(&proof.challenge)))
    });

    meter.add(Op::Verify);
    enc_challenge(ctx, base_c0, statement, &t0, &t1, commitment_point.as_ref()) == proof.challenge
}

/// `R_enc` on the `g_q^{Delta^2}` base (the threshold ciphertext shape).
pub fn prove_enc(
    tc: &ThresholdCl,
    ctx: &[u8],
    statement: &EncStatement<'_>,
    message: &Scalar255,
    rho: &Mpz,
    rng: &mut RandGen,
    meter: &mut Meter,
) -> EncProof {
    prove_enc_with_base(&tc.cl, ctx, &tc.gq_delta2, statement, message, rho, rng, meter)
}

pub fn verify_enc(
    tc: &ThresholdCl,
    ctx: &[u8],
    statement: &EncStatement<'_>,
    proof: &EncProof,
    meter: &mut Meter,
) -> bool {
    verify_enc_with_base(&tc.cl, ctx, &tc.gq_delta2, statement, proof, meter)
}

// ---------------------------------------------------------------------------------------
// R_part_dec: t-CL partial decryption (`pk_i = A^{k_i}`, `pd = B^{k_i}`)
// ---------------------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct PartDecProof {
    pub challenge: Scalar255,
    pub response: Mpz,
}

impl PartDecProof {
    pub fn encode(&self, out: &mut Vec<u8>) {
        wire::put_challenge(out, &self.challenge);
        wire::put_mpz(out, &self.response);
    }

    pub fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            challenge: reader.challenge()?,
            response: reader.mpz()?,
        })
    }

    pub fn encoded_len(&self) -> usize {
        16 + 3 + wire::mpz_len(&self.response)
    }
}

fn part_dec_challenge(ctx: &[u8], pk_i: &QFI, c0: &QFI, pd: &QFI, re: &QFI, theta: &QFI) -> Scalar255 {
    let mut transcript = transcript(DOMAIN_PART_DEC, ctx);
    transcript
        .absorb_qfi(b"pk", pk_i)
        .absorb_qfi(b"c0", c0)
        .absorb_qfi(b"pd", pd)
        .absorb_qfi(b"Re", re)
        .absorb_qfi(b"Theta", theta);
    challenge(&transcript)
}

/// `R_PartDec` for WMC24, `R_clddh` for ROBOT: the same relation on different bases.
///
/// `pk_i = (g_q^Delta)^{k_i}` and `pd = (c_0^Delta)^{k_i}` — both with the *same* exponent
/// `k_i`, which is what lets one response cover both equations.
pub fn prove_part_dec(
    tc: &ThresholdCl,
    ctx: &[u8],
    pk_i: &QFI,
    c0: &QFI,
    pd: &QFI,
    share: &Mpz,
    rng: &mut RandGen,
    meter: &mut Meter,
) -> PartDecProof {
    let cl = &tc.cl;
    let nonce = rng.random_mpz(&mask_bound(tc, &tc.share_bound));
    let re = cl.exp(&tc.gq_delta, &nonce, meter);
    let base_msg = cl.exp(c0, &tc.delta, meter);
    let theta = cl.exp(&base_msg, &nonce, meter);

    let challenge = part_dec_challenge(ctx, pk_i, c0, pd, &re, &theta);
    meter.add(Op::Prove);
    PartDecProof {
        response: nonce + scalar_to_mpz(&challenge) * share.clone(),
        challenge,
    }
}

pub fn verify_part_dec(
    tc: &ThresholdCl,
    ctx: &[u8],
    pk_i: &QFI,
    c0: &QFI,
    pd: &QFI,
    proof: &PartDecProof,
    meter: &mut Meter,
) -> bool {
    let cl = &tc.cl;
    if !cl.is_form(pk_i) || !cl.is_form(c0) || !cl.is_form(pd) {
        return false;
    }
    if !lt(&proof.response, &response_bound(tc, &tc.share_bound)) {
        return false;
    }
    let negative = neg(&scalar_to_mpz(&proof.challenge));
    let re = cl.compose(
        &cl.exp(&tc.gq_delta, &proof.response, meter),
        &cl.exp(pk_i, &negative, meter),
        meter,
    );
    let base_msg = cl.exp(c0, &tc.delta, meter);
    let theta = cl.compose(
        &cl.exp(&base_msg, &proof.response, meter),
        &cl.exp(pd, &negative, meter),
        meter,
    );
    meter.add(Op::Verify);
    part_dec_challenge(ctx, pk_i, c0, pd, &re, &theta) == proof.challenge
}

// ---------------------------------------------------------------------------------------
// R_el_cl (WMC24): ElGamal ciphertext of gamma*D and a CL scaling by the same gamma
// ---------------------------------------------------------------------------------------

pub struct ElClStatement<'a> {
    pub elek: &'a G1,
    pub d: &'a G1,
    pub eg: &'a EgCipher,
    pub c_k: &'a Cipher,
    pub c_gk: &'a Cipher,
}

#[derive(Clone, Debug)]
pub struct ElClProof {
    pub challenge: Scalar255,
    pub response_gamma: Mpz,
    pub response_r: Mpz,
}

impl ElClProof {
    pub fn encode(&self, out: &mut Vec<u8>) {
        wire::put_challenge(out, &self.challenge);
        wire::put_mpz(out, &self.response_gamma);
        wire::put_mpz(out, &self.response_r);
    }

    pub fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            challenge: reader.challenge()?,
            response_gamma: reader.mpz()?,
            response_r: reader.mpz()?,
        })
    }

    pub fn encoded_len(&self) -> usize {
        16 + 3 + wire::mpz_len(&self.response_gamma) + 3 + wire::mpz_len(&self.response_r)
    }
}

fn el_cl_challenge(
    ctx: &[u8],
    statement: &ElClStatement<'_>,
    t0: &G1,
    t1: &G1,
    u0: &QFI,
    u1: &QFI,
) -> Scalar255 {
    let mut transcript = transcript(DOMAIN_EL_CL, ctx);
    transcript
        .absorb_bytes(b"elek", &statement.elek.to_bytes())
        .absorb_bytes(b"D", &statement.d.to_bytes())
        .absorb_bytes(b"A1", &statement.eg.a1.to_bytes())
        .absorb_bytes(b"A2", &statement.eg.a2.to_bytes())
        .absorb_qfi(b"ck0", &statement.c_k.c0)
        .absorb_qfi(b"ck1", &statement.c_k.c1)
        .absorb_qfi(b"cg0", &statement.c_gk.c0)
        .absorb_qfi(b"cg1", &statement.c_gk.c1)
        .absorb_bytes(b"T0", &t0.to_bytes())
        .absorb_bytes(b"T1", &t1.to_bytes())
        .absorb_qfi(b"U0", u0)
        .absorb_qfi(b"U1", u1);
    challenge(&transcript)
}

pub fn prove_el_cl(
    tc: &ThresholdCl,
    ctx: &[u8],
    statement: &ElClStatement<'_>,
    gamma: &Scalar255,
    eg_randomness: &Scalar255,
    rng: &mut RandGen,
    meter: &mut Meter,
) -> ElClProof {
    let cl = &tc.cl;
    let gamma_int = scalar_to_mpz(gamma);
    let nonce_gamma = rng.random_mpz(&mask_bound(tc, &bound_q(tc)));
    let nonce_r = rng.random_mpz(&mask_bound(tc, &bound_q(tc)));

    let n_gamma = mpz_to_scalar(&nonce_gamma);
    let n_r = mpz_to_scalar(&nonce_r);

    meter.add_n(Op::G1Exp, 2);
    let t0 = threshold_bbs::bls381::generator_g1().scale(&n_r);
    let t1 = statement
        .d
        .scale(&n_gamma)
        .combine(&statement.elek.scale(&n_r));
    let u0 = cl.exp(&statement.c_k.c0, &nonce_gamma, meter);
    let u1 = cl.exp(&statement.c_k.c1, &nonce_gamma, meter);

    let challenge = el_cl_challenge(ctx, statement, &t0, &t1, &u0, &u1);
    let challenge_int = scalar_to_mpz(&challenge);

    meter.add(Op::Prove);
    ElClProof {
        response_gamma: nonce_gamma + challenge_int.clone() * gamma_int,
        response_r: nonce_r + challenge_int * scalar_to_mpz(eg_randomness),
        challenge,
    }
}

pub fn verify_el_cl(
    tc: &ThresholdCl,
    ctx: &[u8],
    statement: &ElClStatement<'_>,
    proof: &ElClProof,
    meter: &mut Meter,
) -> bool {
    let cl = &tc.cl;
    if !cl.is_form(&statement.c_k.c0)
        || !cl.is_form(&statement.c_k.c1)
        || !cl.is_form(&statement.c_gk.c0)
        || !cl.is_form(&statement.c_gk.c1)
    {
        return false;
    }
    if !lt(&proof.response_gamma, &response_bound(tc, &bound_q(tc)))
        || !lt(&proof.response_r, &response_bound(tc, &bound_q(tc)))
    {
        return false;
    }

    let z_gamma = mpz_to_scalar(&proof.response_gamma);
    let z_r = mpz_to_scalar(&proof.response_r);
    // The correction on `c_gk = c_k^gamma` is by the *challenge*, not by the response.
    let neg_challenge = neg(&scalar_to_mpz(&proof.challenge));

    meter.add_n(Op::G1Exp, 4);
    let t0 = threshold_bbs::bls381::generator_g1()
        .scale(&z_r)
        .combine(&statement.eg.a1.scale(&neg_scalar(&proof.challenge)));
    let t1 = statement
        .d
        .scale(&z_gamma)
        .combine(&statement.elek.scale(&z_r))
        .combine(&statement.eg.a2.scale(&neg_scalar(&proof.challenge)));
    let u0 = cl.compose(
        &cl.exp(&statement.c_k.c0, &proof.response_gamma, meter),
        &cl.exp(&statement.c_gk.c0, &neg_challenge, meter),
        meter,
    );
    let u1 = cl.compose(
        &cl.exp(&statement.c_k.c1, &proof.response_gamma, meter),
        &cl.exp(&statement.c_gk.c1, &neg_challenge, meter),
        meter,
    );

    meter.add(Op::Verify);
    el_cl_challenge(ctx, statement, &t0, &t1, &u0, &u1) == proof.challenge
}

// ---------------------------------------------------------------------------------------
// R_con (ROBOT)
// ---------------------------------------------------------------------------------------

pub struct ConStatement<'a> {
    /// `pk_cl`: the threshold CL public key.
    pub ek: &'a QFI,
    /// `C_x`: the CL encryption of the BBS+ key.
    pub c_x: &'a Cipher,
    /// `C_{gamma_i}`.
    pub c_gamma: &'a Cipher,
    /// `C_{gamma_i x} = gamma_i * C_x`.
    pub c_gamma_x: &'a Cipher,
    /// The ElGamal public key `X̂`.
    pub eg_public: &'a G1,
    pub h0: &'a G1,
    pub d: &'a G1,
    pub c_d0: &'a EgCipher,
    pub c_d1: &'a EgCipher,
}

#[derive(Clone, Debug)]
pub struct ConProof {
    pub challenge: Scalar255,
    pub response_gamma: Mpz,
    pub response_rho: Mpz,
    pub response_r0: Mpz,
    pub response_r1: Mpz,
}

impl ConProof {
    pub fn encode(&self, out: &mut Vec<u8>) {
        wire::put_challenge(out, &self.challenge);
        wire::put_mpz(out, &self.response_gamma);
        wire::put_mpz(out, &self.response_rho);
        wire::put_mpz(out, &self.response_r0);
        wire::put_mpz(out, &self.response_r1);
    }

    pub fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            challenge: reader.challenge()?,
            response_gamma: reader.mpz()?,
            response_rho: reader.mpz()?,
            response_r0: reader.mpz()?,
            response_r1: reader.mpz()?,
        })
    }

    pub fn encoded_len(&self) -> usize {
        16 + 4 * 3
            + wire::mpz_len(&self.response_gamma)
            + wire::mpz_len(&self.response_rho)
            + wire::mpz_len(&self.response_r0)
            + wire::mpz_len(&self.response_r1)
    }
}

struct ConCommitments {
    cl0: QFI,
    cl1: QFI,
    x0: QFI,
    x1: QFI,
    e0: G1,
    e1: G1,
    f0: G1,
    f1: G1,
}

fn con_challenge(ctx: &[u8], statement: &ConStatement<'_>, c: &ConCommitments) -> Scalar255 {
    let mut transcript = transcript(DOMAIN_CON, ctx);
    transcript
        .absorb_qfi(b"ek", statement.ek)
        .absorb_qfi(b"cx0", &statement.c_x.c0)
        .absorb_qfi(b"cx1", &statement.c_x.c1)
        .absorb_qfi(b"cg0", &statement.c_gamma.c0)
        .absorb_qfi(b"cg1", &statement.c_gamma.c1)
        .absorb_qfi(b"cgx0", &statement.c_gamma_x.c0)
        .absorb_qfi(b"cgx1", &statement.c_gamma_x.c1)
        .absorb_bytes(b"egpk", &statement.eg_public.to_bytes())
        .absorb_bytes(b"H0", &statement.h0.to_bytes())
        .absorb_bytes(b"D", &statement.d.to_bytes())
        .absorb_bytes(b"d01", &statement.c_d0.a1.to_bytes())
        .absorb_bytes(b"d02", &statement.c_d0.a2.to_bytes())
        .absorb_bytes(b"d11", &statement.c_d1.a1.to_bytes())
        .absorb_bytes(b"d12", &statement.c_d1.a2.to_bytes())
        .absorb_qfi(b"CL0", &c.cl0)
        .absorb_qfi(b"CL1", &c.cl1)
        .absorb_qfi(b"X0", &c.x0)
        .absorb_qfi(b"X1", &c.x1)
        .absorb_bytes(b"E0", &c.e0.to_bytes())
        .absorb_bytes(b"E1", &c.e1.to_bytes())
        .absorb_bytes(b"F0", &c.f0.to_bytes())
        .absorb_bytes(b"F1", &c.f1.to_bytes());
    challenge(&transcript)
}

/// `R_con`: one `gamma` in `C_{gamma}`, `C_{gamma x}`, `C_{D_0}` and `C_{D_1}`.
#[allow(clippy::too_many_arguments)]
pub fn prove_con(
    tc: &ThresholdCl,
    ctx: &[u8],
    statement: &ConStatement<'_>,
    gamma: &Scalar255,
    cl_randomness: &Mpz,
    r0: &Scalar255,
    r1: &Scalar255,
    rng: &mut RandGen,
    meter: &mut Meter,
) -> ConProof {
    let cl = &tc.cl;
    let nonce_gamma = rng.random_mpz(&mask_bound(tc, &bound_q(tc)));
    let nonce_rho = rng.random_mpz(&mask_bound(tc, &bound_dq(tc)));
    let nonce_r0 = rng.random_mpz(&mask_bound(tc, &bound_q(tc)));
    let nonce_r1 = rng.random_mpz(&mask_bound(tc, &bound_q(tc)));

    let n_gamma = mpz_to_scalar(&nonce_gamma);
    let n_r0 = mpz_to_scalar(&nonce_r0);
    let n_r1 = mpz_to_scalar(&nonce_r1);

    // The class-group commitments must use the *unreduced* nonce: the verifier recomputes
    // them as `base^{z} * target^{-ch}`, and only integer-exponent arithmetic cancels exactly
    // in a group of unknown order. `f` has order `q`, so reduced exponents are fine there.
    let cl0 = cl.exp(&tc.gq_delta2, &nonce_rho, meter);
    let mask = cl.exp(statement.ek, &nonce_rho, meter);
    let cl1 = cl.compose(&mask, &cl.f_exp(&n_gamma), meter);
    let x0 = cl.exp(&statement.c_x.c0, &nonce_gamma, meter);
    let x1 = cl.exp(&statement.c_x.c1, &nonce_gamma, meter);

    meter.add_n(Op::G1Exp, 6);
    let base = threshold_bbs::bls381::generator_g1();
    let e0 = base.scale(&n_r0);
    let e1 = statement
        .h0
        .scale(&n_gamma)
        .combine(&statement.eg_public.scale(&n_r0));
    let f0 = base.scale(&n_r1);
    let f1 = statement
        .d
        .scale(&n_gamma)
        .combine(&statement.eg_public.scale(&n_r1));

    let commitments = ConCommitments {
        cl0,
        cl1,
        x0,
        x1,
        e0,
        e1,
        f0,
        f1,
    };
    let challenge = con_challenge(ctx, statement, &commitments);
    let challenge_int = scalar_to_mpz(&challenge);

    meter.add(Op::Prove);
    ConProof {
        response_gamma: nonce_gamma + challenge_int.clone() * scalar_to_mpz(gamma),
        response_rho: nonce_rho + challenge_int.clone() * cl_randomness.clone(),
        response_r0: nonce_r0 + challenge_int.clone() * scalar_to_mpz(r0),
        response_r1: nonce_r1 + challenge_int * scalar_to_mpz(r1),
        challenge,
    }
}

pub fn verify_con(
    tc: &ThresholdCl,
    ctx: &[u8],
    statement: &ConStatement<'_>,
    proof: &ConProof,
    meter: &mut Meter,
) -> bool {
    let cl = &tc.cl;
    if !cl.is_form(statement.ek)
        || !cl.is_form(&statement.c_x.c0)
        || !cl.is_form(&statement.c_x.c1)
        || !cl.is_form(&statement.c_gamma.c0)
        || !cl.is_form(&statement.c_gamma.c1)
        || !cl.is_form(&statement.c_gamma_x.c0)
        || !cl.is_form(&statement.c_gamma_x.c1)
    {
        return false;
    }
    if !lt(&proof.response_gamma, &response_bound(tc, &bound_q(tc)))
        || !lt(&proof.response_rho, &response_bound(tc, &bound_dq(tc)))
        || !lt(&proof.response_r0, &response_bound(tc, &bound_q(tc)))
        || !lt(&proof.response_r1, &response_bound(tc, &bound_q(tc)))
    {
        return false;
    }

    let z_gamma = mpz_to_scalar(&proof.response_gamma);
    let z_r0 = mpz_to_scalar(&proof.response_r0);
    let z_r1 = mpz_to_scalar(&proof.response_r1);
    let neg_challenge = neg(&scalar_to_mpz(&proof.challenge));

    // CL: C_gamma = (g_q^{Delta^2 rho}, f^gamma ek^rho)
    let cl0 = cl.compose(
        &cl.exp(&tc.gq_delta2, &proof.response_rho, meter),
        &cl.exp(&statement.c_gamma.c0, &neg_challenge, meter),
        meter,
    );
    let mask = cl.exp(statement.ek, &proof.response_rho, meter);
    let cl1 = cl.compose(
        &cl.compose(&mask, &cl.f_exp(&z_gamma), meter),
        &cl.exp(&statement.c_gamma.c1, &neg_challenge, meter),
        meter,
    );
    // CL.SMul^*: C_{gamma x} = (c_x0^gamma, c_x1^gamma), corrected by `-ch`.
    let x0 = cl.compose(
        &cl.exp(&statement.c_x.c0, &proof.response_gamma, meter),
        &cl.exp(&statement.c_gamma_x.c0, &neg_challenge, meter),
        meter,
    );
    let x1 = cl.compose(
        &cl.exp(&statement.c_x.c1, &proof.response_gamma, meter),
        &cl.exp(&statement.c_gamma_x.c1, &neg_challenge, meter),
        meter,
    );

    // ElGamal: C_{D_0} = (r_0 G_1, gamma H_0 + r_0 X̂), C_{D_1} = (r_1 G_1, gamma D + r_1 X̂)
    let base = threshold_bbs::bls381::generator_g1();
    meter.add_n(Op::G1Exp, 8);
    let negative_challenge = neg_scalar(&proof.challenge);
    let e0 = base
        .scale(&z_r0)
        .combine(&statement.c_d0.a1.scale(&negative_challenge));
    let e1 = statement
        .h0
        .scale(&z_gamma)
        .combine(&statement.eg_public.scale(&z_r0))
        .combine(&statement.c_d0.a2.scale(&negative_challenge));
    let f0 = base
        .scale(&z_r1)
        .combine(&statement.c_d1.a1.scale(&negative_challenge));
    let f1 = statement
        .d
        .scale(&z_gamma)
        .combine(&statement.eg_public.scale(&z_r1))
        .combine(&statement.c_d1.a2.scale(&negative_challenge));

    let commitments = ConCommitments {
        cl0,
        cl1,
        x0,
        x1,
        e0,
        e1,
        f0,
        f1,
    };
    meter.add(Op::Verify);
    con_challenge(ctx, statement, &commitments) == proof.challenge
}

/// `x G_2` for a scalar, counted.
pub fn point_g2(value: &Scalar255, meter: &mut Meter) -> G2 {
    meter.add(Op::G2Exp);
    threshold_bbs::bls381::generator_g2().scale(value)
}

/// Helper for the crates: `m G_2` under an arbitrary base.
pub fn scale_g2(base: &G2, value: &Scalar255, meter: &mut Meter) -> G2 {
    meter.add(Op::G2Exp);
    base.scale(value)
}

/// `mul` re-export so callers do not pull in `util` for one call.
pub fn mul_mpz(lhs: &Mpz, rhs: &Mpz) -> Mpz {
    mul(lhs, rhs)
}
