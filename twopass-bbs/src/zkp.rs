//! The three Σ-protocols of Appendix A, compiled with Fiat–Shamir.
//!
//! | relation | statement | witness | where |
//! |---|---|---|---|
//! | `R_DL` | `Y = y G` | `y in Z_q` | DKG pass 2: `P_2` knows `sk_2` behind `vk_2` |
//! | `R_CL-DL` | `C_x = CL-Enc(ek, x)`, `X = x G_2` | `x`, `rho` | DKG pass 3: `C_key1` is an encryption of `x_1` |
//! | `R_CL-Lin` | `CT_b = r*CT_a + CL-Enc(ek, r(x+e))`, `C = r B`, `W = r(x+e) B` | `r`, `x`, `rho` | signing pass 2 |
//!
//! # How `R_CL-Lin` differs from Fig. 4
//!
//! Fig. 4 keeps the two multiplicative facts (`C = r B` in `G_1`, `r(x+e)` inside the
//! ciphertext) tied together by a pairing identity, and commits to that identity with the
//! `G_T` element `T_{alpha_t} = alpha_t G_H`. That commitment has to be *in* the Fiat–Shamir
//! transcript — without it the pairing equation becomes an identity the verifier computes for
//! itself, and `P_2` regains the freedom to encrypt the wrong plaintext (the selective-abort
//! channel that lets it probe `x_1` one bit at a time).
//!
//! `bls12_381::Gt` has no canonical encoding (its `Fp12` internals are crate-private), so a
//! `G_T` element cannot be absorbed into a transcript. This implementation therefore sends
//! `W = r(x+e) B` in the clear and has the verifier check
//!
//! ```text
//! e(W, G_2) = e(C, X + e G_2)          (public, deterministic, no challenge needed)
//! ```
//!
//! which is the same constraint: with `C = rB` it forces `W = r(x+e) B`. Soundness is
//! unchanged (extract `r` and `w` from the two Schnorr equations on `B`, then `w = r(x+e)`
//! follows from the pairing check), and HVZK still holds: the simulator picks `r'`, sets
//! `C = r' A` and `W = r' B`, which satisfies the check because `A = B/(x+e)`.
//!
//! Two things make this a free substitution rather than a weakening: `W` is exactly the value
//! `P_1` recovers from `D` (`d B` with `d = CL-Dec(dk_1, D)`), so sending it reveals nothing
//! `P_1` does not learn anyway; and the pairing check uses only public values, so its outcome
//! cannot depend on `x_1`. A proof now carries `W` (48 B) and no `beta_t`, which is 16 B less
//! than `M` + `beta_t`.

use bicycl::{Mpz, QFI, RandGen};

use threshold_bbs::algebra::{Group, PairingGroup, Scalar};
use threshold_bbs::bls381::{Scalar255, G1, G2};
use threshold_bbs::hash::Transcript;
use threshold_bbs::util::{mpz_lt, mpz_to_scalar, scalar_to_mpz};

use crate::cl::Cipher;
use crate::error::Result;
use crate::meter::{Meter, Op};
use crate::params::PublicParameters;
use crate::wire::{self, Reader};

pub const DOMAIN_DL: &[u8] = b"twopass-bbs/v01/zkp/dl";
pub const DOMAIN_CL_DL: &[u8] = b"twopass-bbs/v01/zkp/cl-dl";
pub const DOMAIN_CL_LIN: &[u8] = b"twopass-bbs/v01/zkp/cl-lin";

/// `ctx = sid || tag || ids`: what binds a proof to one execution.
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

fn base_transcript(pp: &PublicParameters, domain: &[u8], ctx: &[u8]) -> Transcript {
    let mut transcript = Transcript::new(domain);
    transcript.absorb_bytes(b"ctx", ctx);
    pp.absorb(&mut transcript);
    transcript
}

fn neg(value: &Scalar255) -> Scalar255 {
    <Scalar255 as Scalar>::zero().sub(value)
}

fn mpz_len(value: &Mpz) -> usize {
    threshold_bbs::util::mpz_bytes(value).len()
}

// ---------------------------------------------------------------------------------------
// R_DL
// ---------------------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct DlProof {
    pub challenge: Scalar255,
    pub response: Scalar255,
}

impl DlProof {
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
        16 + 32
    }
}

pub fn prove_dl(
    pp: &PublicParameters,
    ctx: &[u8],
    base: &G1,
    target: &G1,
    witness: &Scalar255,
    rng: &mut impl rand_core::RngCore,
    meter: &mut Meter,
) -> DlProof {
    let nonce = Scalar255::random(rng);
    meter.add(Op::G1Exp);
    let commitment = base.scale(&nonce);

    let mut transcript = base_transcript(pp, DOMAIN_DL, ctx);
    transcript
        .absorb_g1(b"G", base)
        .absorb_g1(b"Y", target)
        .absorb_g1(b"U", &commitment);
    let challenge = pp.challenge(&transcript);

    meter.add(Op::Prove);
    DlProof {
        response: nonce.add(&challenge.mul(witness)),
        challenge,
    }
}

pub fn verify_dl(
    pp: &PublicParameters,
    ctx: &[u8],
    base: &G1,
    target: &G1,
    proof: &DlProof,
    meter: &mut Meter,
) -> bool {
    meter.add(Op::G1Exp);
    let commitment = base
        .scale(&proof.response)
        .combine(&target.scale(&neg(&proof.challenge)));

    let mut transcript = base_transcript(pp, DOMAIN_DL, ctx);
    transcript
        .absorb_g1(b"G", base)
        .absorb_g1(b"Y", target)
        .absorb_g1(b"U", &commitment);
    meter.add(Op::Verify);
    pp.challenge(&transcript) == proof.challenge
}

// ---------------------------------------------------------------------------------------
// R_CL-DL  (Fig. 3b)
// ---------------------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct ClDlProof {
    pub challenge: Scalar255,
    /// `z* = z_0 + ch x`.
    pub response_x: Scalar255,
    /// `rho* = rho_0 + ch rho`, an integer that is never reduced.
    pub response_rho: Mpz,
}

impl ClDlProof {
    pub fn encode(&self, out: &mut Vec<u8>) {
        wire::put_challenge(out, &self.challenge);
        wire::put_scalar(out, &self.response_x);
        wire::put_mpz(out, &self.response_rho);
    }

    pub fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            challenge: reader.challenge()?,
            response_x: reader.scalar()?,
            response_rho: reader.mpz()?,
        })
    }

    pub fn encoded_len(&self) -> usize {
        16 + 32 + 3 + mpz_len(&self.response_rho)
    }
}

pub struct ClDlStatement<'a> {
    pub ek: &'a QFI,
    pub x_g2: &'a G2,
    pub cipher: &'a Cipher,
}

fn cl_dl_challenge(
    pp: &PublicParameters,
    ctx: &[u8],
    statement: &ClDlStatement<'_>,
    phi1: &QFI,
    phi2: &QFI,
    point: &G2,
) -> Scalar255 {
    let mut transcript = base_transcript(pp, DOMAIN_CL_DL, ctx);
    transcript
        .absorb_qfi(b"ek", statement.ek)
        .absorb_g2(b"X", statement.x_g2)
        .absorb_qfi(b"c1", &statement.cipher.c1)
        .absorb_qfi(b"c2", &statement.cipher.c2)
        .absorb_qfi(b"phi1", phi1)
        .absorb_qfi(b"phi2", phi2)
        .absorb_g2(b"Z", point);
    pp.challenge(&transcript)
}

pub fn prove_cl_dl(
    pp: &PublicParameters,
    ctx: &[u8],
    statement: &ClDlStatement<'_>,
    witness_x: &Scalar255,
    witness_rho: &Mpz,
    rng: &mut RandGen,
    meter: &mut Meter,
) -> ClDlProof {
    let class = &pp.cl;
    let nonce_x = Scalar255::random(&mut rand_core::OsRng);
    let nonce_rho = class.sample_dq(rng);

    let phi1 = class.exp(class.gq(), &nonce_rho, meter);
    let key = class.exp(statement.ek, &nonce_rho, meter);
    let phi2 = class.compose(&key, &class.f_exp(&nonce_x), meter);
    meter.add(Op::G2Exp);
    let point = pp.g2.scale(&nonce_x);

    let challenge = cl_dl_challenge(pp, ctx, statement, &phi1, &phi2, &point);
    let challenge_int = scalar_to_mpz(&challenge);

    meter.add(Op::Prove);
    ClDlProof {
        response_x: nonce_x.add(&challenge.mul(witness_x)),
        response_rho: nonce_rho + challenge_int * witness_rho.clone(),
        challenge,
    }
}

pub fn verify_cl_dl(
    pp: &PublicParameters,
    ctx: &[u8],
    statement: &ClDlStatement<'_>,
    proof: &ClDlProof,
    meter: &mut Meter,
) -> bool {
    let class = &pp.cl;
    if !class.is_form(statement.ek)
        || !class.is_form(&statement.cipher.c1)
        || !class.is_form(&statement.cipher.c2)
    {
        return false;
    }
    if !mpz_lt(&proof.response_rho, &pp.response_bound_dq()) {
        return false;
    }

    let negative = Mpz::from(0u64) - scalar_to_mpz(&proof.challenge);

    // Z_0 = z* G_2 - ch X
    meter.add(Op::G2Exp);
    let point = pp
        .g2
        .scale(&proof.response_x)
        .combine(&statement.x_g2.scale(&neg(&proof.challenge)));

    // phi1 = g_q^{rho*} c1^{-ch}
    let exp_rho = class.exp(class.gq(), &proof.response_rho, meter);
    let corrective = class.exp(&statement.cipher.c1, &negative, meter);
    let phi1 = class.compose(&exp_rho, &corrective, meter);

    // phi2 = f^{z*} ek^{rho*} c2^{-ch}
    let kernel = class.f_exp(&proof.response_x);
    let key = class.exp(statement.ek, &proof.response_rho, meter);
    let sealed = class.compose(&key, &kernel, meter);
    let corrective = class.exp(&statement.cipher.c2, &negative, meter);
    let phi2 = class.compose(&sealed, &corrective, meter);

    meter.add(Op::Verify);
    cl_dl_challenge(pp, ctx, statement, &phi1, &phi2, &point) == proof.challenge
}

// ---------------------------------------------------------------------------------------
// R_CL-Lin
// ---------------------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct LinProof {
    /// `W = r(x+e) B`; the verifier checks `e(W, G_2) = e(C, X + e G_2)` against it.
    pub w: G1,
    pub challenge: Scalar255,
    /// `beta_r = alpha_r + ch r`.
    pub response_r: Mpz,
    /// `beta_rx = alpha_rx + ch r(x+e)`.
    pub response_rx: Mpz,
    /// `beta_rho = alpha_rho + ch rho`.
    pub response_rho: Mpz,
}

impl LinProof {
    pub fn encode(&self, out: &mut Vec<u8>) {
        wire::put_g1(out, &self.w);
        wire::put_challenge(out, &self.challenge);
        wire::put_mpz(out, &self.response_r);
        wire::put_mpz(out, &self.response_rx);
        wire::put_mpz(out, &self.response_rho);
    }

    pub fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            w: reader.g1()?,
            challenge: reader.challenge()?,
            response_r: reader.mpz()?,
            response_rx: reader.mpz()?,
            response_rho: reader.mpz()?,
        })
    }

    pub fn encoded_len(&self) -> usize {
        48 + 16
            + 3
            + mpz_len(&self.response_r)
            + 3
            + mpz_len(&self.response_rx)
            + 3
            + mpz_len(&self.response_rho)
    }
}

pub struct LinStatement<'a> {
    pub ek: &'a QFI,
    /// The relation's `G_1`: the BBS+ base `B`.
    pub base: &'a G1,
    /// `C = r * base`.
    pub scaled: &'a G1,
    /// `X = x G_2`, i.e. `P_2`'s public share `X_2`.
    pub x_g2: &'a G2,
    /// `CT_a`: `P_1`'s long-term ciphertext `C_key1`.
    pub ct_a: &'a Cipher,
    /// `CT_b`: the freshly produced `D`.
    pub ct_b: &'a Cipher,
    pub e: &'a Scalar255,
}

pub struct LinWitness<'a> {
    pub r: &'a Scalar255,
    pub x: &'a Scalar255,
    pub rho: &'a Mpz,
}

#[allow(clippy::too_many_arguments)]
fn lin_challenge(
    pp: &PublicParameters,
    ctx: &[u8],
    statement: &LinStatement<'_>,
    w: &G1,
    t_r: &G1,
    t_w: &G1,
    t_1: &QFI,
    t_2: &QFI,
) -> Scalar255 {
    let mut transcript = base_transcript(pp, DOMAIN_CL_LIN, ctx);
    transcript
        .absorb_qfi(b"ek", statement.ek)
        .absorb_g1(b"G", statement.base)
        .absorb_g1(b"C", statement.scaled)
        .absorb_g2(b"X", statement.x_g2)
        .absorb_qfi(b"c1", &statement.ct_a.c1)
        .absorb_qfi(b"c2", &statement.ct_a.c2)
        .absorb_qfi(b"d1", &statement.ct_b.c1)
        .absorb_qfi(b"d2", &statement.ct_b.c2)
        .absorb_scalar(b"e", statement.e)
        .absorb_g1(b"W", w)
        .absorb_g1(b"TR", t_r)
        .absorb_g1(b"TW", t_w)
        .absorb_qfi(b"T1", t_1)
        .absorb_qfi(b"T2", t_2);
    pp.challenge(&transcript)
}

/// `Pi_{R_CL-Lin}.Prv`.
pub fn prove_cl_lin(
    pp: &PublicParameters,
    ctx: &[u8],
    statement: &LinStatement<'_>,
    witness: &LinWitness<'_>,
    rng: &mut RandGen,
    meter: &mut Meter,
) -> LinProof {
    let class = &pp.cl;
    let rx = witness.r.mul(&witness.x.add(statement.e));

    let alpha_r = rng.random_mpz(&pp.mask_bound_q());
    let alpha_rx = rng.random_mpz(&pp.mask_bound_q());
    let alpha_rho = rng.random_mpz(&pp.mask_bound_dq());

    meter.add_n(Op::G1Exp, 3);
    let w = statement.base.scale(&rx);
    let t_r = statement.base.scale(&mpz_to_scalar(&alpha_r));
    let t_w = statement.base.scale(&mpz_to_scalar(&alpha_rx));

    let t_1 = t1_of(class, statement, &alpha_r, &alpha_rho, meter);
    let t_2 = t2_of(class, statement, &alpha_r, &alpha_rx, &alpha_rho, meter);

    let challenge = lin_challenge(pp, ctx, statement, &w, &t_r, &t_w, &t_1, &t_2);
    let challenge_int = scalar_to_mpz(&challenge);

    meter.add(Op::Prove);
    LinProof {
        response_r: alpha_r + challenge_int.clone() * scalar_to_mpz(witness.r),
        response_rx: alpha_rx + challenge_int.clone() * scalar_to_mpz(&rx),
        response_rho: alpha_rho + challenge_int * witness.rho.clone(),
        w,
        challenge,
    }
}

/// `Pi_{R_CL-Lin}.Vrf`, including the public pairing check on `W`.
pub fn verify_cl_lin(
    pp: &PublicParameters,
    ctx: &[u8],
    statement: &LinStatement<'_>,
    proof: &LinProof,
    meter: &mut Meter,
) -> bool {
    let class = &pp.cl;
    if !class.is_form(statement.ek)
        || !class.is_form(&statement.ct_a.c1)
        || !class.is_form(&statement.ct_a.c2)
        || !class.is_form(&statement.ct_b.c1)
        || !class.is_form(&statement.ct_b.c2)
    {
        return false;
    }
    if !mpz_lt(&proof.response_r, &pp.response_bound_q())
        || !mpz_lt(&proof.response_rx, &pp.response_bound_q())
        || !mpz_lt(&proof.response_rho, &pp.response_bound_dq())
    {
        return false;
    }

    // The public pairing identity: e(W, G_2) = e(C, X + e G_2). This is what forces
    // W = r(x+e) B once C = r B is fixed, and it depends on no secret of P_1's.
    meter.add_n(Op::Pairing, 2);
    let x_plus_e = statement.x_g2.combine(&pp.g2.scale(statement.e));
    if G1::pairing(&pp.g2, &proof.w) != G1::pairing(&x_plus_e, statement.scaled) {
        return false;
    }

    let negative = Mpz::from(0u64) - scalar_to_mpz(&proof.challenge);

    // T_R = beta_r B - ch C,  T_W = beta_rx B - ch W
    meter.add_n(Op::G1Exp, 4);
    let t_r = statement
        .base
        .scale(&mpz_to_scalar(&proof.response_r))
        .combine(&statement.scaled.scale(&neg(&proof.challenge)));
    let t_w = statement
        .base
        .scale(&mpz_to_scalar(&proof.response_rx))
        .combine(&proof.w.scale(&neg(&proof.challenge)));

    // T_1 = c1^{beta_r} g_q^{beta_rho} d1^{-ch}
    let exp_r = class.exp(&statement.ct_a.c1, &proof.response_r, meter);
    let exp_rho = class.exp(class.gq(), &proof.response_rho, meter);
    let corrective = class.exp(&statement.ct_b.c1, &negative, meter);
    let t_1 = class.compose(&class.compose(&exp_r, &exp_rho, meter), &corrective, meter);

    // T_2 = c2^{beta_r} f^{beta_rx} ek^{beta_rho} d2^{-ch}
    let exp_r = class.exp(&statement.ct_a.c2, &proof.response_r, meter);
    let kernel = class.f_exp_mpz(&proof.response_rx);
    let exp_rho = class.exp(statement.ek, &proof.response_rho, meter);
    let sealed = class.compose(&class.compose(&exp_r, &kernel, meter), &exp_rho, meter);
    let corrective = class.exp(&statement.ct_b.c2, &negative, meter);
    let t_2 = class.compose(&sealed, &corrective, meter);

    meter.add(Op::Verify);
    lin_challenge(pp, ctx, statement, &proof.w, &t_r, &t_w, &t_1, &t_2) == proof.challenge
}

fn t1_of(
    class: &crate::cl::ClParameters,
    statement: &LinStatement<'_>,
    alpha_r: &Mpz,
    alpha_rho: &Mpz,
    meter: &mut Meter,
) -> QFI {
    let exp_r = class.exp(&statement.ct_a.c1, alpha_r, meter);
    let exp_rho = class.exp(class.gq(), alpha_rho, meter);
    class.compose(&exp_r, &exp_rho, meter)
}

fn t2_of(
    class: &crate::cl::ClParameters,
    statement: &LinStatement<'_>,
    alpha_r: &Mpz,
    alpha_rx: &Mpz,
    alpha_rho: &Mpz,
    meter: &mut Meter,
) -> QFI {
    let exp_r = class.exp(&statement.ct_a.c2, alpha_r, meter);
    let kernel = class.f_exp_mpz(alpha_rx);
    let exp_rho = class.exp(statement.ek, alpha_rho, meter);
    class.compose(&class.compose(&exp_r, &kernel, meter), &exp_rho, meter)
}

/// Errors out when `r(x+e) = 0`, the only arithmetic abort in signing.
pub fn require_invertible(value: &Scalar255) -> Result<()> {
    value
        .invert()
        .map(|_| ())
        .ok_or(crate::error::Error::Arithmetic("r(x + e) = 0"))
}
