//! The three Σ-protocols, compiled with Fiat–Shamir.
//!
//! | relation | statement | witness | used in |
//! |---|---|---|---|
//! | `R_dlc`  | `C = c^w` | `w in [0, B)` | PVSS commitments, `D_i` share proofs |
//! | `R_dls`  | `C = c^w` | `w in [0, B)` | `phi_{K^{gamma_i}} = phi_K^{gamma_i}` |
//! | `R_enc`  | `c1 = g_q^r, c2 = pk^r f^m, M = m G_2` | `(m, r)` | `(phi_{K_i}, x_i^K, X_i)` |
//!
//! `R_dlc` and `R_dls` are the same Σ-protocol over different domains: the paper's `R_dls`
//! is stated with a `2^{-w_2}` twist to support extraction from a possibly biased
//! encapsulation (§B.3), and the deployed witness is `(gamma_i, 0)`, so the prover here
//! sends one integer response. `R_enc` is Fig. 9 with the same compression.
//!
//! In all three the verifier does not receive the first message: it recomputes it from
//! `(challenge, responses)` and re-derives the challenge, so a proof is
//! `16 + ~151` bytes for `R_dlc`/`R_dls` and `16 + ~151 + 32` for `R_enc`. This is the
//! mechanism behind the 0.78 KiB per signer in Table 3.

use bicycl::{Mpz, QFI, RandGen};

use threshold_bbs::algebra::{Group, Scalar};
use threshold_bbs::bls381::{Scalar255, G2};
use threshold_bbs::hash::Transcript;
use threshold_bbs::util::{mpz_lt, mpz_to_scalar, pow2};

use crate::error::Result;
use crate::params::PublicParameters;
use crate::stats::{Meter, Op};
use crate::util::neg;
use crate::wire::{self, Reader};

pub const DOMAIN_DLC: &[u8] = b"clkem-tbbs/v01/zkp/dlc";
pub const DOMAIN_DLS: &[u8] = b"clkem-tbbs/v01/zkp/dls";
pub const DOMAIN_ENC: &[u8] = b"clkem-tbbs/v01/zkp/enc";

/// `ctx = sid || tag || id`: what binds a proof to a party, a round and a session.
pub fn context(session: &[u8], tag: &[u8], id: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(session.len() + tag.len() + 16);
    bytes.extend_from_slice(&(session.len() as u32).to_be_bytes());
    bytes.extend_from_slice(session);
    bytes.extend_from_slice(&(tag.len() as u32).to_be_bytes());
    bytes.extend_from_slice(tag);
    bytes.extend_from_slice(&(id as u64).to_be_bytes());
    bytes
}

fn base_transcript(pp: &PublicParameters, domain: &[u8], ctx: &[u8]) -> Transcript {
    let mut transcript = Transcript::new(domain);
    transcript.absorb_bytes(b"ctx", ctx);
    pp.absorb(&mut transcript);
    transcript
}

/// `2^{lambda + lambda_d} * bound`: the interval nonces are drawn from.
pub fn mask_bound(pp: &PublicParameters, bound: &Mpz) -> Mpz {
    pow2(pp.config.lambda + pp.config.lambda_d) * bound.clone()
}

/// `2^{lambda} * bound * (2^{lambda_d} + 1)`: the honest response bound.
pub fn response_bound(pp: &PublicParameters, bound: &Mpz) -> Mpz {
    pow2(pp.config.lambda) * bound.clone() * (pow2(pp.config.lambda_d) + Mpz::from(1u64))
}

/// `C = c^w` — the ZKPoK behind `R_dlc` and `R_dls`.
#[derive(Clone, Debug)]
pub struct DlProof {
    pub challenge: Mpz,
    /// `r_1 + k w`, kept as an integer and never reduced.
    pub response: Mpz,
}

impl DlProof {
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
        let mut buffer = Vec::new();
        self.encode(&mut buffer);
        buffer.len()
    }
}

/// `Pi_{R_dlc}.Prv` / `Pi_{R_dls}.Prv`.
pub fn prove_dl(
    pp: &PublicParameters,
    domain: &[u8],
    ctx: &[u8],
    base: &QFI,
    target: &QFI,
    witness: &Mpz,
    bound: &Mpz,
    rng: &mut RandGen,
    meter: &mut Meter,
) -> DlProof {
    let cl = &pp.cl;
    let mask = rng.random_mpz(&mask_bound(pp, bound));
    let commitment = cl.exp(base, &mask, meter);

    let mut transcript = base_transcript(pp, domain, ctx);
    transcript
        .absorb_qfi(b"c", base)
        .absorb_qfi(b"C", target)
        .absorb_qfi(b"T", &commitment);
    let challenge = pp.challenge(&transcript);

    meter.add(Op::Prove);
    DlProof {
        response: mask + challenge.clone() * witness.clone(),
        challenge,
    }
}

/// `Pi_{R_dlc}.Vrf` / `Pi_{R_dls}.Vrf`.
pub fn verify_dl(
    pp: &PublicParameters,
    domain: &[u8],
    ctx: &[u8],
    base: &QFI,
    target: &QFI,
    proof: &DlProof,
    bound: &Mpz,
    meter: &mut Meter,
) -> bool {
    let cl = &pp.cl;
    if !cl.is_form(base) || !cl.is_form(target) {
        return false;
    }
    if !mpz_lt(&proof.response, &response_bound(pp, bound)) {
        return false;
    }
    // T = c^r * C^{-k}, recomputed rather than transmitted.
    let negative = neg(&proof.challenge);
    let positive = cl.exp(base, &proof.response, meter);
    let corrective = cl.exp(target, &negative, meter);
    let commitment = cl.compose(&positive, &corrective, meter);

    let mut transcript = base_transcript(pp, domain, ctx);
    transcript
        .absorb_qfi(b"c", base)
        .absorb_qfi(b"C", target)
        .absorb_qfi(b"T", &commitment);
    meter.add(Op::Verify);
    pp.challenge(&transcript) == proof.challenge
}

/// Fig. 9's `R_enc`, compressed.
#[derive(Clone, Debug)]
pub struct EncProof {
    pub challenge: Mpz,
    pub response_r: Mpz,
    pub response_m: Scalar255,
}

impl EncProof {
    pub fn encode(&self, out: &mut Vec<u8>) {
        wire::put_challenge(out, &self.challenge);
        wire::put_mpz(out, &self.response_r);
        wire::put_scalar(out, &self.response_m);
    }

    pub fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            challenge: reader.challenge()?,
            response_r: reader.mpz()?,
            response_m: reader.scalar()?,
        })
    }

    pub fn encoded_len(&self) -> usize {
        let mut buffer = Vec::new();
        self.encode(&mut buffer);
        buffer.len()
    }
}

/// `Pi_{R_enc}.Prv((pk, phi, x_bar, X), (x_i, r_i))`.
#[allow(clippy::too_many_arguments)]
pub fn prove_enc(
    pp: &PublicParameters,
    ctx: &[u8],
    pk: &QFI,
    phi: &QFI,
    cipher: &QFI,
    point: &G2,
    message: &Scalar255,
    randomness: &Mpz,
    rng: &mut RandGen,
    meter: &mut Meter,
) -> EncProof {
    let cl = &pp.cl;
    let mask_r = rng.random_mpz(&mask_bound(pp, cl.bound_bq()));
    let mask_m = Scalar255::random(&mut rand_core::OsRng);

    let first = cl.exp(cl.gq(), &mask_r, meter);
    let key = cl.exp(pk, &mask_r, meter);
    let second = cl.compose(&key, &cl.f_exp(&mask_m), meter);
    let point_mask = {
        meter.add(Op::G2Exp);
        pp.g2.scale(&mask_m)
    };

    let mut transcript = base_transcript(pp, DOMAIN_ENC, ctx);
    transcript
        .absorb_qfi(b"pk", pk)
        .absorb_qfi(b"phi", phi)
        .absorb_qfi(b"xbar", cipher)
        .absorb_g2(b"X", point)
        .absorb_qfi(b"phi'", &first)
        .absorb_qfi(b"xbar'", &second)
        .absorb_g2(b"X'", &point_mask);
    let challenge = pp.challenge(&transcript);

    let c = mpz_to_scalar(&challenge);
    meter.add(Op::Prove);
    EncProof {
        response_r: mask_r + challenge.clone() * randomness.clone(),
        response_m: mask_m.add(&c.mul(message)),
        challenge,
    }
}

/// `Pi_{R_enc}.Vrf`.
pub fn verify_enc(
    pp: &PublicParameters,
    ctx: &[u8],
    pk: &QFI,
    phi: &QFI,
    cipher: &QFI,
    point: &G2,
    proof: &EncProof,
    meter: &mut Meter,
) -> bool {
    let cl = &pp.cl;
    if !cl.is_form(pk) || !cl.is_form(phi) || !cl.is_form(cipher) {
        return false;
    }
    if !mpz_lt(&proof.response_r, &response_bound(pp, cl.bound_bq())) {
        return false;
    }

    let c = mpz_to_scalar(&proof.challenge);
    let negative_scalar = Scalar255::zero().sub(&c);
    let negative = neg(&proof.challenge);

    // phi' = g_q^{r_3} phi^{-k}
    let first = cl.compose_powers(cl.gq(), &proof.response_r, phi, &negative, meter);
    // x_bar' = pk^{r_3} f^{r_4} x_bar^{-k}
    let key = cl.exp(pk, &proof.response_r, meter);
    let kernel = cl.f_exp(&proof.response_m);
    let sealed = cl.compose(&key, &kernel, meter);
    let corrective = cl.exp(cipher, &negative, meter);
    let second = cl.compose(&sealed, &corrective, meter);
    // X' = r_4 G_2 - k X
    let point_mask = {
        meter.add_n(Op::G2Exp, 2);
        pp.g2
            .scale(&proof.response_m)
            .combine(&point.scale(&negative_scalar))
    };

    let mut transcript = base_transcript(pp, DOMAIN_ENC, ctx);
    transcript
        .absorb_qfi(b"pk", pk)
        .absorb_qfi(b"phi", phi)
        .absorb_qfi(b"xbar", cipher)
        .absorb_g2(b"X", point)
        .absorb_qfi(b"phi'", &first)
        .absorb_qfi(b"xbar'", &second)
        .absorb_g2(b"X'", &point_mask);
    meter.add(Op::Verify);
    pp.challenge(&transcript) == proof.challenge
}
