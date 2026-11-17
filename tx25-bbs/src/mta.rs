//! Multi-party MtA with public checking, and its batched `R*` proof (TX25 §3.3 / Appendix A.3).
//!
//! For every ordered pair `(j, i)` of signers, `P_i` holds the affine map `k_i` and `P_j`'s
//! ciphertext `C_{gamma_j}`; the result `C_{alpha_{j,i}}` is decryptable only by `P_j` and
//! opens `gamma_j k_i - beta_{i,j}`. One batched proof covers all `j` at once, using the
//! random batching exponents `e_j = H(statement)`.

use std::collections::BTreeMap;

use bicycl::{Mpz, QFI, RandGen};

use tcl::cl::{self, Cipher, ClParameters};
use tcl::meter::{Meter, Op};
use tcl::util::{lt, mul, neg};
use tcl::wire::{self, Reader};
use tcl::{Error, Result};

use threshold_bbs::algebra::{Encodable, Group, Scalar};
use threshold_bbs::bls381::{Scalar255, G2};
use threshold_bbs::hash::Transcript;
use threshold_bbs::util::{mpz_to_scalar, pow2, scalar_to_mpz};

pub const DOMAIN_BATCH: &[u8] = b"tx25-bbs/v01/mta/batch";
pub const DOMAIN_AFF: &[u8] = b"tx25-bbs/v01/zkp/aff";

/// `(C_{gamma^*}, C_{alpha^*}, B, R)` — the aggregated statement of `R^*`.
#[derive(Clone, Debug)]
pub struct Aggregated {
    pub gamma: Cipher,
    pub alpha: Cipher,
    pub b: G2,
    pub x_point: G2,
}

/// `e_j = H(statement, j)`, the batching exponents. Both sides derive them from the same data,
/// so the aggregated statement and the proof agree without transmitting the exponents.
pub fn batch_exponents(
    ctx: &[u8],
    c_gammas: &BTreeMap<usize, Cipher>,
    c_alphas: &BTreeMap<usize, Cipher>,
    b_points: &BTreeMap<usize, G2>,
    x_point: &G2,
) -> Result<BTreeMap<usize, Scalar255>> {
    let mut transcript = Transcript::new(DOMAIN_BATCH);
    transcript
        .absorb_bytes(b"ctx", ctx)
        .absorb_bytes(b"X", &x_point.to_bytes());
    for (id, gamma) in c_gammas {
        let alpha = c_alphas.get(id).ok_or(Error::Missing("alpha ciphertext"))?;
        let b = b_points.get(id).ok_or(Error::Missing("B point"))?;
        transcript
            .absorb_u64(b"id", *id as u64)
            .absorb_qfi(b"c1", &gamma.c0)
            .absorb_qfi(b"c2", &gamma.c1)
            .absorb_qfi(b"d1", &alpha.c0)
            .absorb_qfi(b"d2", &alpha.c1)
            .absorb_bytes(b"B", &b.to_bytes());
    }
    let digest = transcript.digest32();
    let mut exponents = BTreeMap::new();
    for id in c_gammas.keys() {
        let mut per_party = Transcript::new(DOMAIN_BATCH);
        per_party
            .absorb_bytes(b"digest", &digest)
            .absorb_u64(b"id", *id as u64);
        exponents.insert(
            *id,
            Scalar255::from_be_bytes_mod_order(&per_party.digest32()[..16]),
        );
    }
    Ok(exponents)
}

/// `Aggregate`: component-wise products with the batching exponents, and `B = sum e_j B_j`.
pub fn aggregate(
    cl: &ClParameters,
    ctx: &[u8],
    c_gammas: &BTreeMap<usize, Cipher>,
    c_alphas: &BTreeMap<usize, Cipher>,
    b_points: &BTreeMap<usize, G2>,
    x_point: &G2,
    meter: &mut Meter,
) -> Result<(Aggregated, BTreeMap<usize, Scalar255>)> {
    let exponents = batch_exponents(ctx, c_gammas, c_alphas, b_points, x_point)?;
    let mut gamma = Cipher {
        c0: cl.identity().clone(),
        c1: cl.identity().clone(),
    };
    let mut alpha = Cipher {
        c0: cl.identity().clone(),
        c1: cl.identity().clone(),
    };
    let mut b = G2::identity();
    for (id, exponent) in &exponents {
        let gamma_j = c_gammas.get(id).ok_or(Error::Missing("gamma ciphertext"))?;
        let alpha_j = c_alphas.get(id).ok_or(Error::Missing("alpha ciphertext"))?;
        gamma = cl::add(
            cl,
            &gamma,
            &cl::smul_star(cl, exponent, gamma_j, meter),
            meter,
        );
        alpha = cl::add(
            cl,
            &alpha,
            &cl::smul_star(cl, exponent, alpha_j, meter),
            meter,
        );
        meter.add(Op::G2Exp);
        b = b.combine(&b_points[id].scale(exponent));
    }
    Ok((
        Aggregated {
            gamma,
            alpha,
            b,
            x_point: x_point.clone(),
        },
        exponents,
    ))
}

/// `beta^* = sum_j e_j beta_j mod q`.
pub fn weighted_beta(
    betas: &BTreeMap<usize, Scalar255>,
    exponents: &BTreeMap<usize, Scalar255>,
) -> Result<Scalar255> {
    let mut total = <Scalar255 as Scalar>::zero();
    for (id, exponent) in exponents {
        let beta = betas.get(id).ok_or(Error::Missing("beta"))?;
        total = total.add(&exponent.mul(beta));
    }
    Ok(total)
}

/// The batched proof: `((d_1', d_2'), B_0, R_0, z_k, z_beta)`.
#[derive(Clone, Debug)]
pub struct AffProof {
    pub d1: QFI,
    pub d2: QFI,
    pub b0: G2,
    pub r0: G2,
    pub response_k: Mpz,
    pub response_beta: Mpz,
    pub challenge: Scalar255,
}

impl AffProof {
    pub fn encode(&self, out: &mut Vec<u8>) {
        wire::put_qfi(out, &self.d1);
        wire::put_qfi(out, &self.d2);
        wire::put_g2(out, &self.b0);
        wire::put_g2(out, &self.r0);
        wire::put_mpz(out, &self.response_k);
        wire::put_mpz(out, &self.response_beta);
        wire::put_challenge(out, &self.challenge);
    }

    pub fn decode(reader: &mut Reader<'_>, cl: &ClParameters) -> Result<Self> {
        Ok(Self {
            d1: reader.qfi(cl)?,
            d2: reader.qfi(cl)?,
            b0: reader.g2()?,
            r0: reader.g2()?,
            response_k: reader.mpz()?,
            response_beta: reader.mpz()?,
            challenge: reader.challenge()?,
        })
    }
}

/// `k^* = k + e q` lives in `[0, q (1 + D_q))`.
fn k_bound(cl: &ClParameters) -> Mpz {
    cl.modulus().clone() * (Mpz::from(1u64) + cl.bound_dq().clone())
}

fn mask(bound: &Mpz, cl: &ClParameters) -> Mpz {
    pow2(cl.lambda() + cl.lambda_d()) * bound.clone()
}

fn response(bound: &Mpz, cl: &ClParameters) -> Mpz {
    (pow2(cl.lambda() + cl.lambda_d()) + pow2(cl.lambda())) * bound.clone()
}

#[allow(clippy::too_many_arguments)]
fn aff_challenge(
    ctx: &[u8],
    aggregated: &Aggregated,
    proof_d1: &QFI,
    proof_d2: &QFI,
    b0: &G2,
    r0: &G2,
) -> Scalar255 {
    let mut transcript = Transcript::new(DOMAIN_AFF);
    transcript
        .absorb_bytes(b"ctx", ctx)
        .absorb_qfi(b"c1", &aggregated.gamma.c0)
        .absorb_qfi(b"c2", &aggregated.gamma.c1)
        .absorb_qfi(b"d1", &aggregated.alpha.c0)
        .absorb_qfi(b"d2", &aggregated.alpha.c1)
        .absorb_bytes(b"B", &aggregated.b.to_bytes())
        .absorb_bytes(b"R", &aggregated.x_point.to_bytes())
        .absorb_qfi(b"d1p", proof_d1)
        .absorb_qfi(b"d2p", proof_d2)
        .absorb_bytes(b"B0", &b0.to_bytes())
        .absorb_bytes(b"R0", &r0.to_bytes());
    Scalar255::from_be_bytes_mod_order(&transcript.digest32()[..16])
}

/// `Prove_{R^*}` with witness `(k^*, beta^*)`.
pub fn prove_aff(
    cl: &ClParameters,
    ctx: &[u8],
    aggregated: &Aggregated,
    k_star: &Mpz,
    beta_star: &Scalar255,
    rng: &mut RandGen,
    meter: &mut Meter,
) -> AffProof {
    let nonce_k = rng.random_mpz(&mask(&k_bound(cl), cl));
    let nonce_beta = rng.random_mpz(&mask(cl.modulus(), cl));

    let d1 = cl.exp(&aggregated.gamma.c0, &nonce_k, meter);
    let scaled = cl.exp(&aggregated.gamma.c1, &nonce_k, meter);
    let kernel = cl.invert(&cl.f_exp_mpz(&nonce_beta), meter);
    let d2 = cl.compose(&scaled, &kernel, meter);
    meter.add(Op::G2Exp);
    let b0 = threshold_bbs::bls381::generator_g2().scale(&mpz_to_scalar(&nonce_beta));
    let r0 = threshold_bbs::bls381::generator_g2().scale(&mpz_to_scalar(&nonce_k));

    let challenge = aff_challenge(ctx, aggregated, &d1, &d2, &b0, &r0);
    let challenge_int = scalar_to_mpz(&challenge);

    meter.add(Op::Prove);
    AffProof {
        d1,
        d2,
        b0,
        r0,
        response_k: nonce_k + challenge_int.clone() * k_star.clone(),
        response_beta: nonce_beta + challenge_int * scalar_to_mpz(beta_star),
        challenge,
    }
}

/// `Verify_{R^*}`.
pub fn verify_aff(
    cl: &ClParameters,
    ctx: &[u8],
    aggregated: &Aggregated,
    proof: &AffProof,
    meter: &mut Meter,
) -> bool {
    if !cl.is_form(&aggregated.gamma.c0)
        || !cl.is_form(&aggregated.gamma.c1)
        || !cl.is_form(&aggregated.alpha.c0)
        || !cl.is_form(&aggregated.alpha.c1)
    {
        return false;
    }
    if !lt(&proof.response_k, &response(&k_bound(cl), cl))
        || !lt(&proof.response_beta, &response(cl.modulus(), cl))
    {
        return false;
    }
    let negative = neg(&scalar_to_mpz(&proof.challenge));

    let d1 = cl.compose(
        &cl.exp(&aggregated.gamma.c0, &proof.response_k, meter),
        &cl.exp(&aggregated.alpha.c0, &negative, meter),
        meter,
    );
    let scaled = cl.exp(&aggregated.gamma.c1, &proof.response_k, meter);
    let kernel = cl.invert(&cl.f_exp_mpz(&proof.response_beta), meter);
    let sealed = cl.compose(&scaled, &kernel, meter);
    let corrective = cl.exp(&aggregated.alpha.c1, &negative, meter);
    let d2 = cl.compose(&sealed, &corrective, meter);

    let g2 = threshold_bbs::bls381::generator_g2();
    meter.add_n(Op::G2Exp, 2);
    let b0 = g2
        .scale(&mpz_to_scalar(&proof.response_beta))
        .combine(&aggregated.b.scale(&<Scalar255 as Scalar>::zero().sub(&proof.challenge)));
    let r0 = g2
        .scale(&mpz_to_scalar(&proof.response_k))
        .combine(&aggregated.x_point.scale(&<Scalar255 as Scalar>::zero().sub(&proof.challenge)));

    meter.add(Op::Verify);
    aff_challenge(ctx, aggregated, &d1, &d2, &b0, &r0) == proof.challenge
}

/// `S = C_gamma^{k^*} sample` — the affine operation itself, exposed for the signer.
pub fn aff_map(
    cl: &ClParameters,
    cipher: &Cipher,
    k_star: &Mpz,
    beta: &Scalar255,
    meter: &mut Meter,
) -> Cipher {
    let c0 = cl.exp(&cipher.c0, k_star, meter);
    let c1 = cl.exp(&cipher.c1, k_star, meter);
    let kernel = cl.invert(&cl.f_exp(beta), meter);
    let c1 = cl.compose(&c1, &kernel, meter);
    Cipher { c0, c1 }
}

/// `k^* = k + e q` with `e <- D_q`.
pub fn shift(k: &Scalar255, cl: &ClParameters, rng: &mut RandGen) -> Mpz {
    let shift = cl.sample_dq(rng);
    scalar_to_mpz(k) + mul(&shift, cl.modulus())
}
