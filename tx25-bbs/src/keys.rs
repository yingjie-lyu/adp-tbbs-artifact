//! Key material: the BBS+ key shared over `G_2`, and one CL key pair per party for the MtA.
//!
//! The paper's Figure 1 DKG delivers CL-encrypted shares with an `R_Sh`/`R_Dec-DL` proof
//! chain; here the `x` shares come from [`tcl::dkg_dl`]'s Feldman construction and every party
//! samples its own CL key pair, publishing `R_key` (`ek_j = g_q^{dk_j}`) as the paper's PKI
//! setup step does.

use std::collections::BTreeMap;
use std::sync::Arc;

use bicycl::{Mpz, QFI};

use tcl::cl::ClParameters;
use tcl::meter::{Meter, Op};
use tcl::random::fresh_rng;
use tcl::util::{lt, mul, neg};
use tcl::wire::{self, Reader};
use tcl::{Error, Result};

use threshold_bbs::bls381::{Scalar255, G2};
use threshold_bbs::hash::Transcript;
use threshold_bbs::util::{pow2, scalar_to_mpz};

use crate::params::PublicParameters;

pub const DOMAIN_KEY: &[u8] = b"tx25-bbs/v01/keygen/R-key";
pub const DKG: &[u8] = b"tx25-bbs/v01/keygen/dkg";

/// `R_key`: knowledge of `dk` with `ek = g_q^{dk}`.
#[derive(Clone, Debug)]
pub struct KeyProof {
    pub challenge: Scalar255,
    pub response: Mpz,
}

impl KeyProof {
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
}

fn mask_bound(cl: &ClParameters) -> Mpz {
    pow2(cl.lambda() + cl.lambda_d()) * cl.bound_dq().clone()
}

fn response_bound(cl: &ClParameters) -> Mpz {
    (pow2(cl.lambda() + cl.lambda_d()) + pow2(cl.lambda())) * cl.bound_dq().clone()
}

fn challenge(ctx: &[u8], ek: &QFI, commitment: &QFI) -> Scalar255 {
    let mut transcript = Transcript::new(DOMAIN_KEY);
    transcript
        .absorb_bytes(b"ctx", ctx)
        .absorb_qfi(b"ek", ek)
        .absorb_qfi(b"R", commitment);
    Scalar255::from_be_bytes_mod_order(&transcript.digest32()[..16])
}

pub fn prove_key(
    cl: &ClParameters,
    ctx: &[u8],
    ek: &QFI,
    dk: &Mpz,
    meter: &mut Meter,
) -> KeyProof {
    let mut rng = fresh_rng();
    let nonce = rng.random_mpz(&mask_bound(cl));
    let commitment = cl.exp(cl.gq(), &nonce, meter);
    let challenge = challenge(ctx, ek, &commitment);
    meter.add(Op::Prove);
    KeyProof {
        response: nonce + mul(&scalar_to_mpz(&challenge), dk),
        challenge,
    }
}

pub fn verify_key(
    cl: &ClParameters,
    ctx: &[u8],
    ek: &QFI,
    proof: &KeyProof,
    meter: &mut Meter,
) -> bool {
    if !cl.is_form(ek) || !lt(&proof.response, &response_bound(cl)) {
        return false;
    }
    let negative = neg(&scalar_to_mpz(&proof.challenge));
    let commitment = cl.compose(
        &cl.exp(cl.gq(), &proof.response, meter),
        &cl.exp(ek, &negative, meter),
        meter,
    );
    meter.add(Op::Verify);
    challenge(ctx, ek, &commitment) == proof.challenge
}

/// Everything one signer needs.
#[derive(Clone)]
pub struct Keys {
    pub params: Arc<PublicParameters>,
    pub party: usize,
    pub n: usize,
    pub t: usize,
    /// `x_i`, a `Z_q` Shamir share of the BBS+ signing key.
    pub x_share: Scalar255,
    pub x_public_share: G2,
    pub x_public: G2,
    pub all_x_public: BTreeMap<usize, G2>,
    /// This party's CL key pair, used as Alice in the MtA when holding a `C_gamma`.
    pub ek: QFI,
    pub dk: Mpz,
    pub all_ek: BTreeMap<usize, QFI>,
}

/// `(x, X)` over `G_2` plus one CL key pair per party with an `R_key` proof.
pub fn setup(
    params: Arc<PublicParameters>,
    parties: &[usize],
    t: usize,
    session: &[u8],
    meter: &mut Meter,
) -> Result<BTreeMap<usize, Keys>> {
    let cl = params.cl.clone();
    let shares = tcl::dkg_dl(
        &threshold_bbs::bls381::generator_g2(),
        parties,
        t,
        session,
        Op::G2Exp,
        meter,
    )?;

    let mut rng = fresh_rng();
    let mut pairs: BTreeMap<usize, (QFI, Mpz, KeyProof)> = BTreeMap::new();
    for id in parties {
        let dk = cl.sample_dq(&mut rng);
        let ek = cl.exp(cl.gq(), &dk, meter);
        let ctx = tcl::zkp::context(session, DKG, &[*id]);
        let proof = prove_key(&cl, &ctx, &ek, &dk, meter);
        pairs.insert(*id, (ek, dk, proof));
    }
    // Everyone verifies everyone: this is the PKI step.
    for id in parties {
        let ctx = tcl::zkp::context(session, DKG, &[*id]);
        let (ek, _, proof) = pairs
            .get(id)
            .ok_or(Error::Missing("CL key pair"))?;
        for _verifier in parties {
            if !verify_key(&cl, &ctx, ek, proof, meter) {
                return Err(Error::Verify("R_key for a CL public key"));
            }
        }
    }
    let all_ek: BTreeMap<usize, QFI> = pairs
        .iter()
        .map(|(id, (ek, _, _))| (*id, ek.clone()))
        .collect();

    let mut keys = BTreeMap::new();
    for id in parties {
        let (ek, dk, _) = pairs.get(id).ok_or(Error::Missing("CL key pair"))?.clone();
        let key = shares.get(id).ok_or(Error::Missing("BBS+ share"))?;
        keys.insert(
            *id,
            Keys {
                params: params.clone(),
                party: *id,
                n: parties.len(),
                t,
                x_share: key.share.clone(),
                x_public_share: key.public_share.clone(),
                x_public: key.public.clone(),
                all_x_public: key.all_public_shares.clone(),
                ek,
                dk,
                all_ek: all_ek.clone(),
            },
        );
    }
    Ok(keys)
}
