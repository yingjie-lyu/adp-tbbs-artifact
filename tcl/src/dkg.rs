//! Distribution of the three key pairs the threshold BBS+ protocols consume.
//!
//! Both papers invoke three DKGs before signing:
//!
//! * `EG.DKG` over `G_2` for the BBS+ key pair `(x, X = x G_2)`,
//! * `EG.DKG` over `G_1` for the threshold ElGamal key pair `(x̂, X̂ = x̂ G_1)`,
//! * `CL.DKG` for the threshold CL key pair `(k, g_q^{Delta^3 k})`,
//!
//! and then each party publishes a CL encryption of its BBS+ share with a proof, so that every
//! party ends up holding `C_x = CL.Enc(ek, x)`.
//!
//! The concrete protocol here is Feldman-style PVSS: the dealer broadcasts commitments to its
//! polynomial, sends the shares over private channels, and every recipient checks its share
//! against the commitments. WMC24's own DKG (rushing-resilient, delivering base-`q` encrypted
//! shares under each party's key, with dual-code verification and complaints) and ROBOT's
//! ideal functionalities `F_cldkg` / `F_egdkg` are *not* reproduced; see the crate docs.

use std::collections::BTreeMap;
use std::sync::Arc;

use bicycl::{Mpz, QFI};

use threshold_bbs::algebra::{Encodable, Group, Scalar};
use threshold_bbs::bls381::{Scalar255, G1, G2};

use crate::cl::{ClParameters, ThresholdCl};
use crate::error::{Error, Result};
use crate::meter::{Meter, Op};
use crate::random::fresh_rng;
use crate::share::{delta_lagrange, lagrange_scalar, Zss};
use crate::util::{add, index_pow, mul};
use crate::zkp;
use crate::zkp::EncStatement;

/// One party's view of a discrete-log key pair shared over `Z_q`.
#[derive(Clone, Debug)]
pub struct DlKey<G> {
    pub share: Scalar255,
    pub public_share: G,
    pub public: G,
    pub all_public_shares: BTreeMap<usize, G>,
}

/// One party's view of the threshold CL key.
#[derive(Clone, Debug)]
pub struct ClKey {
    /// `k_i`, a Z-SS share of `Delta k`.
    pub share: Mpz,
    /// `g_q^{k_i}`.
    pub public_share: QFI,
    /// `g_q^{Delta^3 k}`.
    pub public: QFI,
    pub all_public_shares: BTreeMap<usize, QFI>,
}

pub const DKG_DL: &[u8] = b"tcl/v01/dkg/dl";
pub const DKG_CL: &[u8] = b"tcl/v01/dkg/cl";
pub const DKG_X: &[u8] = b"tcl/v01/keys/x-enc";

/// Feldman DKG over a prime-order group `G` (`G_1` or `G_2`).
pub fn dkg_dl<G: Group<Scalar = Scalar255> + Encodable>(
    base: &G,
    parties: &[usize],
    t: usize,
    _session: &[u8],
    group_op: Op,
    meter: &mut Meter,
) -> Result<BTreeMap<usize, DlKey<G>>> {
    let n = parties.len();
    if t == 0 || t > n {
        return Err(Error::Protocol("threshold out of range"));
    }
    let mut rng = rand_core::OsRng;

    // (dealer, degree) -> commitment, and (dealer, recipient) -> share.
    let mut commitments: BTreeMap<(usize, usize), G> = BTreeMap::new();
    let mut shares: BTreeMap<(usize, usize), Scalar255> = BTreeMap::new();
    for dealer in parties {
        let mut coefficients = Vec::with_capacity(t);
        coefficients.push(Scalar255::random(&mut rng));
        for _ in 1..t {
            coefficients.push(Scalar255::random(&mut rng));
        }
        for (degree, coefficient) in coefficients.iter().enumerate() {
            meter.add(group_op);
            commitments.insert((*dealer, degree), base.scale(coefficient));
        }
        for (position, id) in parties.iter().enumerate() {
            shares.insert((*dealer, *id), crate::share::eval_scalar(&coefficients, *id));
            let _ = position;
        }
    }

    // Every recipient checks its share against the dealer's commitments.
    for recipient in parties {
        for dealer in parties {
            let share = shares
                .get(&(*dealer, *recipient))
                .ok_or(Error::Missing("share"))?;
            meter.add(group_op);
            let mut expected = commitments
                .get(&(*dealer, 0))
                .ok_or(Error::Missing("commitment"))?
                .clone();
            let point = Scalar255::from_u64(*recipient as u64);
            let mut power = point.clone();
            for degree in 1..t {
                expected = expected.combine(
                    &commitments
                        .get(&(*dealer, degree))
                        .ok_or(Error::Missing("commitment"))?
                        .scale(&power),
                );
                power = power.mul(&point);
            }
            if expected != base.scale(share) {
                return Err(Error::Verify("DKG share check"));
            }
        }
    }

    let mut public = G::identity();
    for dealer in parties {
        public = public.combine(
            commitments
                .get(&(*dealer, 0))
                .ok_or(Error::Missing("commitment"))?,
        );
    }

    // The global share of every party, so each signer holds the whole `X_j` vector.
    let mut global: BTreeMap<usize, Scalar255> = BTreeMap::new();
    for recipient in parties {
        let mut share = <Scalar255 as Scalar>::zero();
        for dealer in parties {
            share = share.add(
                shares
                    .get(&(*dealer, *recipient))
                    .ok_or(Error::Missing("share"))?,
            );
        }
        global.insert(*recipient, share);
    }
    let all_public: BTreeMap<usize, G> = global
        .iter()
        .map(|(id, share)| (*id, base.scale(share)))
        .collect();

    let mut keys = BTreeMap::new();
    for recipient in parties {
        let share = global
            .get(recipient)
            .ok_or(Error::Missing("share"))?
            .clone();
        keys.insert(
            *recipient,
            DlKey {
                share: share.clone(),
                public_share: all_public[recipient].clone(),
                public: public.clone(),
                all_public_shares: all_public.clone(),
            },
        );
    }
    Ok(keys)
}

/// Feldman-style DKG for the threshold CL key, with Z-SS integer shares.
pub fn dkg_cl(
    cl: Arc<ClParameters>,
    parties: &[usize],
    t: usize,
    meter: &mut Meter,
) -> Result<(Zss, BTreeMap<usize, ClKey>)> {
    let n = parties.len();
    if t == 0 || t > n {
        return Err(Error::Protocol("threshold out of range"));
    }
    let mut rng = fresh_rng();
    let zss = Zss::new(n, t, crate::util::bits(cl.bound_dq()), cl.lambda_d());
    let delta = zss.delta.clone();

    let mut commitments: BTreeMap<(usize, usize), QFI> = BTreeMap::new();
    let mut shares: BTreeMap<(usize, usize), Mpz> = BTreeMap::new();
    for dealer in parties {
        let contribution = cl.sample_dq(&mut rng);
        let coefficients = zss.coefficients(t, &mut rng);
        let poly = zss.shares_from(&contribution, &coefficients, n);
        // C_{i,0} = g_q^{Delta k_i}, C_{i,d} = g_q^{a_d}.
        commitments.insert(
            (*dealer, 0),
            cl.exp(cl.gq(), &mul(&delta, &contribution), meter),
        );
        for (degree, coefficient) in coefficients.iter().enumerate() {
            commitments.insert((*dealer, degree + 1), cl.exp(cl.gq(), coefficient, meter));
        }
        for (position, share) in poly.iter().enumerate() {
            shares.insert((*dealer, parties[position]), share.clone());
        }
    }

    // g_q^{share} == C_{i,0} * prod_d C_{i,d}^{j^d}
    for recipient in parties {
        for dealer in parties {
            let share = shares
                .get(&(*dealer, *recipient))
                .ok_or(Error::Missing("share"))?;
            let mut expected = commitments[&(*dealer, 0)].clone();
            for degree in 1..t {
                expected = cl.compose(
                    &expected,
                    &cl.exp(&commitments[&(*dealer, degree)], &index_pow(*recipient, degree), meter),
                    meter,
                );
            }
            if expected != cl.exp(cl.gq(), share, meter) {
                return Err(Error::Verify("DKG-CL share check"));
            }
        }
    }

    // g_q^{Delta^3 k} = prod_j pk_j^{Delta L_j} over the full party set.
    let mut public_shares = BTreeMap::new();
    for recipient in parties {
        let mut value = cl.identity().clone();
        for dealer in parties {
            let mut term = commitments[&(*dealer, 0)].clone();
            for degree in 1..t {
                term = cl.compose(
                    &term,
                    &cl.exp(&commitments[&(*dealer, degree)], &index_pow(*recipient, degree), meter),
                    meter,
                );
            }
            value = cl.compose(&value, &term, meter);
        }
        // `pk_i = g_q^{Delta k_i}`: the paper's public share is the *lifted* one, which is what
        // the partial-decryption relation `pk_i = (g_q^Delta)^{k_i}` needs.
        public_shares.insert(*recipient, cl.exp(&value, &delta, meter));
    }
    let mut public = cl.identity().clone();
    for (id, share) in &public_shares {
        public = cl.compose(
            &public,
            &cl.exp(share, &delta_lagrange(&delta, *id, parties), meter),
            meter,
        );
    }

    let mut keys = BTreeMap::new();
    for recipient in parties {
        let mut share = Mpz::from(0u64);
        for dealer in parties {
            share = add(&share, &shares[&(*dealer, *recipient)]);
        }
        keys.insert(
            *recipient,
            ClKey {
                share,
                public_share: public_shares[&recipient].clone(),
                public: public.clone(),
                all_public_shares: public_shares.clone(),
            },
        );
    }
    Ok((zss, keys))
}

/// Everything one signer needs: the three keys plus `C_x`, the CL encryption of the BBS+ key.
#[derive(Clone)]
pub struct ThresholdKeys {
    pub tc: ThresholdCl,
    pub party: usize,
    pub n: usize,
    pub t: usize,
    /// `Delta^3 k`'s group element, i.e. `clek`.
    pub cl_public: QFI,
    /// `k_i`, the Z-SS share of `Delta k`.
    pub cl_share: Mpz,
    /// `g_q^{k_i}`.
    pub cl_public_share: QFI,
    pub cl_public_shares: BTreeMap<usize, QFI>,
    /// `x_i`, a `Z_q` Shamir share of the BBS+ key.
    pub x_share: Scalar255,
    pub x_public_share: G2,
    pub x_public: G2,
    pub x_public_shares: BTreeMap<usize, G2>,
    /// `CL.Enc(clek, x)`, aggregated with the plain Lagrange coefficients.
    pub c_x: crate::cl::Cipher,
    /// `x̂_i`, the ElGamal share, and `X̂`.
    pub eg_share: Scalar255,
    pub eg_public_share: G1,
    pub eg_public: G1,
    pub eg_public_shares: BTreeMap<usize, G1>,
}

/// Run the three DKGs and aggregate `C_x`.
pub fn setup(
    cl: Arc<ClParameters>,
    parties: &[usize],
    t: usize,
    session: &[u8],
    meter: &mut Meter,
) -> Result<BTreeMap<usize, ThresholdKeys>> {
    let n = parties.len();
    let tc = ThresholdCl::new(cl.clone(), n, t, meter);

    let x_keys = dkg_dl(
        &threshold_bbs::bls381::generator_g2(),
        parties,
        t,
        session,
        Op::G2Exp,
        meter,
    )?;
    let eg_keys = dkg_dl(
        &threshold_bbs::bls381::generator_g1(),
        parties,
        t,
        session,
        Op::G1Exp,
        meter,
    )?;
    let (_zss, cl_keys) = dkg_cl(cl.clone(), parties, t, meter)?;

    let mut rng = fresh_rng();
    // Each party encrypts its BBS+ share and proves plaintext consistency; every party
    // verifies every proof, which is also what decides the aggregation set.
    let mut ciphertexts: BTreeMap<usize, crate::cl::Cipher> = BTreeMap::new();
    for id in parties {
        let rho = cl.sample_dq(&mut rng);
        let cipher = tc.enc(&cl_keys[id].public, &x_keys[id].share, &rho, meter);
        let ctx = zkp::context(session, DKG_X, &[*id]);
        let statement = EncStatement {
            ek: &cl_keys[id].public,
            cipher: &cipher,
            point: Some(&x_keys[id].public_share),
        };
        let proof = zkp::prove_enc(
            &tc,
            &ctx,
            &statement,
            &x_keys[id].share,
            &rho,
            &mut rng,
            meter,
        );
        for _verifier in parties {
            if !zkp::verify_enc(&tc, &ctx, &statement, &proof, meter) {
                return Err(Error::Verify("R_cldl for C_x"));
            }
        }
        ciphertexts.insert(*id, cipher);
    }

    // C_x = sum_{j valid} CL.SMul^*(L_j, C_{x_j}).
    let weights: Vec<Scalar255> = parties
        .iter()
        .map(|id| lagrange_scalar(*id, parties))
        .collect();
    let scaled: Vec<crate::cl::Cipher> = parties
        .iter()
        .zip(&weights)
        .map(|(id, weight)| tc.smul_star(weight, &ciphertexts[id], meter))
        .collect();
    let c_x = tc.add_many(&scaled, meter);

    let mut keys = BTreeMap::new();
    for id in parties {
        keys.insert(
            *id,
            ThresholdKeys {
                tc: tc.clone(),
                party: *id,
                n,
                t,
                cl_public: cl_keys[id].public.clone(),
                cl_share: cl_keys[id].share.clone(),
                cl_public_share: cl_keys[id].public_share.clone(),
                cl_public_shares: cl_keys[id].all_public_shares.clone(),
                x_share: x_keys[id].share.clone(),
                x_public_share: x_keys[id].public_share.clone(),
                x_public: x_keys[id].public.clone(),
                x_public_shares: x_keys[id].all_public_shares.clone(),
                c_x: c_x.clone(),
                eg_share: eg_keys[id].share.clone(),
                eg_public_share: eg_keys[id].public_share.clone(),
                eg_public: eg_keys[id].public.clone(),
                eg_public_shares: eg_keys[id].all_public_shares.clone(),
            },
        );
    }
    Ok(keys)
}
