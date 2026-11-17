//! `keygen(t, n)`.
//!
//! Four random degree-`(t-1)` polynomials over `Z_q` — `x`, `s`, `v`, `s~` — with
//! `s(0) = 0` in a real execution, so `pk = g_2^{x(0)}`. Party `i` receives
//! `(x_i, s_i, v_i, s~_i)`, publishes `X_i = g_2^{x_i} h_2^{s_i}`, `Y_i = g_1^{v_i} h_1^{s~_i}`
//! and a role-A NIM encoding of `x_i`, and shares a seed with every other party.

use std::collections::BTreeMap;

use bicycl::{Mpz, RandGen, QFI};
use rand_core::{OsRng, RngCore};

use crate::algebra::{Breakdown, Group, Phase, Scalar};
use crate::bls381::{Scalar255, G1, G2};
use crate::error::{Error, Result};
use crate::params::PublicParameters;
use crate::shamir::{evaluate_at, lagrange_at_zero};

pub const SEED_LEN: usize = 32;

#[derive(Clone, Debug)]
pub struct PairwiseSeed {
    pub peer: usize,
    pub seed: [u8; SEED_LEN],
}

/// Party `i`'s secret state.
#[derive(Clone, Debug)]
pub struct KeyShare {
    pub id: usize,
    pub x_i: Scalar255,
    pub s_i: Scalar255,
    pub v_i: Scalar255,
    pub s_tilde_i: Scalar255,
    /// Role-A coins `r_{x,i}` for the encoding of `x_i`; kept for `decode_A` in round 2.
    pub randomness_x: Mpz,
    pub x_encoding: QFI,
    pub seeds: Vec<PairwiseSeed>,
}

impl KeyShare {
    pub fn seed_with(&self, peer: usize) -> Option<&[u8; SEED_LEN]> {
        self.seeds
            .iter()
            .find(|candidate| candidate.peer == peer)
            .map(|candidate| &candidate.seed)
    }

    /// `lambda_{i,Q}` for this party in the given quorum.
    pub fn lagrange(&self, quorum: &[usize]) -> Result<Scalar255> {
        lagrange_at_zero::<Scalar255>(self.id, quorum).ok_or(Error::InvalidQuorum)
    }
}

#[derive(Clone, Debug)]
pub struct PublicShare {
    pub id: usize,
    /// `X_i = g_2^{x_i} h_2^{s_i}`.
    pub x_commitment: G2,
    /// `Y_i = g_1^{v_i} h_1^{s~_i}`.
    pub vrf_commitment: G1,
    /// Role-A NIM encoding `pe_{x,i}`.
    pub x_encoding: QFI,
}

#[derive(Clone, Debug)]
pub struct KeyPackage {
    pub threshold: usize,
    pub parties: usize,
    /// `pk = g_2^{x(0)}`.
    pub public_key: G2,
    pub public_shares: BTreeMap<usize, PublicShare>,
    pub secret_shares: BTreeMap<usize, KeyShare>,
}

/// Everything one party is allowed to know.
///
/// The dealer output [`KeyPackage`] holds every secret share; a deployed party only ever sees
/// its own. Round 1, round 2 and combine all take a `PartyView`, so no code path can
/// accidentally use another party's secrets.
#[derive(Clone, Debug)]
pub struct PartyView {
    pub id: usize,
    pub threshold: usize,
    pub public_key: G2,
    pub public_shares: BTreeMap<usize, PublicShare>,
    pub share: KeyShare,
}

impl PartyView {
    pub fn validate_quorum(&self, quorum: &[usize]) -> Result<()> {
        if quorum.len() < self.threshold || !quorum.contains(&self.id) {
            return Err(Error::InvalidQuorum);
        }
        if quorum.iter().any(|id| !self.public_shares.contains_key(id)) {
            return Err(Error::InvalidQuorum);
        }
        let mut sorted = quorum.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        if sorted.len() != quorum.len() {
            return Err(Error::InvalidQuorum);
        }
        Ok(())
    }

    pub fn public_share(&self, id: usize) -> Result<&PublicShare> {
        self.public_shares.get(&id).ok_or(Error::MissingShare(id))
    }
}

impl KeyPackage {
    /// Extract the view of one party. Everything else stays with the dealer.
    pub fn party_view(&self, id: usize) -> Result<PartyView> {
        let share = self.secret_shares.get(&id).ok_or(Error::MissingShare(id))?;
        Ok(PartyView {
            id,
            threshold: self.threshold,
            public_key: self.public_key.clone(),
            public_shares: self.public_shares.clone(),
            share: share.clone(),
        })
    }

    pub fn share(&self, id: usize) -> Result<&KeyShare> {
        self.secret_shares.get(&id).ok_or(Error::MissingShare(id))
    }

    pub fn public_share(&self, id: usize) -> Result<&PublicShare> {
        self.public_shares.get(&id).ok_or(Error::MissingShare(id))
    }

    pub fn validate_quorum(&self, quorum: &[usize]) -> Result<()> {
        if quorum.len() < self.threshold {
            return Err(Error::InvalidQuorum);
        }
        if quorum.iter().any(|id| !self.secret_shares.contains_key(id)) {
            return Err(Error::InvalidQuorum);
        }
        let mut sorted = quorum.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        if sorted.len() != quorum.len() {
            return Err(Error::InvalidQuorum);
        }
        Ok(())
    }
}

pub fn keygen(pp: &PublicParameters, threshold: usize, parties: usize) -> Result<KeyPackage> {
    keygen_with_stats(pp, threshold, parties, &mut Breakdown::default())
}

/// `keygen` that records its cost into `stats`.
pub fn keygen_with_stats(
    pp: &PublicParameters,
    threshold: usize,
    parties: usize,
    stats: &mut Breakdown,
) -> Result<KeyPackage> {
    stats.step(Phase::Keygen, |s| keygen_inner(pp, threshold, parties, s))
}

fn keygen_inner(
    pp: &PublicParameters,
    threshold: usize,
    parties: usize,
    stats: &mut Breakdown,
) -> Result<KeyPackage> {
    if threshold == 0 || threshold > parties {
        return Err(Error::InvalidParameters("need 1 <= t <= n"));
    }

    let mut rng = OsRng;
    let mut sample = |zero: bool| -> Vec<Scalar255> {
        (0..threshold)
            .map(|index| {
                if zero && index == 0 {
                    Scalar255::zero()
                } else {
                    Scalar255::random(&mut rng)
                }
            })
            .collect()
    };

    // s(0) = 0 in a real execution; the pad is the handle used in the adaptive proof.
    let x_coefficients = sample(false);
    let s_coefficients = sample(true);
    let v_coefficients = sample(false);
    let s_tilde_coefficients = sample(false);

    let mut seeds: BTreeMap<(usize, usize), [u8; SEED_LEN]> = BTreeMap::new();
    for low in 1..=parties {
        for high in low + 1..=parties {
            let mut seed = [0u8; SEED_LEN];
            rng.fill_bytes(&mut seed);
            seeds.insert((low, high), seed);
        }
    }

    let public_key = pp.g2.scale(&x_coefficients[0]);
    let mut class_rng = RandGen::new();
    let mut secret_shares = BTreeMap::new();
    let mut public_shares = BTreeMap::new();

    for id in 1..=parties {
        let x_i = evaluate_at(&x_coefficients, id);
        let s_i = evaluate_at(&s_coefficients, id);
        let v_i = evaluate_at(&v_coefficients, id);
        let s_tilde_i = evaluate_at(&s_tilde_coefficients, id);

        let x_commitment = pp.g2.scale(&x_i).combine(&pp.h2.scale(&s_i));
        let vrf_commitment = pp.g1.scale(&v_i).combine(&pp.h1.scale(&s_tilde_i));

        let encoded = pp.nim.encode_a(&x_i, &mut class_rng, stats);

        let mut party_seeds = Vec::with_capacity(parties.saturating_sub(1));
        for peer in 1..=parties {
            if peer == id {
                continue;
            }
            let key = (id.min(peer), id.max(peer));
            let seed = *seeds
                .get(&key)
                .ok_or(Error::MissingSeed { from: id, to: peer })?;
            party_seeds.push(PairwiseSeed { peer, seed });
        }

        public_shares.insert(
            id,
            PublicShare {
                id,
                x_commitment,
                vrf_commitment,
                x_encoding: encoded.element.clone(),
            },
        );
        secret_shares.insert(
            id,
            KeyShare {
                id,
                x_i,
                s_i,
                v_i,
                s_tilde_i,
                randomness_x: encoded.randomness,
                x_encoding: encoded.element,
                seeds: party_seeds,
            },
        );
    }

    Ok(KeyPackage {
        threshold,
        parties,
        public_key,
        public_shares,
        secret_shares,
    })
}
