//! The zero-sharing functionality `F_zero` (paper §2.5, following DKL+23).
//!
//! One-time setup: every pair `(P_i, P_j)` agrees on a seed `beta_{i,j}` by commit and
//! release. Sampling: for a quorum `T`,
//!
//! ```text
//! alpha_i = sum_{i<j in T} H(cnt_{i,j}, beta_{i,j}) - sum_{i>j in T} H(cnt_{i,j}, beta_{j,i})
//! ```
//!
//! so `sum_{i in T} alpha_i = 0` and the individual `alpha_i` look uniform. Round 3 of
//! signing uses `alpha_i` to re-randomise `pd_i`: without it a partial decryption is a
//! deterministic function of the honest party's view, which the simulator cannot produce.
//!
//! The counter is part of the hash input. Callers that sign more than once under the same
//! session id must advance it; [`Seeds::sample`] takes it as an argument so that reuse is
//! visible at the call site instead of silently repeating a mask.

use std::collections::BTreeMap;

use threshold_bbs::algebra::Scalar;
use threshold_bbs::bls381::Scalar255;
use threshold_bbs::hash::Transcript;

use crate::error::{Error, Result};

pub const DOMAIN_SEED: &[u8] = b"clkem-tbbs/v01/zero/seed";
pub const DOMAIN_MASK: &[u8] = b"clkem-tbbs/v01/zero/mask";

/// Pairwise seeds `beta_{i,j}`, ordered so that `(i, j)` and `(j, i)` name the same entry.
#[derive(Clone, Debug, Default)]
pub struct Seeds {
    values: BTreeMap<(usize, usize), [u8; 32]>,
}

impl Seeds {
    /// `beta_{i,j} = H(beta_i, beta_j, i, j)` with the pair sorted.
    pub fn pair(id: usize, contribution: &[u8; 32], peer: usize, peer_contribution: &[u8; 32]) -> [u8; 32] {
        let (low, high, low_share, high_share) = if id < peer {
            (id, peer, contribution, peer_contribution)
        } else {
            (peer, id, peer_contribution, contribution)
        };
        let mut transcript = Transcript::new(DOMAIN_SEED);
        transcript
            .absorb_u64(b"i", low as u64)
            .absorb_u64(b"j", high as u64)
            .absorb_bytes(b"beta_i", low_share)
            .absorb_bytes(b"beta_j", high_share);
        transcript.digest32()
    }

    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, id: usize, peer: usize, seed: [u8; 32]) {
        let key = if id < peer { (id, peer) } else { (peer, id) };
        self.values.insert(key, seed);
    }

    pub fn get(&self, id: usize, peer: usize) -> Option<&[u8; 32]> {
        let key = if id < peer { (id, peer) } else { (peer, id) };
        self.values.get(&key)
    }

    /// Build my view of the pairwise seeds from every party's opened contribution.
    pub fn from_contributions(
        id: usize,
        contributions: &BTreeMap<usize, [u8; 32]>,
    ) -> Result<Self> {
        let mine = *contributions
            .get(&id)
            .ok_or(Error::Missing("seed contribution missing"))?;
        let mut seeds = Seeds::new();
        for (peer, contribution) in contributions {
            if *peer == id {
                continue;
            }
            seeds.insert(id, *peer, Seeds::pair(id, &mine, *peer, contribution));
        }
        Ok(seeds)
    }

    /// `alpha_i` for this signing session. The quorum's `alpha` values sum to zero.
    pub fn sample(&self, id: usize, quorum: &[usize], session: &[u8], counter: u64) -> Result<Scalar255> {
        let zero = Scalar255::from_u64(0);
        let mut total = zero.clone();

        for &peer in quorum {
            if peer == id {
                continue;
            }
            let seed = self
                .get(id, peer)
                .ok_or(Error::Missing("pairwise seed missing"))?;
            // The hash is keyed on the *sorted* pair, so both sides of a pair compute the
            // same value and the `+`/`-` assignment makes the quorum sum vanish.
            let (low, high) = if id < peer { (id, peer) } else { (peer, id) };
            let contribution = mask(seed, low, high, session, counter);
            total = if id < peer {
                total.add(&contribution)
            } else {
                total.sub(&contribution)
            };
        }
        Ok(total)
    }
}

fn mask(seed: &[u8; 32], low: usize, high: usize, session: &[u8], counter: u64) -> Scalar255 {
    let mut transcript = Transcript::new(DOMAIN_MASK);
    transcript
        .absorb_bytes(b"sid", session)
        .absorb_u64(b"i", low as u64)
        .absorb_u64(b"j", high as u64)
        .absorb_u64(b"cnt", counter)
        .absorb_bytes(b"seed", seed);
    // The crate-private `Transcript::challenge_scalar` in `threshold-bbs` was removed once the
    // parent crate stopped using it; this is the same derivation, kept local to the one caller.
    Scalar255::from_be_bytes_mod_order(&transcript.digest())
}
