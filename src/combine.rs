//! `combine`: turn the round-2 shares into one BBS+ signature and check it.

use std::collections::BTreeMap;

use crate::algebra::{measure, Breakdown, Group, Operation, Phase, Scalar};
use crate::bbs::{self, Signature};
use crate::bls381::{Scalar255, G1};
use crate::error::{Error, Result};
use crate::keygen::PartyView;
use crate::params::PublicParameters;
use crate::round1::Round1Message;
use crate::round2::{self, Round2Message};

/// `u = sum_j u_j`, `S = prod_j S_j`, `A = S^{1/u}`, then `bbs.verify(pk, msg, (A,e,phi))`.
pub fn combine(
    pp: &PublicParameters,
    view: &PartyView,
    session: &[u8],
    message: &[Scalar255],
    quorum: &[usize],
    rounds1: &BTreeMap<usize, Round1Message>,
    rounds2: &BTreeMap<usize, Round2Message>,
    stats: &mut Breakdown,
) -> Result<Signature<G1>> {
    view.validate_quorum(quorum)?;

    let (_, e, phi, u_point) = stats.step(Phase::Round2Session, |_| {
        round2::session_values(pp, session, message, quorum, rounds1)
    })?;
    if e.is_zero() {
        return Err(Error::InvalidParameters("e = 0"));
    }
    if round2::is_identity(&u_point) {
        return Err(Error::InvalidParameters("U = 1"));
    }

    let signature = stats.step(Phase::CombineAggregate, |_| -> Result<Signature<G1>> {
        let mut u = Scalar255::zero();
        let mut s = G1::identity();
        for id in quorum {
            let round = rounds2.get(id).ok_or(Error::MissingRound2(*id))?;
            u = u.add(&round.u);
            s = s.combine(&round.s);
        }
        if u.is_zero() {
            return Err(Error::ZeroDenominator);
        }
        let inverse = u.invert().ok_or(Error::ZeroDenominator)?;
        Ok(Signature {
            a: s.scale(&inverse),
            e,
            phi,
        })
    })?;

    let valid = stats.step(Phase::CombineVerify, |s| {
        measure(s, Operation::Pairing, || {
            bbs::verify_with(pp, &view.public_key, message, &signature)
        })
    });

    if valid {
        Ok(signature)
    } else {
        Err(Error::InvalidSignature)
    }
}
