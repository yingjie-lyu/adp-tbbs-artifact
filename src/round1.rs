//! Round 1 of the signing protocol (`presign`).
//!
//! Party `i` evaluates the dual-base threshold VRF on `(sid, msg, Q)`, publishes an
//! evaluation share `W_i = B_1^{v_i} B_2^{s~_i}`, a role-B NIM encoding of a fresh
//! `gamma_i`, a Pedersen commitment `Gamma_i = g_1^{gamma_i} hh^{rho_i}`, and a proof of
//! the five-line presigning relation.

use std::collections::BTreeMap;

use bicycl::Mpz;

use crate::algebra::{measure, Breakdown, Group, Operation, Phase};
use crate::bls381::{Scalar255, G1};
use crate::error::{Error, Result};
use crate::hash::hashvrf;
use crate::keygen::PartyView;
use crate::params::PublicParameters;
use crate::sigma::{self, Proof, Statement, Witness};

/// The round-1 message `pspm_i = (W_i, pe_{gamma,i}, Gamma_i, pi_i)`.
#[derive(Clone, Debug)]
pub struct Round1Message {
    pub id: usize,
    pub vrf_share: G1,
    pub gamma_commitment: G1,
    pub c0: bicycl::QFI,
    pub c1: bicycl::QFI,
    pub proof: Proof,
}

/// Private round-1 state needed to produce the round-2 share.
#[derive(Clone, Debug)]
pub struct PresignState {
    pub gamma_i: Scalar255,
    pub rho_i: Scalar255,
    pub randomness_gamma: Mpz,
}

/// Rebuild the statement a round-1 proof is supposed to prove.
pub fn statement_for(
    pp: &PublicParameters,
    view: &PartyView,
    session: &[u8],
    message: &[Scalar255],
    quorum: &[usize],
    round1: &Round1Message,
) -> Result<Statement> {
    let public_share = view.public_share(round1.id)?;
    let message_bytes = pp.encode_message(message);
    let (base_1, base_2) = hashvrf(session, &message_bytes, quorum);
    Ok(Statement {
        id: round1.id,
        session: session.to_vec(),
        message: message_bytes,
        quorum: quorum.to_vec(),
        base_1,
        base_2,
        vrf_commitment: public_share.vrf_commitment.clone(),
        vrf_share: round1.vrf_share.clone(),
        gamma_commitment: round1.gamma_commitment.clone(),
        c0: round1.c0.clone(),
        c1: round1.c1.clone(),
    })
}

/// Run `presign(sid, i, msg, Q)` for one party.
pub fn presign(
    pp: &PublicParameters,
    view: &PartyView,
    session: &[u8],
    message: &[Scalar255],
    quorum: &[usize],
    stats: &mut Breakdown,
) -> Result<(Round1Message, PresignState)> {
    view.validate_quorum(quorum)?;
    if message.len() != pp.message_bases.len() {
        return Err(Error::WrongMessageLength {
            expected: pp.message_bases.len(),
            actual: message.len(),
        });
    }

    let id = view.id;
    let share = &view.share;
    let message_bytes = pp.encode_message(message);
    let (base_1, base_2) = stats.step(Phase::Round1Hash, |_| {
        hashvrf(session, &message_bytes, quorum)
    });

    // W_i = B_1^{v_i} B_2^{s~_i} and Gamma_i. This is the only place the message enters
    // before a quorum speaks, which is what makes the TVRF output unpredictable.
    let mut rng = rand_core::OsRng;
    let gamma_i = Scalar255::random(&mut rng);
    let rho_i = Scalar255::random(&mut rng);
    let (vrf_share, gamma_commitment) = stats.step(Phase::Round1VrfShare, |s| {
        let share_point = measure(s, Operation::G1Exponentiation, || {
            base_1
                .scale(&share.v_i)
                .combine(&base_2.scale(&share.s_tilde_i))
        });
        let commitment = measure(s, Operation::G1Exponentiation, || {
            pp.g1.scale(&gamma_i).combine(&pp.hh.scale(&rho_i))
        });
        (share_point, commitment)
    });

    let encoded = stats.step(Phase::Round1EncodeB, |s| {
        pp.nim.encode_b(&gamma_i, &mut bicycl::RandGen::new(), s)
    });

    let statement = Statement {
        id,
        session: session.to_vec(),
        message: message_bytes,
        quorum: quorum.to_vec(),
        base_1,
        base_2,
        vrf_commitment: view.public_share(id)?.vrf_commitment.clone(),
        vrf_share: vrf_share.clone(),
        gamma_commitment: gamma_commitment.clone(),
        c0: encoded.c0.clone(),
        c1: encoded.c1.clone(),
    };
    let witness = Witness {
        v_i: share.v_i.clone(),
        s_tilde_i: share.s_tilde_i.clone(),
        gamma_i: gamma_i.clone(),
        rho_i: rho_i.clone(),
        randomness_gamma: encoded.randomness.clone(),
    };
    let proof = stats.step(Phase::Round1Proof, |s| {
        sigma::prove(pp, &statement, &witness, s)
    });

    Ok((
        Round1Message {
            id,
            vrf_share,
            gamma_commitment,
            c0: encoded.c0,
            c1: encoded.c1,
            proof,
        },
        PresignState {
            gamma_i,
            rho_i,
            randomness_gamma: encoded.randomness,
        },
    ))
}

/// Verify one round-1 message. Kept public so tests can tamper with it directly.
pub fn verify_round1(
    pp: &PublicParameters,
    view: &PartyView,
    session: &[u8],
    message: &[Scalar255],
    quorum: &[usize],
    round1: &Round1Message,
    stats: &mut Breakdown,
) -> bool {
    match statement_for(pp, view, session, message, quorum, round1) {
        Ok(statement) => sigma::verify(pp, &statement, &round1.proof, stats),
        Err(_) => false,
    }
}

/// Interpolate the session TVRF output `W = prod_j W_j^{lambda_j}`.
pub fn interpolate_vrf(quorum: &[usize], rounds: &BTreeMap<usize, Round1Message>) -> Result<G1> {
    let mut output = G1::identity();
    for id in quorum {
        let round = rounds.get(id).ok_or(Error::MissingRound1(*id))?;
        let lambda = crate::shamir::lagrange_at_zero::<Scalar255>(*id, quorum)
            .ok_or(Error::InvalidQuorum)?;
        output = output.combine(&round.vrf_share.scale(&lambda));
    }
    Ok(output)
}
