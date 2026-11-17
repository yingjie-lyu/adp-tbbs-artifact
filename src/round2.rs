//! Round 2 of the signing protocol (`sign`).
//!
//! Every party verifies all round-1 proofs, decodes the cross terms `mu_{i,j}` and
//! `nu_{j,i}` with the class-group NIM, interpolates the TVRF output `W`, reads `(e, phi)`
//! from `hashout`, and emits
//!
//! ```text
//! u_i = e*gamma_i + lambda_i*x_i*gamma_i + sum_{j != i} (mu_{i,j} + nu_{j,i})
//!       + sum_{j != i} hashu(seed_{i,j}, tr) * sgn(i - j)
//! S_i = U^{gamma_i} * prod_{j != i} hashS(seed_{i,j}, tr)^{sgn(i - j)}
//! ```
//!
//! `mu_{i,j}` is party `i`'s role-A share of `x_i * gamma_j` and `nu_{j,i}` is its role-B
//! share of `x_j * gamma_i`; each product is split across its two owners, so the shares only
//! combine into `gamma * (x + e)` once all quorum members contribute.

use std::collections::BTreeMap;

use crate::algebra::{Breakdown, Encodable, Group, Phase, Scalar};
use crate::bls381::{Scalar255, G1};
use crate::error::{Error, Result};
use crate::hash::{hashout, mask_group, mask_scalar, mask_sign, Transcript};
use crate::keygen::PartyView;
use crate::nim::{EncodedA, EncodedB};
use crate::params::PublicParameters;
use crate::round1::{self, PresignState, Round1Message};

#[derive(Clone, Debug)]
pub struct Round2Message {
    pub id: usize,
    pub u: Scalar255,
    pub s: G1,
}

pub fn is_identity(point: &G1) -> bool {
    point.to_bytes() == G1::identity().to_bytes()
}

/// `tr = (pk, sid, msg, Q, {pspm_j})`, hashed canonically. Two distinct recipient views
/// never share a mask input.
pub fn recipient_transcript(
    view: &PartyView,
    session: &[u8],
    message: &[u8],
    quorum: &[usize],
    rounds: &BTreeMap<usize, Round1Message>,
) -> [u8; 32] {
    let mut transcript = Transcript::new(b"threshold-bbs/v03/transcript");
    transcript
        .absorb_g2(b"pk", &view.public_key)
        .absorb_bytes(b"sid", session)
        .absorb_bytes(b"msg", message)
        .absorb_quorum(quorum);

    let mut sorted = quorum.to_vec();
    sorted.sort_unstable();
    for id in sorted {
        if let Some(round) = rounds.get(&id) {
            transcript
                .absorb_u64(b"party", id as u64)
                .absorb_g1(b"W", &round.vrf_share)
                .absorb_g1(b"Gamma", &round.gamma_commitment)
                .absorb_qfi(b"c0", &round.c0)
                .absorb_qfi(b"c1", &round.c1)
                .absorb_bytes(b"z_r", &crate::util::mpz_bytes(&round.proof.z_r))
                .absorb_bytes(b"c", &crate::util::mpz_bytes(&round.proof.challenge))
                .absorb_scalar(b"z_v", &round.proof.z_v)
                .absorb_scalar(b"z_s", &round.proof.z_s)
                .absorb_scalar(b"z_gamma", &round.proof.z_gamma)
                .absorb_scalar(b"z_rho", &round.proof.z_rho);
        }
    }
    transcript.digest32()
}

/// Recompute `(W, e, phi, U)` from public data. Both round 2 and combine need this, and
/// neither takes `(e, phi)` on faith from a caller.
pub fn session_values(
    pp: &PublicParameters,
    session: &[u8],
    message: &[Scalar255],
    quorum: &[usize],
    rounds: &BTreeMap<usize, Round1Message>,
) -> Result<(G1, Scalar255, Scalar255, G1)> {
    let message_bytes = pp.encode_message(message);
    let vrf_output = round1::interpolate_vrf(quorum, rounds)?;
    let (e, phi) = hashout(session, &message_bytes, quorum, &vrf_output);
    let u = pp.compute_u(&phi, message);
    Ok((vrf_output, e, phi, u))
}

/// Run `sign(sid, i, msg, Q, {pspm_j}, {pk_j}, sk_i, pst_i)` for one party.
pub fn sign_share(
    pp: &PublicParameters,
    view: &PartyView,
    session: &[u8],
    message: &[Scalar255],
    quorum: &[usize],
    rounds: &BTreeMap<usize, Round1Message>,
    state: &PresignState,
    stats: &mut Breakdown,
) -> Result<Round2Message> {
    view.validate_quorum(quorum)?;
    let id = view.id;
    let share = &view.share;

    // 1. Every *other* party's round-1 proof must verify before any share is released.
    //    Our own proof is not re-checked: the paper's loop is over `Q \ {i}`.
    for peer in quorum {
        if *peer == id {
            continue;
        }
        let round = rounds.get(peer).ok_or(Error::MissingRound1(*peer))?;
        let valid = stats.step(Phase::Round2Verify, |s| {
            round1::verify_round1(pp, view, session, message, quorum, round, s)
        });
        if !valid {
            return Err(Error::InvalidProof { from: *peer });
        }
    }

    // 2. Session values and the recipient transcript the masks are keyed by.
    let message_bytes = pp.encode_message(message);
    let ((_, e, _phi, u_point), transcript) = stats.step(Phase::Round2Session, |_| {
        let values = session_values(pp, session, message, quorum, rounds)?;
        let transcript = recipient_transcript(view, session, &message_bytes, quorum, rounds);
        Ok((values, transcript))
    })?;
    if e.is_zero() {
        return Err(Error::InvalidParameters(
            "e = 0, retry with another session",
        ));
    }
    if is_identity(&u_point) {
        return Err(Error::InvalidParameters("U = 1, retry with another nonce"));
    }

    let lambda_i = share.lagrange(quorum)?;

    // 3. Cross terms: role-A shares of x_i*gamma_j and role-B shares of x_j*gamma_i.
    let cross = stats.step(Phase::Round2Decode, |s| -> Result<Scalar255> {
        let mut cross = Scalar255::zero();
        for peer in quorum {
            if *peer == id {
                continue;
            }
            let round = rounds.get(peer).ok_or(Error::MissingRound1(*peer))?;
            let lambda_j = crate::shamir::lagrange_at_zero::<Scalar255>(*peer, quorum)
                .ok_or(Error::InvalidQuorum)?;

            let gamma_encoding = EncodedB {
                c0: round.c0.clone(),
                c1: round.c1.clone(),
                randomness: bicycl::Mpz::from(0u64),
            };
            let mu = pp
                .nim
                .decode_a(&gamma_encoding, &share.randomness_x, &share.x_i, s)
                .mul(&lambda_i);

            let x_public = view.public_share(*peer)?;
            let x_encoding = EncodedA {
                element: x_public.x_encoding.clone(),
                randomness: bicycl::Mpz::from(0u64),
            };
            let nu = pp
                .nim
                .decode_b(&x_encoding, &state.randomness_gamma, s)
                .mul(&lambda_j);

            cross = cross.add(&mu).add(&nu);
        }
        Ok(cross)
    })?;

    // 4. The unmasked share, then the pairwise masks keyed by the recipient transcript.
    let mut scalar_share = stats.step(Phase::Round2Assemble, |_| {
        e.mul(&state.gamma_i)
            .add(&lambda_i.mul(&share.x_i).mul(&state.gamma_i))
            .add(&cross)
    });
    let mut group_share = u_point.scale(&state.gamma_i);

    stats.step(Phase::Round2Masks, |_| {
        for peer in quorum {
            if *peer == id {
                continue;
            }
            let seed = share.seed_with(*peer).ok_or(Error::MissingSeed {
                from: id,
                to: *peer,
            })?;
            let sign = mask_sign(id, *peer);
            let scalar_mask = mask_scalar(seed, &transcript);
            scalar_share = if sign > 0 {
                scalar_share.add(&scalar_mask)
            } else {
                scalar_share.sub(&scalar_mask)
            };

            let group_mask = mask_group(seed, &transcript);
            group_share = if sign > 0 {
                group_share.combine(&group_mask)
            } else {
                group_share.combine(&group_mask.inverse())
            };
        }
        Ok::<(), Error>(())
    })?;

    Ok(Round2Message {
        id,
        u: scalar_share,
        s: group_share,
    })
}
