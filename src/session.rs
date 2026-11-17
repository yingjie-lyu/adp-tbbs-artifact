//! Session drivers.
//!
//! Two flavours, same protocol:
//!
//! * [`run_views`] passes typed messages between parties in one process. Useful for tests and
//!   for measuring the protocol itself.
//! * [`run_over_bus`] sends **only bytes** through a [`Bus`], so every message goes through
//!   [`crate::wire`]. This is the one that proves the wire format round-trips, and it is what
//!   a deployment would replace with a real transport.
//!
//! Both take [`PartyView`]s: a party never sees another party's secret share.
//!
//! Each `*_with` variant accepts a caller-owned [`Breakdown`], so a report can record
//! `setup` and `keygen` first and then run the session into the same profile.

use std::collections::BTreeMap;

use crate::algebra::{Breakdown, Phase};
use crate::bbs::Signature;
use crate::bls381::{Scalar255, G1};
use crate::combine::combine;
use crate::error::{Error, Result};
use crate::keygen::{KeyPackage, PartyView};
use crate::params::PublicParameters;
use crate::round1::{presign, PresignState, Round1Message};
use crate::round2::{sign_share, Round2Message};
use crate::transport::{Bus, Round};
use crate::wire;

#[derive(Debug)]
pub struct Session {
    pub signature: Signature<G1>,
    pub round1: BTreeMap<usize, Round1Message>,
    pub round2: BTreeMap<usize, Round2Message>,
    /// Payload bytes published in this session (zero for the typed driver).
    pub wire_bytes: usize,
    /// Snapshot of the profile for this session only.
    pub stats: Breakdown,
}

/// Convenience driver from the dealer's output: extracts a view per quorum member and runs
/// the typed path.
pub fn run(
    pp: &PublicParameters,
    pkg: &KeyPackage,
    session_id: &[u8],
    message: &[Scalar255],
    quorum: &[usize],
) -> Result<Session> {
    pkg.validate_quorum(quorum)?;
    let views = quorum
        .iter()
        .map(|id| pkg.party_view(*id))
        .collect::<Result<Vec<_>>>()?;
    run_views(pp, &views, session_id, message, quorum)
}

/// Typed in-process driver: no encoding, but no other party's secrets either.
pub fn run_views(
    pp: &PublicParameters,
    views: &[PartyView],
    session_id: &[u8],
    message: &[Scalar255],
    quorum: &[usize],
) -> Result<Session> {
    let mut stats = Breakdown::default();
    run_views_with(pp, views, session_id, message, quorum, &mut stats)
}

/// Typed driver that adds its profile to `stats`.
pub fn run_views_with(
    pp: &PublicParameters,
    views: &[PartyView],
    session_id: &[u8],
    message: &[Scalar255],
    quorum: &[usize],
    stats: &mut Breakdown,
) -> Result<Session> {
    let views = index_views(views, quorum)?;
    let mut session = stats.step(Phase::Session, |s| {
        run_typed(pp, &views, session_id, message, quorum, s)
    })?;
    session.stats = stats.clone();
    Ok(session)
}

/// Wire driver: parties publish bytes and read bytes.
pub fn run_over_bus(
    pp: &PublicParameters,
    views: &[PartyView],
    bus: &mut Bus,
    session_id: &[u8],
    message: &[Scalar255],
    quorum: &[usize],
) -> Result<Session> {
    let mut stats = Breakdown::default();
    run_over_bus_with(pp, views, bus, session_id, message, quorum, &mut stats)
}

/// Wire driver that adds its profile to `stats`.
pub fn run_over_bus_with(
    pp: &PublicParameters,
    views: &[PartyView],
    bus: &mut Bus,
    session_id: &[u8],
    message: &[Scalar255],
    quorum: &[usize],
    stats: &mut Breakdown,
) -> Result<Session> {
    let views = index_views(views, quorum)?;
    let mut session = stats.step(Phase::Session, |s| {
        run_wire(pp, &views, bus, session_id, message, quorum, s)
    })?;
    session.stats = stats.clone();
    Ok(session)
}

struct Parts {
    signature: Signature<G1>,
    round1: BTreeMap<usize, Round1Message>,
    round2: BTreeMap<usize, Round2Message>,
    wire_bytes: usize,
}

impl From<Parts> for Session {
    fn from(parts: Parts) -> Self {
        Self {
            signature: parts.signature,
            round1: parts.round1,
            round2: parts.round2,
            wire_bytes: parts.wire_bytes,
            stats: Breakdown::default(),
        }
    }
}

fn run_typed(
    pp: &PublicParameters,
    views: &BTreeMap<usize, &PartyView>,
    session_id: &[u8],
    message: &[Scalar255],
    quorum: &[usize],
    stats: &mut Breakdown,
) -> Result<Session> {
    let mut states: BTreeMap<usize, PresignState> = BTreeMap::new();
    let mut round1: BTreeMap<usize, Round1Message> = BTreeMap::new();
    for id in quorum {
        let view = views.get(id).ok_or(Error::MissingShare(*id))?;
        let (message_one, state) = presign(pp, view, session_id, message, quorum, stats)?;
        round1.insert(*id, message_one);
        states.insert(*id, state);
    }

    let mut round2: BTreeMap<usize, Round2Message> = BTreeMap::new();
    for id in quorum {
        let view = views.get(id).ok_or(Error::MissingShare(*id))?;
        let state = states.get(id).ok_or(Error::MissingShare(*id))?;
        let share = sign_share(pp, view, session_id, message, quorum, &round1, state, stats)?;
        round2.insert(*id, share);
    }

    let combiner = views.values().next().ok_or(Error::InvalidQuorum)?;
    let signature = combine(
        pp, combiner, session_id, message, quorum, &round1, &round2, stats,
    )?;
    Ok(Parts {
        signature,
        round1,
        round2,
        wire_bytes: 0,
    }
    .into())
}

fn run_wire(
    pp: &PublicParameters,
    views: &BTreeMap<usize, &PartyView>,
    bus: &mut Bus,
    session_id: &[u8],
    message: &[Scalar255],
    quorum: &[usize],
    stats: &mut Breakdown,
) -> Result<Session> {
    // Round 1: publish, then read what everyone else published.
    let mut states: BTreeMap<usize, PresignState> = BTreeMap::new();
    for id in quorum {
        let view = views.get(id).ok_or(Error::MissingShare(*id))?;
        let (round_one, state) = presign(pp, view, session_id, message, quorum, stats)?;
        let payload = stats.step(Phase::Wire, |_| {
            let mut payload = Vec::new();
            wire::encode_round1(&mut payload, &round_one, &pp.nim);
            payload
        });
        bus.publish(session_id, Round::One, *id, payload)?;
        states.insert(*id, state);
    }

    let mut round1: BTreeMap<usize, Round1Message> = BTreeMap::new();
    let mut round2: BTreeMap<usize, Round2Message> = BTreeMap::new();
    for id in quorum {
        let view = views.get(id).ok_or(Error::MissingShare(*id))?;
        let state = states.get(id).ok_or(Error::MissingShare(*id))?;

        let mut received: BTreeMap<usize, Round1Message> = BTreeMap::new();
        for envelope in bus.drain(*id, session_id, Round::One)? {
            let decoded = stats.step(Phase::Wire, |_| {
                wire::decode_round1(&envelope.payload, &pp.nim)
            })?;
            if decoded.id != envelope.from {
                return Err(Error::UnexpectedMessage("round-1 sender mismatch"));
            }
            received.insert(decoded.id, decoded);
        }
        if Some(id) == quorum.first() {
            round1 = received.clone();
        }

        let share = sign_share(
            pp, view, session_id, message, quorum, &received, state, stats,
        )?;
        let payload = stats.step(Phase::Wire, |_| {
            let mut payload = Vec::new();
            wire::encode_round2(&mut payload, &share);
            payload
        });
        bus.publish(session_id, Round::Two, *id, payload)?;
    }

    // Combine: whoever collects the round-2 shares.
    let combiner = views
        .get(quorum.first().ok_or(Error::InvalidQuorum)?)
        .ok_or(Error::InvalidQuorum)?;
    for envelope in bus.drain(combiner.id, session_id, Round::Two)? {
        let decoded = stats.step(Phase::Wire, |_| wire::decode_round2(&envelope.payload))?;
        if decoded.id != envelope.from {
            return Err(Error::UnexpectedMessage("round-2 sender mismatch"));
        }
        round2.insert(decoded.id, decoded);
    }

    let signature = combine(
        pp, combiner, session_id, message, quorum, &round1, &round2, stats,
    )?;
    let (_, _, wire_bytes) = bus.stats();
    Ok(Parts {
        signature,
        round1,
        round2,
        wire_bytes,
    }
    .into())
}

fn index_views<'a>(
    views: &'a [PartyView],
    quorum: &[usize],
) -> Result<BTreeMap<usize, &'a PartyView>> {
    let mut index = BTreeMap::new();
    for view in views {
        index.insert(view.id, view);
    }
    for id in quorum {
        if !index.contains_key(id) {
            return Err(Error::MissingShare(*id));
        }
    }
    Ok(index)
}
