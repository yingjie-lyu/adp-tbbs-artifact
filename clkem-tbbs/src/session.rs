//! Session drivers: key generation and signing over a [`crate::transport::Bus`].
//!
//! The drivers are the only place that knows the round schedule; parties themselves are
//! passive state machines ([`crate::keygen::KeygenParty`], [`crate::sign::SignParty`]) that
//! take messages in and produce messages out. Everything that crosses a party boundary is
//! encoded and decoded here, so the wire format is exercised on every run.

use std::collections::BTreeMap;
use std::sync::Arc;

use threshold_bbs::bls381::Scalar255;

use crate::bbs::{self, Signature};
use crate::error::{Error, Result};
use crate::keygen::{
    KeyPackage, KeygenCommitMsg, KeygenOpenMsg, KeygenParty, PvssMsg, SeedCommitMsg, SeedOpenMsg,
    ShareMsg,
};
use crate::params::PublicParameters;
use crate::sign::{SignCommitMsg, SignOpenMsg, SignParty, SignShareMsg};
use crate::stats::Meter;
use crate::transport::{Bus, Round};

pub struct KeygenOutcome {
    pub parties: BTreeMap<usize, KeyPackage>,
    pub bus: Bus,
}

/// Run the five key-generation rounds for `n` parties with threshold `t`.
pub fn run_keygen(
    pp: Arc<PublicParameters>,
    n: usize,
    t: usize,
    session: &[u8],
    meter: &mut Meter,
) -> Result<KeygenOutcome> {
    let ids: Vec<usize> = (1..=n).collect();
    let mut bus = Bus::new(&ids);
    let mut parties: BTreeMap<usize, KeygenParty> = BTreeMap::new();
    for id in &ids {
        parties.insert(*id, KeygenParty::new(pp.clone(), *id, n, t, session.to_vec()));
    }

    // Round 1: seed commitments.
    for id in &ids {
        let message = parties
            .get_mut(id)
            .ok_or(Error::Protocol("missing party"))?
            .seed_commit(meter);
        bus.publish(Round::SeedCommit, *id, message.encode())?;
    }
    // Round 2: seed openings.
    for id in &ids {
        let payloads = bus.broadcast(*id, Round::SeedCommit)?;
        let inbox = payloads
            .iter()
            .map(|envelope| SeedCommitMsg::decode(&envelope.payload))
            .collect::<Result<Vec<_>>>()?;
        let message = parties
            .get_mut(id)
            .ok_or(Error::Protocol("missing party"))?
            .seed_open(&inbox, meter)?;
        bus.publish(Round::SeedOpen, *id, message.encode())?;
    }
    // Pairwise seeds.
    for id in &ids {
        let payloads = bus.broadcast(*id, Round::SeedOpen)?;
        let inbox = payloads
            .iter()
            .map(|envelope| SeedOpenMsg::decode(&envelope.payload))
            .collect::<Result<Vec<_>>>()?;
        parties
            .get_mut(id)
            .ok_or(Error::Protocol("missing party"))?
            .absorb_seeds(&inbox)?;
    }

    // Round 3: PVSS deals, broadcast commitments plus private shares.
    for id in &ids {
        let (broadcast, shares) = parties
            .get_mut(id)
            .ok_or(Error::Protocol("missing party"))?
            .deal(meter);
        bus.publish(Round::Pvss, *id, broadcast.encode())?;
        for (recipient, share) in shares {
            bus.send_to(Round::Pvss, *id, recipient, share.encode())?;
        }
    }
    for id in &ids {
        let broadcasts = bus.broadcast(*id, Round::Pvss)?;
        let privates = bus.direct(*id, Round::Pvss)?;
        for envelope in &broadcasts {
            let message = PvssMsg::decode(&envelope.payload, &pp.cl)?;
            let share_envelope = privates
                .iter()
                .find(|candidate| candidate.from == message.id)
                .ok_or(Error::Missing("private share from a dealer"))?;
            let share = ShareMsg::decode(&share_envelope.payload)?;
            parties
                .get_mut(id)
                .ok_or(Error::Protocol("missing party"))?
                .accept_deal(&message, &share, meter)?;
        }
    }

    // Round 4: D_i, encapsulation, commitment.
    for id in &ids {
        let message = parties
            .get_mut(id)
            .ok_or(Error::Protocol("missing party"))?
            .keygen_commit(meter)?;
        bus.publish(Round::KeygenCommit, *id, message.encode())?;
    }
    // Round 5: open and prove R_enc.
    for id in &ids {
        let payloads = bus.broadcast(*id, Round::KeygenCommit)?;
        let inbox = payloads
            .iter()
            .map(|envelope| KeygenCommitMsg::decode(&envelope.payload, &pp.cl))
            .collect::<Result<Vec<_>>>()?;
        let message = parties
            .get_mut(id)
            .ok_or(Error::Protocol("missing party"))?
            .keygen_open(&inbox, meter)?;
        bus.publish(Round::KeygenOpen, *id, message.encode())?;
    }

    let mut packages = BTreeMap::new();
    for id in &ids {
        let payloads = bus.broadcast(*id, Round::KeygenOpen)?;
        let inbox = payloads
            .iter()
            .map(|envelope| KeygenOpenMsg::decode(&envelope.payload, &pp.cl))
            .collect::<Result<Vec<_>>>()?;
        let package = parties
            .get_mut(id)
            .ok_or(Error::Protocol("missing party"))?
            .finish(&inbox, meter)?;
        packages.insert(*id, package);
    }

    Ok(KeygenOutcome { parties: packages, bus })
}

pub struct SignOutcome {
    pub signature: Signature,
    pub quorum: Vec<usize>,
    pub bus: Bus,
}

/// Run the three signing rounds with the signers indexed by `quorum`.
pub fn run_signing(
    packages: &BTreeMap<usize, KeyPackage>,
    quorum: &[usize],
    message: &[Scalar255],
    session: &[u8],
    meter: &mut Meter,
) -> Result<SignOutcome> {
    if quorum.is_empty() {
        return Err(Error::Protocol("empty quorum"));
    }
    let mut ids = quorum.to_vec();
    ids.sort_unstable();
    ids.dedup();
    if ids.len() != quorum.len() {
        return Err(Error::Protocol("duplicate signer in the quorum"));
    }

    let mut bus = Bus::new(&ids);
    let mut parties: BTreeMap<usize, SignParty> = BTreeMap::new();
    for id in &ids {
        let package = packages
            .get(id)
            .ok_or(Error::Missing("key package for a signer"))?
            .clone();
        parties.insert(*id, SignParty::new(package, &ids, message, session)?);
    }

    for id in &ids {
        let message = parties
            .get_mut(id)
            .ok_or(Error::Protocol("missing signer"))?
            .commit(meter);
        bus.publish(Round::SignCommit, *id, message.encode())?;
    }
    for id in &ids {
        let payloads = bus.broadcast(*id, Round::SignCommit)?;
        let inbox = payloads
            .iter()
            .map(|envelope| SignCommitMsg::decode(&envelope.payload, &packages[&ids[0]].public.pp.cl))
            .collect::<Result<Vec<_>>>()?;
        let message = parties
            .get_mut(id)
            .ok_or(Error::Protocol("missing signer"))?
            .open(&inbox, meter)?;
        bus.publish(Round::SignOpen, *id, message.encode())?;
    }
    for id in &ids {
        let payloads = bus.broadcast(*id, Round::SignOpen)?;
        let inbox = payloads
            .iter()
            .map(|envelope| SignOpenMsg::decode(&envelope.payload))
            .collect::<Result<Vec<_>>>()?;
        let message = parties
            .get_mut(id)
            .ok_or(Error::Protocol("missing signer"))?
            .share(&inbox, meter)?;
        bus.publish(Round::SignShare, *id, message.encode())?;
    }

    let mut signature: Option<Signature> = None;
    for id in &ids {
        let payloads = bus.broadcast(*id, Round::SignShare)?;
        let inbox = payloads
            .iter()
            .map(|envelope| SignShareMsg::decode(&envelope.payload, &packages[&ids[0]].public.pp.cl))
            .collect::<Result<Vec<_>>>()?;
        let produced = parties
            .get_mut(id)
            .ok_or(Error::Protocol("missing signer"))?
            .combine(&inbox, meter)?;
        if let Some(first) = &signature {
            if *first != produced {
                return Err(Error::Protocol("signers derived different signatures"));
            }
        }
        signature = Some(produced);
    }

    Ok(SignOutcome {
        signature: signature.ok_or(Error::Protocol("no signature produced"))?,
        quorum: ids,
        bus,
    })
}

/// Verify a signature against a package's public key, as an outside verifier would.
pub fn verify(
    package: &KeyPackage,
    message: &[Scalar255],
    signature: &Signature,
) -> bool {
    let public = &package.public;
    bbs::verify(&public.pp, &public.bases, &public.x_g2, message, signature)
}
