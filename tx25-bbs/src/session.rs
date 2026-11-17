//! Session driver: two offline rounds, one online round, all over the wire format.

use std::collections::BTreeMap;

use tcl::meter::Meter;
use tcl::{Error, Result};

use threshold_bbs::bls381::Scalar255;

use crate::bbs::{self, Signature};
use crate::keys::Keys;
use crate::sign::{Offline1Msg, Offline2Msg, OnlineMsg, Signer};

pub struct SignOutcome {
    pub signature: Signature,
    pub quorum: Vec<usize>,
    /// Bytes per round, summed over signers.
    pub bytes: [usize; 3],
    pub per_party: BTreeMap<usize, usize>,
}

impl SignOutcome {
    pub fn total_bytes(&self) -> usize {
        self.bytes.iter().sum()
    }
}

pub fn run_signing(
    keys: &BTreeMap<usize, Keys>,
    parties: &[usize],
    message: &[Scalar255],
    session: &[u8],
    meter: &mut Meter,
) -> Result<SignOutcome> {
    let mut signers: BTreeMap<usize, Signer> = BTreeMap::new();
    for id in parties {
        let package = keys
            .get(id)
            .ok_or(Error::Missing("keys for a signer"))?
            .clone();
        signers.insert(*id, Signer::new(package));
    }
    let mut per_party: BTreeMap<usize, usize> = BTreeMap::new();
    let mut bytes = [0usize; 3];

    // Offline round 1
    let mut wire1 = Vec::new();
    for id in parties {
        let message = signers
            .get_mut(id)
            .ok_or(Error::Missing("signer"))?
            .offline1(session, meter)?;
        let encoded = message.encode();
        *per_party.entry(*id).or_insert(0) += encoded.len();
        bytes[0] += encoded.len();
        wire1.push(encoded);
    }

    // Offline round 2
    let mut wire2 = Vec::new();
    let mut quorums: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for id in parties {
        let cl = &keys[id].params.cl;
        let inbox = wire1
            .iter()
            .map(|encoded| Offline1Msg::decode(encoded, cl))
            .collect::<Result<Vec<_>>>()?;
        let mut view = parties.to_vec();
        let message = signers
            .get_mut(id)
            .ok_or(Error::Missing("signer"))?
            .offline2(session, &mut view, &inbox, meter)?;
        quorums.insert(*id, view);
        let encoded = message.encode();
        *per_party.entry(*id).or_insert(0) += encoded.len();
        bytes[1] += encoded.len();
        wire2.push(encoded);
    }

    // Offline output
    for id in parties {
        let cl = &keys[id].params.cl;
        let inbox = wire2
            .iter()
            .map(|encoded| Offline2Msg::decode(encoded, cl))
            .collect::<Result<Vec<_>>>()?;
        let first = wire1
            .iter()
            .map(|encoded| Offline1Msg::decode(encoded, cl))
            .collect::<Result<Vec<_>>>()?;
        let mut view = quorums
            .get(id)
            .cloned()
            .ok_or(Error::Protocol("no quorum recorded"))?;
        signers
            .get_mut(id)
            .ok_or(Error::Missing("signer"))?
            .offline_output(session, &mut view, &inbox, &first, meter)?;
        quorums.insert(*id, view);
    }

    // Online round
    let mut wire3 = Vec::new();
    for id in parties {
        let message = signers
            .get_mut(id)
            .ok_or(Error::Missing("signer"))?
            .online(message, session, meter)?;
        let encoded = message.encode();
        *per_party.entry(*id).or_insert(0) += encoded.len();
        bytes[2] += encoded.len();
        wire3.push(encoded);
    }

    // Output
    let mut signature: Option<Signature> = None;
    let mut quorum = Vec::new();
    for id in parties {
        let inbox = wire3
            .iter()
            .map(|encoded| OnlineMsg::decode(encoded))
            .collect::<Result<Vec<_>>>()?;
        let mut view = quorums
            .get(id)
            .cloned()
            .ok_or(Error::Protocol("no quorum recorded"))?;
        let produced = signers
            .get_mut(id)
            .ok_or(Error::Missing("signer"))?
            .output(message, session, &mut view, &inbox, meter)?;
        quorum = view;
        if let Some(first) = &signature {
            if *first != produced {
                return Err(Error::Protocol("signers derived different signatures"));
            }
        }
        signature = Some(produced);
    }
    let signature = signature.ok_or(Error::Protocol("no signature produced"))?;
    if !bbs::verify(
        &keys[&parties[0]].params.bases,
        &keys[&parties[0]].x_public,
        message,
        &signature,
    ) {
        return Err(Error::Verify("threshold signature"));
    }

    Ok(SignOutcome {
        signature,
        quorum,
        bytes,
        per_party,
    })
}
