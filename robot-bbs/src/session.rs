//! Session driver: two rounds, every message crossing the byte boundary.

use std::collections::BTreeMap;
use std::sync::Arc;

use tcl::meter::Meter;
use tcl::{Error, Result, ThresholdKeys};

use threshold_bbs::bls381::Scalar255;

use crate::bbs::{Bases, PublicParameters, Signature};
use crate::sign::{Round1Msg, Round2Msg, Signer};

pub struct SignOutcome {
    pub signature: Signature,
    pub quorum: Vec<usize>,
    pub bytes_round1: usize,
    pub bytes_round2: usize,
    /// Bytes each signer puts on the wire, indexed by party.
    pub per_party: BTreeMap<usize, usize>,
}

impl SignOutcome {
    pub fn total_bytes(&self) -> usize {
        self.bytes_round1 + self.bytes_round2
    }
}

/// Run one signing session over the signer set `quorum`.
pub fn run_signing(
    keys: &BTreeMap<usize, ThresholdKeys>,
    bases: &Bases,
    params: Arc<PublicParameters>,
    quorum: &[usize],
    message: &[Scalar255],
    session: &[u8],
    meter: &mut Meter,
) -> Result<SignOutcome> {
    if quorum.is_empty() {
        return Err(Error::Protocol("empty quorum"));
    }
    let mut signers: BTreeMap<usize, Signer> = BTreeMap::new();
    for id in quorum {
        let package = keys
            .get(id)
            .ok_or(Error::Missing("key package for a signer"))?
            .clone();
        signers.insert(*id, Signer::new(package, bases.clone(), params.clone()));
    }

    let mut per_party: BTreeMap<usize, usize> = BTreeMap::new();
    let mut round1_wire: Vec<Vec<u8>> = Vec::new();
    for id in quorum {
        let produced = signers
            .get_mut(id)
            .ok_or(Error::Missing("signer"))?
            .round1(message, session, meter)?;
        let bytes = produced.encode();
        *per_party.entry(*id).or_insert(0) += bytes.len();
        round1_wire.push(bytes);
    }
    let bytes_round1: usize = round1_wire.iter().map(|bytes| bytes.len()).sum();

    let mut round2_wire: Vec<Vec<u8>> = Vec::new();
    let mut quorums: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for id in quorum {
        let inbox = round1_wire
            .iter()
            .map(|bytes| Round1Msg::decode(bytes, &keys[id].tc.cl))
            .collect::<Result<Vec<_>>>()?;
        let mut view = quorum.to_vec();
        let produced = signers
            .get_mut(id)
            .ok_or(Error::Missing("signer"))?
            .round2(message, session, &mut view, &inbox, meter)?;
        quorums.insert(*id, view);
        let bytes = produced.encode();
        *per_party.entry(*id).or_insert(0) += bytes.len();
        round2_wire.push(bytes);
    }
    let bytes_round2: usize = round2_wire.iter().map(|bytes| bytes.len()).sum();

    let mut signature: Option<Signature> = None;
    for id in quorum {
        let inbox = round2_wire
            .iter()
            .map(|bytes| Round2Msg::decode(bytes, &keys[id].tc.cl))
            .collect::<Result<Vec<_>>>()?;
        let produced = signers
            .get_mut(id)
            .ok_or(Error::Missing("signer"))?
            .output(message, session, &inbox, meter)?;
        if let Some(first) = &signature {
            if *first != produced {
                return Err(Error::Protocol("signers derived different signatures"));
            }
        }
        signature = Some(produced);
    }

    let quorum = quorums
        .values()
        .next()
        .cloned()
        .ok_or(Error::Protocol("no quorum recorded"))?;

    Ok(SignOutcome {
        signature: signature.ok_or(Error::Protocol("no signature produced"))?,
        quorum,
        bytes_round1,
        bytes_round2,
        per_party,
    })
}
