//! Session driver: four rounds, every message crossing the byte boundary.

use std::collections::BTreeMap;
use std::sync::Arc;

use tcl::meter::Meter;
use tcl::{Error, Result, ThresholdKeys};

use threshold_bbs::bls381::Scalar255;

use crate::bbs::{self, PublicParameters, Signature};
use crate::sign::{Round1Msg, Round2Msg, Round3Msg, Round4Msg, Signer};

pub struct SignOutcome {
    pub signature: Signature,
    pub quorum: Vec<usize>,
    /// Bytes on the wire per round (summed over signers).
    pub bytes: [usize; 4],
    pub per_party: BTreeMap<usize, usize>,
}

impl SignOutcome {
    pub fn total_bytes(&self) -> usize {
        self.bytes.iter().sum()
    }
}

pub fn run_signing(
    keys: &BTreeMap<usize, ThresholdKeys>,
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
        signers.insert(*id, Signer::new(package, params.clone()));
    }
    let mut per_party: BTreeMap<usize, usize> = BTreeMap::new();
    let mut bytes = [0usize; 4];

    // Round 1
    let mut wire1 = Vec::new();
    for id in quorum {
        let produced = signers
            .get_mut(id)
            .ok_or(Error::Missing("signer"))?
            .round1(message, session, meter)?;
        let encoded = produced.encode();
        *per_party.entry(*id).or_insert(0) += encoded.len();
        bytes[0] += encoded.len();
        wire1.push(encoded);
    }

    // Round 2
    let mut wire2 = Vec::new();
    let mut quorums: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for id in quorum {
        let inbox = wire1
            .iter()
            .map(|encoded| Round1Msg::decode(encoded, &keys[id].tc.cl))
            .collect::<Result<Vec<_>>>()?;
        let mut view = quorum.to_vec();
        let produced = signers
            .get_mut(id)
            .ok_or(Error::Missing("signer"))?
            .round2(session, &mut view, &inbox, meter)?;
        quorums.insert(*id, view);
        let encoded = produced.encode();
        *per_party.entry(*id).or_insert(0) += encoded.len();
        bytes[1] += encoded.len();
        wire2.push(encoded);
    }

    // Round 3
    let mut wire3 = Vec::new();
    for id in quorum {
        let inbox = wire2
            .iter()
            .map(|encoded| Round2Msg::decode(encoded, &keys[id].tc.cl))
            .collect::<Result<Vec<_>>>()?;
        let mut view = quorums
            .get(id)
            .cloned()
            .ok_or(Error::Protocol("no quorum recorded"))?;
        let produced = signers
            .get_mut(id)
            .ok_or(Error::Missing("signer"))?
            .round3(message, session, &mut view, &inbox, meter)?;
        quorums.insert(*id, view);
        let encoded = produced.encode();
        *per_party.entry(*id).or_insert(0) += encoded.len();
        bytes[2] += encoded.len();
        wire3.push(encoded);
    }

    // Round 4
    let mut wire4 = Vec::new();
    for id in quorum {
        let inbox = wire3
            .iter()
            .map(|encoded| Round3Msg::decode(encoded, &keys[id].tc.cl))
            .collect::<Result<Vec<_>>>()?;
        let mut view = quorums
            .get(id)
            .cloned()
            .ok_or(Error::Protocol("no quorum recorded"))?;
        let produced = signers
            .get_mut(id)
            .ok_or(Error::Missing("signer"))?
            .round4(session, &mut view, &inbox, meter)?;
        quorums.insert(*id, view);
        let encoded = produced.encode();
        *per_party.entry(*id).or_insert(0) += encoded.len();
        bytes[3] += encoded.len();
        wire4.push(encoded);
    }

    // Output
    let mut signature: Option<Signature> = None;
    for id in quorum {
        let inbox = wire4
            .iter()
            .map(|encoded| Round4Msg::decode(encoded, &keys[id].tc.cl))
            .collect::<Result<Vec<_>>>()?;
        let produced = signers
            .get_mut(id)
            .ok_or(Error::Missing("signer"))?
            .output(session, &inbox, meter)?;
        if let Some(first) = &signature {
            if *first != produced {
                return Err(Error::Protocol("signers derived different signatures"));
            }
        }
        signature = Some(produced);
    }
    let signature = signature.ok_or(Error::Protocol("no signature produced"))?;
    if !bbs::verify(&params.bases, &keys[&quorum[0]].x_public, message, &signature) {
        return Err(Error::Verify("threshold signature"));
    }

    let quorum = quorums
        .values()
        .next()
        .cloned()
        .ok_or(Error::Protocol("no quorum recorded"))?;

    Ok(SignOutcome {
        signature,
        quorum,
        bytes,
        per_party,
    })
}
