//! Session drivers.
//!
//! Every message crosses the byte boundary: the drivers encode what a party produced and decode
//! it before the other party sees it, so the wire format is exercised on every run, and they
//! count the bytes each side puts on the wire (that is what the paper's 0.85 KB refers to).

use std::sync::Arc;

use threshold_bbs::bls381::Scalar255;

use crate::bbs::Signature;
use crate::error::{Error, Result};
use crate::keygen::{DkgPass1, DkgPass2, DkgPass3, FirstParty, FirstSetup, SecondParty, SecondSetup};
use crate::meter::Meter;
use crate::params::PublicParameters;
use crate::sign::{Pass1, Pass2, SignerOne, SignerTwo};

pub struct DkgOutcome {
    pub first: FirstParty,
    pub second: SecondParty,
    /// Bytes on the wire for pass 1, 2 and 3 respectively.
    pub bytes: [usize; 3],
}

/// Run the three DKG passes.
pub fn run_dkg(
    params: Arc<PublicParameters>,
    session: &[u8],
    meter: &mut Meter,
) -> Result<DkgOutcome> {
    let (mut first, pass1) = FirstSetup::new(params.clone(), session, meter);
    let pass1_wire = pass1.encode();

    let (second, pass2) = SecondSetup::new(
        params.clone(),
        session,
        &DkgPass1::decode(&pass1_wire)?,
        meter,
    )?;
    let pass2_wire = pass2.encode();

    let pass3 = first.pass3(&DkgPass2::decode(&pass2_wire)?, meter)?;
    let pass3_wire = pass3.encode();

    let second = second.finish(&DkgPass3::decode(&pass3_wire, &params)?, meter)?;
    let first = first.finish(meter)?;

    if first.public_key != second.public_key {
        return Err(Error::Protocol("parties derived different public keys"));
    }

    Ok(DkgOutcome {
        first,
        second,
        bytes: [pass1_wire.len(), pass2_wire.len(), pass3_wire.len()],
    })
}

pub struct SignOutcome {
    pub signature: Signature,
    pub bytes_pass1: usize,
    pub bytes_pass2: usize,
}

impl SignOutcome {
    pub fn total_bytes(&self) -> usize {
        self.bytes_pass1 + self.bytes_pass2
    }
}

/// Run one signing session: `P_1` moves, `P_2` answers, `P_1` outputs.
pub fn run_signing(
    first: &mut SignerOne,
    second: &mut SignerTwo,
    message: &[Scalar255],
    session: &[u8],
    meter: &mut Meter,
) -> Result<SignOutcome> {
    let pass1 = first.pass1(message, session, meter)?;
    let pass1_wire = pass1.encode();

    let pass2 = second.pass2(&Pass1::decode(&pass1_wire)?, message, session, meter)?;
    let pass2_wire = pass2.encode();

    let params = first.params().clone();
    let signature = first.output(&Pass2::decode(&pass2_wire, &params)?, message, session, meter)?;

    Ok(SignOutcome {
        signature,
        bytes_pass1: pass1_wire.len(),
        bytes_pass2: pass2_wire.len(),
    })
}

/// `P_1` outputs the signature, but both parties can verify it against the joint public key.
pub fn verify(
    params: &Arc<PublicParameters>,
    public_key: &threshold_bbs::bls381::G2,
    message: &[Scalar255],
    signature: &Signature,
) -> bool {
    crate::bbs::verify(params, public_key, message, signature)
}
