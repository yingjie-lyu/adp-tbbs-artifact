//! Adversarial cases: tampered proofs, nonces and shares must all be caught.

use std::collections::BTreeMap;

use clkem_tbbs::keygen::KeygenParty;
use clkem_tbbs::params::PublicParameters;
use clkem_tbbs::session::run_keygen;
use clkem_tbbs::sign::{SignCommitMsg, SignOpenMsg, SignParty, SignShareMsg};
use clkem_tbbs::stats::Meter;
use clkem_tbbs::transport::{Bus, Round};

use threshold_bbs::algebra::Scalar;
use threshold_bbs::bls381::Scalar255;

/// Drive one signing session by hand so a message can be tampered with in flight.
fn sign_with_tamper(pp: &PublicParameters, packages: &BTreeMap<usize, clkem_tbbs::KeyPackage>, tamper: u8) -> Result<(), clkem_tbbs::Error> {
    let quorum = vec![1usize, 2usize];
    let message = vec![Scalar255::from_u64(42), Scalar255::from_u64(43)];
    let mut meter = Meter::new();
    let mut bus = Bus::new(&quorum);
    let mut parties: BTreeMap<usize, SignParty> = quorum
        .iter()
        .map(|id| {
            let party = SignParty::new(packages[id].clone(), &quorum, &message, b"tamper").unwrap();
            (*id, party)
        })
        .collect();

    for id in &quorum {
        let message = parties.get_mut(id).unwrap().commit(&mut meter);
        let payload = if tamper == 1 && *id == 2 {
            // Replace phi_{K^{gamma_2}} with an unrelated form: the proof no longer matches.
            let mut broken = message.clone();
            broken.phi_gamma = pp.cl.exp(pp.cl.gq(), &bicycl::Mpz::from(7u64), &mut meter);
            broken.encode()
        } else {
            message.encode()
        };
        bus.publish(Round::SignCommit, *id, payload).unwrap();
    }

    for id in &quorum {
        let inbox: Vec<SignCommitMsg> = bus
            .broadcast(*id, Round::SignCommit)
            .unwrap()
            .iter()
            .map(|envelope| SignCommitMsg::decode(&envelope.payload, &pp.cl).unwrap())
            .collect();
        let message = parties.get_mut(id).unwrap().open(&inbox, &mut meter)?;
        let payload = if tamper == 2 && *id == 2 {
            // Open a different e_i than the one committed to in round 1.
            let mut broken = message.clone();
            broken.e_i = broken.e_i.add(&Scalar255::from_u64(1));
            broken.encode()
        } else {
            message.encode()
        };
        bus.publish(Round::SignOpen, *id, payload).unwrap();
    }

    for id in &quorum {
        let inbox: Vec<SignOpenMsg> = bus
            .broadcast(*id, Round::SignOpen)
            .unwrap()
            .iter()
            .map(|envelope| SignOpenMsg::decode(&envelope.payload).unwrap())
            .collect();
        let message = parties.get_mut(id).unwrap().share(&inbox, &mut meter)?;
        let payload = if tamper == 3 && *id == 2 {
            // Corrupt the partial decryption: add f^1 to the kernel.
            let mut broken = message.clone();
            broken.pd_i = pp
                .cl
                .compose(&broken.pd_i, &pp.cl.f_exp(&Scalar255::from_u64(1)), &mut meter);
            broken.encode()
        } else {
            message.encode()
        };
        bus.publish(Round::SignShare, *id, payload).unwrap();
    }

    let inbox: Vec<SignShareMsg> = bus
        .broadcast(1, Round::SignShare)
        .unwrap()
        .iter()
        .map(|envelope| SignShareMsg::decode(&envelope.payload, &pp.cl).unwrap())
        .collect();
    parties.get_mut(&1).unwrap().combine(&inbox, &mut meter)?;
    Ok(())
}

#[test]
fn an_honest_run_passes_the_same_harness() {
    let pp = PublicParameters::production(2);
    let mut meter = Meter::new();
    let keygen = run_keygen(pp.clone(), 2, 2, b"neg-honest", &mut meter).unwrap();
    sign_with_tamper(&pp, &keygen.parties, 0).expect("honest run");
}

#[test]
fn a_forged_gamma_share_is_rejected() {
    let pp = PublicParameters::production(2);
    let mut meter = Meter::new();
    let keygen = run_keygen(pp.clone(), 2, 2, b"neg-gamma", &mut meter).unwrap();
    let result = sign_with_tamper(&pp, &keygen.parties, 1);
    assert!(matches!(result, Err(clkem_tbbs::Error::Verify(_))), "got {result:?}");
}

#[test]
fn an_opened_nonce_must_match_its_commitment() {
    let pp = PublicParameters::production(2);
    let mut meter = Meter::new();
    let keygen = run_keygen(pp.clone(), 2, 2, b"neg-nonce", &mut meter).unwrap();
    let result = sign_with_tamper(&pp, &keygen.parties, 2);
    assert!(matches!(result, Err(clkem_tbbs::Error::Verify(_))), "got {result:?}");
}

#[test]
fn a_corrupted_partial_decryption_breaks_the_pairing_check() {
    let pp = PublicParameters::production(2);
    let mut meter = Meter::new();
    let keygen = run_keygen(pp.clone(), 2, 2, b"neg-pd", &mut meter).unwrap();
    let result = sign_with_tamper(&pp, &keygen.parties, 3);
    assert!(matches!(result, Err(clkem_tbbs::Error::Verify(_))), "got {result:?}");
}

#[test]
fn a_pvss_share_for_another_index_fails_sscheck() {
    let pp = PublicParameters::production(1);
    let mut meter = Meter::new();
    let mut dealer = KeygenParty::new(pp.clone(), 2, 3, 2, b"neg-pvss".to_vec());
    let (broadcast, shares) = dealer.deal(&mut meter);
    let for_party_one = shares
        .iter()
        .find(|(id, _)| *id == 1)
        .map(|(_, share)| share.clone())
        .unwrap();

    let mut first = KeygenParty::new(pp.clone(), 1, 3, 2, b"neg-pvss".to_vec());
    first
        .accept_deal(&broadcast, &for_party_one, &mut meter)
        .expect("the honest share checks out");

    // Party 3 receiving party 1's share must reject it.
    let mut third = KeygenParty::new(pp.clone(), 3, 3, 2, b"neg-pvss".to_vec());
    let result = third.accept_deal(&broadcast, &for_party_one, &mut meter);
    assert!(matches!(result, Err(clkem_tbbs::Error::Verify(_))), "got {result:?}");
}
