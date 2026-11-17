//! End to end: DKG, then the four-round signing protocol.

use std::collections::BTreeMap;
use std::sync::Arc;

use bicycl::Mpz;

use tcl::cl::ClParameters;
use tcl::meter::Meter;

use threshold_bbs::algebra::Scalar;
use threshold_bbs::bls381::{Scalar255, SCALAR_MODULUS_DECIMAL};

use wmc24_bbs::bbs::{self, PublicParameters};
use wmc24_bbs::session::run_signing;
use wmc24_bbs::sign::{Round1Msg, Signer};

fn parameters() -> Arc<ClParameters> {
    Arc::new(ClParameters::setup(
        &Mpz::from(SCALAR_MODULUS_DECIMAL),
        1827,
        128,
        80,
    ))
}

fn keyset(
    cl: &Arc<ClParameters>,
    parties: &[usize],
    t: usize,
) -> BTreeMap<usize, tcl::ThresholdKeys> {
    let mut meter = Meter::new();
    tcl::setup(cl.clone(), parties, t, b"wmc24-dkg", &mut meter).expect("dkg")
}

fn messages(len: usize, seed: u64) -> Vec<Scalar255> {
    (0..len)
        .map(|index| Scalar255::from_u64(seed * 100 + index as u64 + 1))
        .collect()
}

#[test]
fn four_parties_sign_in_four_rounds() {
    let cl = parameters();
    let parties: Vec<usize> = (1..=4).collect();
    let keys = keyset(&cl, &parties, 2);
    let params = PublicParameters::new(cl.clone(), 2);
    let mut meter = Meter::new();

    let message = messages(2, 9);
    let outcome = run_signing(&keys, params.clone(), &parties, &message, b"sign", &mut meter)
        .expect("signing");
    assert!(bbs::verify(
        &params.bases,
        &keys[&1].x_public,
        &message,
        &outcome.signature
    ));
    assert_eq!(outcome.bytes.iter().sum::<usize>(), outcome.total_bytes());
}

#[test]
fn a_threshold_subset_suffices() {
    let cl = parameters();
    let parties: Vec<usize> = (1..=5).collect();
    let keys = keyset(&cl, &parties, 2);
    let params = PublicParameters::new(cl.clone(), 1);
    let mut meter = Meter::new();

    for quorum in [vec![1, 2, 3], vec![3, 4, 5], vec![1, 2, 4, 5]] {
        let message = messages(1, quorum.len() as u64);
        let outcome = run_signing(&keys, params.clone(), &quorum, &message, b"sid", &mut meter)
            .unwrap_or_else(|error| panic!("signing with {quorum:?}: {error}"));
        assert!(bbs::verify(
            &params.bases,
            &keys[&1].x_public,
            &message,
            &outcome.signature
        ));
    }
}

#[test]
fn a_bad_nonce_ciphertext_is_dropped() {
    let cl = parameters();
    let parties: Vec<usize> = (1..=4).collect();
    let keys = keyset(&cl, &parties, 2);
    let params = PublicParameters::new(cl.clone(), 1);
    let message = messages(1, 13);

    let mut signers: BTreeMap<usize, Signer> = BTreeMap::new();
    for id in &parties {
        signers.insert(*id, Signer::new(keys[id].clone(), params.clone()));
    }
    let mut meter = Meter::new();
    let mut wire = Vec::new();
    for id in &parties {
        let produced = signers.get_mut(id).unwrap().round1(&message, b"robust", &mut meter).unwrap();
        // Party 4 sends a ciphertext whose proof does not match.
        let encoded = if *id == 4 {
            let mut broken = produced.clone();
            broken.c_e.c1 = cl.compose(&broken.c_e.c1, &cl.f_exp(&Scalar255::from_u64(1)), &mut meter);
            broken.encode()
        } else {
            produced.encode()
        };
        wire.push(encoded);
    }

    let inbox: Vec<Round1Msg> = wire
        .iter()
        .map(|encoded| Round1Msg::decode(encoded, &cl).unwrap())
        .collect();
    let mut quorum = parties.clone();
    signers
        .get_mut(&1)
        .unwrap()
        .round2(b"robust", &mut quorum, &inbox, &mut meter)
        .expect("round 2 with a corrupted peer");
    assert_eq!(quorum, vec![1, 2, 3], "the faulty ciphertext must be dropped");
}

#[test]
fn a_different_message_does_not_verify() {
    let cl = parameters();
    let parties: Vec<usize> = (1..=3).collect();
    let keys = keyset(&cl, &parties, 2);
    let params = PublicParameters::new(cl.clone(), 1);
    let mut meter = Meter::new();
    let message = messages(1, 21);

    let outcome = run_signing(&keys, params.clone(), &parties, &message, b"sign-a", &mut meter).unwrap();
    assert!(!bbs::verify(
        &params.bases,
        &keys[&1].x_public,
        &messages(1, 22),
        &outcome.signature
    ));
}

#[test]
fn every_signature_is_fresh() {
    let cl = parameters();
    let parties: Vec<usize> = (1..=3).collect();
    let keys = keyset(&cl, &parties, 2);
    let params = PublicParameters::new(cl.clone(), 1);
    let mut meter = Meter::new();
    let message = messages(1, 31);

    let one = run_signing(&keys, params.clone(), &parties, &message, b"sid-1", &mut meter).unwrap();
    let two = run_signing(&keys, params.clone(), &parties, &message, b"sid-2", &mut meter).unwrap();
    assert_ne!(one.signature.e, two.signature.e);
    assert!(bbs::verify(&params.bases, &keys[&1].x_public, &message, &two.signature));
}
