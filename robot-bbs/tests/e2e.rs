//! End to end: DKG, then the two-round signing protocol, over several signer sets.

use std::collections::BTreeMap;
use std::sync::Arc;

use bicycl::Mpz;

use robot_bbs::bbs::{self, Bases, PublicParameters};
use robot_bbs::session::{run_signing, SignOutcome};
use robot_bbs::sign::{Round1Msg, Signer};
use tcl::cl::ClParameters;
use tcl::meter::Meter;

use threshold_bbs::algebra::{Group, Scalar};
use threshold_bbs::bls381::{Scalar255, SCALAR_MODULUS_DECIMAL};

pub fn parameters() -> Arc<ClParameters> {
    Arc::new(ClParameters::setup(
        &Mpz::from(SCALAR_MODULUS_DECIMAL),
        1827,
        128,
        80,
    ))
}

pub fn keyset(
    cl: &Arc<ClParameters>,
    parties: &[usize],
    t: usize,
) -> BTreeMap<usize, tcl::ThresholdKeys> {
    let mut meter = Meter::new();
    tcl::setup(cl.clone(), parties, t, b"robot-dkg", &mut meter).expect("dkg")
}

fn messages(len: usize, seed: u64) -> Vec<Scalar255> {
    (0..len)
        .map(|index| Scalar255::from_u64(seed * 100 + index as u64 + 1))
        .collect()
}

#[test]
fn four_parties_sign_in_two_rounds() {
    let cl = parameters();
    let parties: Vec<usize> = (1..=4).collect();
    let keys = keyset(&cl, &parties, 2);
    let params = PublicParameters::new(cl.clone(), 2);
    let bases = Bases::derive(&keys[&1].x_public, 2);

    let mut meter = Meter::new();
    let message = messages(2, 7);
    let outcome = run_signing(&keys, &bases, params, &parties, &message, b"sign", &mut meter)
        .expect("signing");

    assert!(bbs::verify(
        &bases,
        &keys[&1].x_public,
        &message,
        &outcome.signature
    ));
    assert_eq!(outcome.bytes_round1 + outcome.bytes_round2, outcome.total_bytes());
    assert!(outcome.total_bytes() > 0);
}

#[test]
fn a_threshold_subset_suffices() {
    let cl = parameters();
    let parties: Vec<usize> = (1..=5).collect();
    let keys = keyset(&cl, &parties, 2);
    let params = PublicParameters::new(cl.clone(), 1);
    let bases = Bases::derive(&keys[&1].x_public, 1);
    let mut meter = Meter::new();

    for quorum in [vec![1, 2, 3], vec![2, 4, 5], vec![1, 3, 5]] {
        let message = messages(1, quorum[0] as u64);
        let outcome = run_signing(&keys, &bases, params.clone(), &quorum, &message, b"sid", &mut meter)
            .unwrap_or_else(|error| panic!("signing with {quorum:?}: {error}"));
        assert!(bbs::verify(
            &bases,
            &keys[&1].x_public,
            &message,
            &outcome.signature
        ));
    }
}

#[test]
fn a_bad_vrf_share_is_dropped_and_signing_succeeds() {
    let cl = parameters();
    let parties: Vec<usize> = (1..=4).collect();
    let keys = keyset(&cl, &parties, 2);
    let params = PublicParameters::new(cl.clone(), 1);
    let bases = Bases::derive(&keys[&1].x_public, 1);
    let message = messages(1, 11);
    let session = b"robust";

    let mut signers: BTreeMap<usize, Signer> = BTreeMap::new();
    for id in &parties {
        signers.insert(
            *id,
            Signer::new(keys[id].clone(), bases.clone(), params.clone()),
        );
    }
    let mut meter = Meter::new();
    let mut wire = Vec::new();
    for id in &parties {
        let produced = signers.get_mut(id).unwrap().round1(&message, session, &mut meter).unwrap();
        // Party 4 broadcasts a corrupted VRF share.
        let encoded = if *id == 4 {
            let mut broken = produced.clone();
            broken.z_i = broken.z_i.combine(&bases.h[0]);
            broken.encode()
        } else {
            produced.encode()
        };
        wire.push(encoded);
    }

    // One honest signer runs round 2 and reports the participant set it accepted.
    let c1 = signers.get_mut(&1).unwrap();
    let inbox: Vec<Round1Msg> = wire
        .iter()
        .map(|encoded| Round1Msg::decode(encoded, &cl).unwrap())
        .collect();
    let mut quorum = parties.clone();
    c1.round2(&message, session, &mut quorum, &inbox, &mut meter)
        .expect("round 2 with a corrupted peer");
    assert_eq!(quorum, vec![1, 2, 3], "the faulty share must be dropped");
}

#[test]
fn a_different_message_does_not_verify() {
    let cl = parameters();
    let parties: Vec<usize> = (1..=3).collect();
    let keys = keyset(&cl, &parties, 2);
    let params = PublicParameters::new(cl.clone(), 1);
    let bases = Bases::derive(&keys[&1].x_public, 1);
    let mut meter = Meter::new();

    let message = messages(1, 3);
    let outcome: SignOutcome =
        run_signing(&keys, &bases, params, &parties, &message, b"sign-a", &mut meter).unwrap();
    assert!(!bbs::verify(
        &bases,
        &keys[&1].x_public,
        &messages(1, 4),
        &outcome.signature
    ));
}

#[test]
fn every_signature_is_fresh() {
    let cl = parameters();
    let parties: Vec<usize> = (1..=3).collect();
    let keys = keyset(&cl, &parties, 2);
    let params = PublicParameters::new(cl.clone(), 1);
    let bases = Bases::derive(&keys[&1].x_public, 1);
    let mut meter = Meter::new();
    let message = messages(1, 5);

    let one = run_signing(&keys, &bases, params.clone(), &parties, &message, b"sid-1", &mut meter)
        .unwrap();
    let two = run_signing(&keys, &bases, params, &parties, &message, b"sid-2", &mut meter).unwrap();
    assert_ne!(one.signature.e, two.signature.e);
    assert_ne!(one.signature.a, two.signature.a);
    assert!(bbs::verify(&bases, &keys[&1].x_public, &message, &two.signature));
}
