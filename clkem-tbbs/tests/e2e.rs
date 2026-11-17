//! End to end: key generation, three-round signing with several quorums, verification.

use clkem_tbbs::params::PublicParameters;
use clkem_tbbs::session::{run_keygen, run_signing, verify};
use clkem_tbbs::stats::{Meter, Op};

use threshold_bbs::algebra::Scalar;
use threshold_bbs::bls381::Scalar255;

fn messages(seed: u64, len: usize) -> Vec<Scalar255> {
    (0..len)
        .map(|index| Scalar255::from_u64(seed * 1000 + index as u64 + 1))
        .collect()
}

#[test]
fn two_of_three_every_quorum() {
    let pp = PublicParameters::production(3);
    let mut meter = Meter::new();
    let session = b"keygen-2of3";
    let keygen = run_keygen(pp.clone(), 3, 2, session, &mut meter).expect("keygen");

    // The verifying key must be the same at every party.
    let reference = &keygen.parties[&1].public;
    for id in 2..=3 {
        let other = &keygen.parties[&id].public;
        assert_eq!(reference.x_g2, other.x_g2, "X differs at party {id}");
        assert_eq!(reference.bases.h1, other.bases.h1, "H_1 differs at party {id}");
        assert_eq!(reference.phi_k, other.phi_k, "phi_K differs at party {id}");
        assert_eq!(reference.x_bar, other.x_bar, "x^K differs at party {id}");
    }
    // The base vector is the sum of the contributions, so it is not the zero vector.
    assert_ne!(reference.bases.h1, threshold_bbs::algebra::Group::identity());

    for quorum in [vec![1, 2], vec![2, 3], vec![1, 3], vec![1, 2, 3]] {
        let message = messages(quorum.len() as u64, 3);
        let tag = format!("sign-{quorum:?}");
        let outcome = run_signing(&keygen.parties, &quorum, &message, tag.as_bytes(), &mut meter)
            .unwrap_or_else(|error| panic!("signing with {quorum:?} failed: {error}"));

        for id in &quorum {
            assert!(verify(&keygen.parties[id], &message, &outcome.signature));
        }
        assert!(
            !verify(&keygen.parties[&1], &messages(9, 3), &outcome.signature),
            "signature must not verify against another message"
        );
    }
}

#[test]
fn three_of_five_and_a_four_subset() {
    let pp = PublicParameters::production(2);
    let mut meter = Meter::new();
    let keygen = run_keygen(pp.clone(), 5, 3, b"keygen-3of5", &mut meter).expect("keygen");

    for quorum in [vec![1, 2, 3], vec![3, 4, 5], vec![1, 2, 4, 5]] {
        let message = messages(1, 2);
        let tag = format!("sign-3of5-{quorum:?}");
        let outcome = run_signing(&keygen.parties, &quorum, &message, tag.as_bytes(), &mut meter)
            .unwrap_or_else(|error| panic!("signing with {quorum:?} failed: {error}"));
        assert!(verify(&keygen.parties[&quorum[0]], &message, &outcome.signature));
    }
}

#[test]
fn a_quorum_below_the_threshold_is_rejected() {
    let pp = PublicParameters::production(2);
    let mut meter = Meter::new();
    let keygen = run_keygen(pp.clone(), 3, 2, b"keygen-small", &mut meter).expect("keygen");
    let message = messages(4, 2);
    let outcome = run_signing(&keygen.parties, &[1], &message, b"sign-small", &mut meter);
    assert!(outcome.is_err(), "one share is below the threshold");
}

#[test]
fn fresh_nonces_per_session() {
    let pp = PublicParameters::production(2);
    let mut meter = Meter::new();
    let keygen = run_keygen(pp.clone(), 3, 2, b"keygen-fresh", &mut meter).expect("keygen");
    let message = messages(5, 2);

    let first = run_signing(&keygen.parties, &[1, 2], &message, b"sign-a", &mut meter).expect("first");
    let second = run_signing(&keygen.parties, &[1, 2], &message, b"sign-b", &mut meter).expect("second");

    assert!(verify(&keygen.parties[&1], &message, &first.signature));
    assert!(verify(&keygen.parties[&1], &message, &second.signature));
    assert_ne!(first.signature.e, second.signature.e, "e must be fresh");
    assert_ne!(first.signature.s, second.signature.s, "s must be fresh");
    assert_ne!(first.signature.a, second.signature.a, "A must be fresh");
}

#[test]
fn the_pairing_check_actually_bites() {
    let pp = PublicParameters::production(1);
    let mut meter = Meter::new();
    let keygen = run_keygen(pp.clone(), 2, 2, b"keygen-pair", &mut meter).expect("keygen");
    let message = messages(6, 1);
    let outcome = run_signing(&keygen.parties, &[1, 2], &message, b"sign-pair", &mut meter).expect("sign");

    let mut broken = outcome.signature.clone();
    broken.e = broken.e.add(&Scalar255::from_u64(1));
    assert!(!verify(&keygen.parties[&1], &message, &broken));

    // The meter recorded exactly one pairing pair per verify call.
    assert!(meter.count(Op::Solve) >= 2, "one CL.Solve per signer");
}
