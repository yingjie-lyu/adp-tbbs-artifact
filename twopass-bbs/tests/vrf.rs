//! ECVRF: determinism, verification, and rejection of tampered proofs.

use rand_core::OsRng;

use twopass_bbs::meter::Meter;
use twopass_bbs::params::PublicParameters;
use twopass_bbs::vrf;

use threshold_bbs::algebra::Scalar;
use threshold_bbs::bls381::Scalar255;

fn parameters() -> std::sync::Arc<PublicParameters> {
    PublicParameters::production(2)
}

#[test]
fn eval_then_verify_recovers_the_output() {
    let pp = parameters();
    let mut meter = Meter::new();
    let key = vrf::VrfKey::generate(&pp, &mut OsRng);

    let (beta, proof) = vrf::eval(&pp, &key, b"alpha", &mut OsRng, &mut meter);
    assert_eq!(
        vrf::verify(&pp, &key.vk, b"alpha", &proof, &mut meter),
        Some(beta)
    );
}

#[test]
fn the_output_is_deterministic_in_the_input() {
    let pp = parameters();
    let mut meter = Meter::new();
    let key = vrf::VrfKey::generate(&pp, &mut OsRng);

    let (first, _) = vrf::eval(&pp, &key, b"alpha", &mut OsRng, &mut meter);
    let (second, _) = vrf::eval(&pp, &key, b"beta", &mut OsRng, &mut meter);
    let (again, _) = vrf::eval(&pp, &key, b"alpha", &mut OsRng, &mut meter);

    assert_eq!(first, again, "beta must depend only on (vk, alpha)");
    assert_ne!(first, second, "different inputs must give different outputs");
}

#[test]
fn a_proof_for_one_input_does_not_verify_for_another() {
    let pp = parameters();
    let mut meter = Meter::new();
    let key = vrf::VrfKey::generate(&pp, &mut OsRng);
    let (_, proof) = vrf::eval(&pp, &key, b"alpha", &mut OsRng, &mut meter);
    assert!(vrf::verify(&pp, &key.vk, b"beta", &proof, &mut meter).is_none());
}

#[test]
fn tampering_with_the_proof_is_caught() {
    let pp = parameters();
    let mut meter = Meter::new();
    let key = vrf::VrfKey::generate(&pp, &mut OsRng);
    let (_, proof) = vrf::eval(&pp, &key, b"alpha", &mut OsRng, &mut meter);

    let mut bad = proof.clone();
    bad.response = bad.response.add(&Scalar255::from_u64(1));
    assert!(vrf::verify(&pp, &key.vk, b"alpha", &bad, &mut meter).is_none());

    let mut bad = proof.clone();
    bad.challenge = bad.challenge.add(&Scalar255::from_u64(1));
    assert!(vrf::verify(&pp, &key.vk, b"alpha", &bad, &mut meter).is_none());

    // A different VRF key must not accept the transcript.
    let other = vrf::VrfKey::generate(&pp, &mut OsRng);
    assert!(vrf::verify(&pp, &other.vk, b"alpha", &proof, &mut meter).is_none());
}
