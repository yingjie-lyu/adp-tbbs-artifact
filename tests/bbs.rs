//! BBS+ signatures and the pairing check the threshold protocol ends with.

use threshold_bbs::algebra::{Group, Scalar};
use threshold_bbs::bbs;
use threshold_bbs::bls381::Scalar255;
use threshold_bbs::params::{PublicParameters, SetupConfig};

fn parameters(len: usize) -> PublicParameters {
    PublicParameters::setup(&SetupConfig::production(len))
}

#[test]
fn sign_verify_round_trip() {
    let pp = parameters(3);
    let secret = Scalar255::from_u64(4242);
    let public = pp.public_key_for(&secret);
    let messages = vec![
        Scalar255::from_u64(7),
        Scalar255::from_u64(11),
        Scalar255::from_u64(19),
    ];

    let signature = bbs::sign(&pp, &secret, &messages).unwrap();
    assert!(bbs::verify_with(&pp, &public, &messages, &signature));
}

#[test]
fn tampered_message_and_signature_are_rejected() {
    let pp = parameters(2);
    let secret = Scalar255::from_u64(99);
    let public = pp.public_key_for(&secret);
    let messages = vec![Scalar255::from_u64(3), Scalar255::from_u64(4)];
    let signature = bbs::sign(&pp, &secret, &messages).unwrap();

    let mut altered = messages.clone();
    altered[1] = altered[1].add(&Scalar255::one());
    assert!(!bbs::verify_with(&pp, &public, &altered, &signature));

    let mut wrong_e = signature.clone();
    wrong_e.e = wrong_e.e.add(&Scalar255::one());
    assert!(!bbs::verify_with(&pp, &public, &messages, &wrong_e));

    let wrong_key = pp.public_key_for(&Scalar255::from_u64(100));
    assert!(!bbs::verify_with(&pp, &wrong_key, &messages, &signature));
}

#[test]
fn zero_e_is_rejected() {
    let pp = parameters(1);
    let secret = Scalar255::from_u64(5);
    let public = pp.public_key_for(&secret);
    let messages = vec![Scalar255::from_u64(1)];
    let signature = bbs::sign(&pp, &secret, &messages).unwrap();

    let mut degenerate = signature;
    degenerate.e = Scalar255::zero();
    assert!(!bbs::verify_with(&pp, &public, &messages, &degenerate));
}

#[test]
fn prescribed_scalars_reproduce_the_threshold_object() {
    // `sign_with` builds the exact signature the protocol must reconstruct: `(e, phi)` come
    // from `hashout`, so the only free variable is the pairing check itself.
    let pp = parameters(2);
    let secret = Scalar255::from_u64(2024);
    let public = pp.public_key_for(&secret);
    let messages = vec![Scalar255::from_u64(8), Scalar255::from_u64(9)];
    let e = Scalar255::from_u64(31);
    let phi = Scalar255::from_u64(41);

    let signature = bbs::sign_with(&pp, &secret, &messages, &e, &phi).unwrap();
    assert!(bbs::verify_with(&pp, &public, &messages, &signature));

    let u = pp.compute_u(&phi, &messages);
    let expected = u.scale(&secret.add(&e).invert().unwrap());
    assert_eq!(signature.a, expected);
}

#[test]
fn message_length_must_match_the_setup() {
    let pp = parameters(2);
    let secret = Scalar255::from_u64(1);
    let too_long = vec![Scalar255::from_u64(1); 3];
    assert!(bbs::sign(&pp, &secret, &too_long).is_none());
    assert!(bbs::sign_with(
        &pp,
        &secret,
        &too_long,
        &Scalar255::from_u64(2),
        &Scalar255::from_u64(3)
    )
    .is_none());
}
