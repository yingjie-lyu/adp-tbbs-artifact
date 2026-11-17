//! End to end: DKG, then two-pass signing over the wire format, with several message lengths.

use twopass_bbs::meter::{Meter, Stage};
use twopass_bbs::params::PublicParameters;
use twopass_bbs::session::{run_dkg, run_signing, verify};
use twopass_bbs::sign::{SignerOne, SignerTwo};

use threshold_bbs::algebra::{Group, Scalar};
use threshold_bbs::bls381::Scalar255;

fn messages(len: usize, seed: u64) -> Vec<Scalar255> {
    (0..len)
        .map(|index| Scalar255::from_u64(seed * 100 + index as u64 + 1))
        .collect()
}

fn keygen(params: &std::sync::Arc<PublicParameters>, session: &[u8]) -> (SignerOne, SignerTwo) {
    let mut meter = Meter::new();
    let outcome = run_dkg(params.clone(), session, &mut meter).expect("dkg");
    assert_eq!(
        outcome.first.public_key, outcome.second.public_key,
        "both parties must derive the same X"
    );
    // The DKG traffic is small: three short messages.
    assert!(outcome.bytes.iter().sum::<usize>() < 1200, "dkg traffic");
    (SignerOne::new(outcome.first), SignerTwo::new(outcome.second))
}

#[test]
fn one_of_each_message_length() {
    for len in [1usize, 3, 5] {
        let params = PublicParameters::production(len);
        let (mut first, mut second) = keygen(&params, b"dkg");
        let mut meter = Meter::new();

        let message = messages(len, 7);
        let outcome = run_signing(&mut first, &mut second, &message, b"sig", &mut meter)
            .unwrap_or_else(|error| panic!("signing ell={len} failed: {error}"));

        assert!(verify(&params, &first.party.public_key, &message, &outcome.signature));
        assert!(verify(
            &params,
            &second.party.public_key,
            &message,
            &outcome.signature
        ));
        assert!(outcome.bytes_pass1 > 0 && outcome.bytes_pass2 > 0);
    }
}

#[test]
fn every_signature_is_fresh() {
    let params = PublicParameters::production(2);
    let (mut first, mut second) = keygen(&params, b"dkg-fresh");
    let mut meter = Meter::new();
    let message = messages(2, 3);

    let one = run_signing(&mut first, &mut second, &message, b"sid-a", &mut meter).expect("first");
    let two = run_signing(&mut first, &mut second, &message, b"sid-b", &mut meter).expect("second");

    assert!(verify(&params, &first.party.public_key, &message, &one.signature));
    assert!(verify(&params, &first.party.public_key, &message, &two.signature));
    assert_ne!(one.signature.e, two.signature.e, "e must be fresh");
    assert_ne!(one.signature.a, two.signature.a, "A must be fresh");
}

#[test]
fn the_nonces_depend_on_the_message() {
    let params = PublicParameters::production(2);
    let (mut first, mut second) = keygen(&params, b"dkg-msg");
    let mut meter = Meter::new();

    let first_message = messages(2, 11);
    let second_message = messages(2, 12);
    let one = run_signing(&mut first, &mut second, &first_message, b"sid-m1", &mut meter).expect("m1");
    let two = run_signing(&mut first, &mut second, &second_message, b"sid-m2", &mut meter).expect("m2");

    assert_ne!(one.signature.e, two.signature.e);
    assert!(!verify(
        &params,
        &first.party.public_key,
        &second_message,
        &one.signature
    ));
}

#[test]
fn a_reused_session_id_is_refused() {
    let params = PublicParameters::production(2);
    let (mut first, mut second) = keygen(&params, b"dkg-reuse");
    let mut meter = Meter::new();
    let message = messages(2, 5);

    run_signing(&mut first, &mut second, &message, b"same-sid", &mut meter).expect("first");
    let second_attempt = run_signing(&mut first, &mut second, &message, b"same-sid", &mut meter);
    assert!(second_attempt.is_err(), "sid reuse must be refused");
}

#[test]
fn the_wrong_public_key_does_not_verify() {
    let params = PublicParameters::production(2);
    let (mut first, mut second) = keygen(&params, b"dkg-other");
    let mut meter = Meter::new();
    let message = messages(2, 9);
    let outcome = run_signing(&mut first, &mut second, &message, b"sid-x", &mut meter).expect("sign");

    let stranger = params.g2.scale(&Scalar255::from_u64(424242));
    assert!(!verify(&params, &stranger, &message, &outcome.signature));
}

#[test]
fn single_key_signing_matches_the_threshold_output() {
    let params = PublicParameters::production(1);
    let (mut first, mut second) = keygen(&params, b"dkg-ref");
    let mut meter = Meter::new();
    let message = messages(1, 2);
    let outcome = run_signing(&mut first, &mut second, &message, b"sid-ref", &mut meter).expect("sign");

    // Recomputing A from the public values must give the same signature.
    let signature = &outcome.signature;
    assert!(verify(&params, &first.party.public_key, &message, signature));
    let check = twopass_bbs::bbs::sign_with(
        &params,
        &first.party.own_share.add(&second.party.own_share),
        &message,
        &signature.e,
        &signature.s,
    )
    .expect("reference signature with the reconstructed key");
    assert_eq!(check.a, signature.a, "A must equal B/(x+e)");

    // And the meter saw exactly one CL.Solve and the two-pass stages.
    let (calls, _) = meter.stage(Stage::SignOutput);
    assert_eq!(calls, 1);
}
