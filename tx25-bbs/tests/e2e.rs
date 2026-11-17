//! End to end: key setup, two offline rounds, one online round.

use std::collections::BTreeMap;
use std::sync::Arc;

use bicycl::Mpz;

use tcl::cl::ClParameters;
use tcl::meter::Meter;

use threshold_bbs::algebra::Scalar;
use threshold_bbs::bls381::{Scalar255, SCALAR_MODULUS_DECIMAL};

use tx25_bbs::bbs;
use tx25_bbs::keys::{self, Keys};
use tx25_bbs::params::PublicParameters;
use tx25_bbs::session::run_signing;

fn cl() -> Arc<ClParameters> {
    Arc::new(ClParameters::setup(
        &Mpz::from(SCALAR_MODULUS_DECIMAL),
        1827,
        128,
        80,
    ))
}

fn setup(len: usize, n: usize, t: usize) -> (Arc<PublicParameters>, BTreeMap<usize, Keys>) {
    let params = PublicParameters::new(cl(), len);
    let parties: Vec<usize> = (1..=n).collect();
    let mut meter = Meter::new();
    let keys = keys::setup(params.clone(), &parties, t, b"tx25-dkg", &mut meter).expect("setup");
    (params, keys)
}

fn messages(len: usize, seed: u64) -> Vec<Scalar255> {
    (0..len)
        .map(|index| Scalar255::from_u64(seed * 100 + index as u64 + 1))
        .collect()
}

#[test]
fn three_rounds_produce_a_valid_signature() {
    let (params, keys) = setup(2, 3, 2);
    let parties: Vec<usize> = (1..=3).collect();
    let mut meter = Meter::new();
    let message = messages(2, 7);

    let outcome = run_signing(&keys, &parties, &message, b"sign", &mut meter).expect("signing");
    assert!(bbs::verify(
        &params.bases,
        &keys[&1].x_public,
        &message,
        &outcome.signature
    ));
    // Two offline rounds and one online round, each with a contribution from every signer.
    assert!(outcome.bytes.iter().all(|bytes| *bytes > 0));
    assert_eq!(outcome.bytes.iter().sum::<usize>(), outcome.total_bytes());
    println!(
        "n=3: offline1 {} B, offline2 {} B, online {} B per signer; total {:.2} KiB",
        outcome.bytes[0] / 3,
        outcome.bytes[1] / 3,
        outcome.bytes[2] / 3,
        outcome.total_bytes() as f64 / 1024.0
    );
}

#[test]
fn a_threshold_subset_suffices() {
    let (params, keys) = setup(1, 4, 2);
    let mut meter = Meter::new();
    for quorum in [vec![1usize, 2, 3], vec![2, 3, 4]] {
        let message = messages(1, quorum[0] as u64);
        let outcome = run_signing(&keys, &quorum, &message, b"sid", &mut meter)
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
fn signatures_are_fresh_and_message_bound() {
    let (params, keys) = setup(1, 3, 2);
    let parties: Vec<usize> = (1..=3).collect();
    let mut meter = Meter::new();
    let message = messages(1, 11);

    let one = run_signing(&keys, &parties, &message, b"sid-1", &mut meter).expect("first");
    let two = run_signing(&keys, &parties, &message, b"sid-2", &mut meter).expect("second");
    assert_ne!(one.signature.e, two.signature.e);
    assert_ne!(one.signature.a, two.signature.a);
    assert!(bbs::verify(
        &params.bases,
        &keys[&1].x_public,
        &message,
        &two.signature
    ));
    assert!(!bbs::verify(
        &params.bases,
        &keys[&1].x_public,
        &messages(1, 12),
        &two.signature
    ));
}

#[test]
fn a_replayed_session_id_is_refused() {
    use tx25_bbs::sign::Signer;

    let (_, keys) = setup(1, 3, 2);
    let mut meter = Meter::new();
    let mut signer = Signer::new(keys[&1].clone());
    signer.offline1(b"same", &mut meter).expect("first");
    // The driver builds fresh signers per session; the guard lives on the signer, so exercising
    // it directly is the honest test.
    assert!(signer.offline1(b"same", &mut meter).is_err());
}
