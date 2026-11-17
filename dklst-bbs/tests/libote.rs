//! The same protocol over libOTe's SoftSpokenOT instead of the vendored `sl-oblivious`.
//!
//! Run with `cargo test --features libote --test libote`.

#![cfg(feature = "libote")]

use bls12_381::Scalar;

use dklst_bbs::mul::{finish, multiply, public_grip, receive, reply, MulVariant};
use dklst_bbs::ot::{Backend, Counters, OtSetup};
use dklst_bbs::params::{ELL, LIBOTE_OTS};
use dklst_bbs::sign::{combine, keygen, verify, OtMaterial, PublicParams, Response, Round1, Round2, Signer};

fn setup() -> OtSetup {
    OtSetup::with_backend(Backend::LibOte).expect("libOTe setup")
}

#[test]
fn the_shim_reports_its_identity() {
    println!(
        "{} with {} base OTs per pair",
        dklst_bbs::libote::version(),
        dklst_bbs::libote::base_ot_count()
    );
    assert!(dklst_bbs::libote::base_ot_count() > 0);
}

#[test]
fn shares_add_up_to_the_product() {
    let grip = public_grip(b"libote-grip");
    let pair = setup();
    let mut counters = Counters::default();

    // Reuse one base-OT instance across several multiplications, as the protocol does.
    for round in 0..4u64 {
        let alpha = Scalar::from(1234567u64 + round);
        let beta = Scalar::from(7654321u64 + round);
        let (a, b) = multiply(
            &round.to_be_bytes(),
            &pair,
            &pair,
            &alpha,
            &beta,
            &grip,
            MulVariant::Correction,
            &mut counters,
        )
        .expect("pi_Mul");
        assert_eq!(a + b, alpha * beta, "t_A + t_B must equal alpha*beta");
    }

    assert_eq!(counters.ots, 4 * LIBOTE_OTS as u64);
    println!(
        "libOTe pi_Mul: {} bits per multiplication (per party {}), {} OTs of 128 bits",
        counters.bits / 4,
        counters.per_party_bits() / 4,
        counters.ots / 4
    );
}

#[test]
fn split_multiplier_is_consistent() {
    let grip = public_grip(b"libote-grip");
    let pair = setup();
    let mut counters = Counters::default();
    let alpha = Scalar::from(99887766u64);
    let beta = Scalar::from(11223344u64);

    let (state, message) =
        receive(b"libote-split", &pair, &beta, &grip, &mut counters).expect("receive");
    let (answer, share_a) =
        reply(
        b"libote-split",
        &pair,
        &message,
        &alpha,
        &grip,
        MulVariant::Correction,
        &mut counters,
    )
    .expect("reply");
    let share_b = finish(b"libote-split", &state, &answer, &grip).expect("finish");
    assert_eq!(share_a + share_b, alpha * beta, "split pi_Mul over libOTe");
}

/// SoftSpokenOT's `field_bits` trades wire for CPU, and `4` is the setting that reproduces the
/// `k = 2` cost model DKLST charge for.
#[test]
fn field_bits_trades_bandwidth_for_cpu() {
    let grip = public_grip(b"libote-knob");
    let mut measured = Vec::new();
    for field_bits in [2u32, 4, 8] {
        let pair = OtSetup::with_options(Backend::LibOte, field_bits).expect("setup");
        // Warm-up: the first extension on a pair also runs the one-time VOLE expansion.
        let _ = multiply(
            b"warm-up",
            &pair,
            &pair,
            &Scalar::from(3u64),
            &Scalar::from(5u64),
            &grip,
            MulVariant::Correction,
            &mut Counters::default(),
        )
        .expect("warm-up");
        let mut counters = Counters::default();
        let reps = 4u64;
        for round in 0..reps {
            let alpha = Scalar::from(101u64 + round);
            let beta = Scalar::from(202u64 + round);
            multiply(
                &round.to_be_bytes(),
                &pair,
                &pair,
                &alpha,
                &beta,
                &grip,
                MulVariant::Correction,
                &mut counters,
            )
            .expect("pi_Mul");
        }
        measured.push(counters.per_party_bits() / reps);
    }

    println!("MulCost bits/party for field_bits 2/4/8: {measured:?} (DKLST model 308576)");
    assert!(
        measured[0] > measured[1] && measured[1] > measured[2],
        "wire must fall as field_bits grows: {measured:?}"
    );
    let delta = (measured[1] as f64 - 308_576.0) / 308_576.0;
    assert!(
        delta.abs() < 0.05,
        "field_bits = 4 should land within 5% of DKLST's MulCost, got {:.1}%",
        delta * 100.0
    );
}

/// A whole signing session over the libOTe backend.
#[test]
fn signature_verifies() {
    let quorum: Vec<usize> = (1..=3).collect();
    let threshold = 3;
    let pp = PublicParams::new(4);
    let keys = keygen(&quorum, threshold);
    let public = keys[0].public;
    let material =
        OtMaterial::with_backend(&quorum, Backend::LibOte, MulVariant::Correction)
            .expect("libOTe setup");

    let message: Vec<Scalar> = (1..=4u64).map(Scalar::from).collect();
    let mut signers: Vec<Signer> = keys
        .into_iter()
        .map(|item| Signer::new(item, &quorum, pp.clone()))
        .collect();

    let session = b"libote-session";
    let round1: Vec<Round1> = signers
        .iter_mut()
        .map(|signer| signer.round1(session, &material))
        .collect();
    let round2: Vec<Round2> = signers
        .iter_mut()
        .map(|signer| signer.round2(session, &material, &round1))
        .collect();
    let responses: Vec<Response> = signers
        .iter_mut()
        .map(|signer| signer.finish(session, &round1, &round2, &message))
        .collect();

    let (a, s, e) = combine(&responses).expect("invertible");
    assert!(verify(&pp, &public, &message, &a, &e, &s), "pairing check");
    assert_eq!(ELL, 672);
}
