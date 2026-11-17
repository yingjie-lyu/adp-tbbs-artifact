//! Threshold-CL / ElGamal smoke tests: the pieces both threshold BBS+ crates build on.

use std::collections::BTreeMap;
use std::sync::Arc;

use bicycl::{Mpz, QFI};

use tcl::cl::ClParameters;
use tcl::eg;
use tcl::meter::Meter;
use tcl::zkp;
use tcl::{setup, ThresholdKeys};

use threshold_bbs::algebra::{Group, Scalar};
use threshold_bbs::bls381::{Scalar255, SCALAR_MODULUS_DECIMAL};

fn parameters() -> Arc<ClParameters> {
    Arc::new(ClParameters::setup(
        &Mpz::from(SCALAR_MODULUS_DECIMAL),
        1827,
        128,
        40,
    ))
}

fn keyset(n: usize, t: usize) -> BTreeMap<usize, ThresholdKeys> {
    let cl = parameters();
    let parties: Vec<usize> = (1..=n).collect();
    let mut meter = Meter::new();
    setup(cl, &parties, t, b"tcl-smoke", &mut meter).expect("setup")
}

#[test]
fn threshold_decryption_round_trip() {
    let keys = keyset(4, 2);
    let mut meter = Meter::new();
    let reference = &keys[&1];
    let tc = &reference.tc;

    let message = Scalar255::from_u64(0xDEADBEEF);
    let rho = tc.cl.sample_dq(&mut tcl::random::fresh_rng());
    let cipher = tc.enc(&reference.cl_public, &message, &rho, &mut meter);

    let quorum = vec![1usize, 2, 3, 4];
    let mut partials = Vec::new();
    for id in &quorum {
        let package = &keys[id];
        let pd = tc.part_dec(&cipher, &package.cl_share, &mut meter);
        let ctx = zkp::context(b"tcl-smoke", b"part-dec", &[*id]);
        let proof = zkp::prove_part_dec(
            tc,
            &ctx,
            &package.cl_public_share,
            &cipher.c0,
            &pd,
            &package.cl_share,
            &mut tcl::random::fresh_rng(),
            &mut meter,
        );
        // The two statements the proof relates must actually hold.
        let base_msg = tc.cl.exp(&cipher.c0, &tc.delta, &mut meter);
        assert_eq!(
            tc.cl.exp(&base_msg, &package.cl_share, &mut meter),
            pd,
            "pd = (c0^Delta)^{{k_i}}"
        );
        assert_eq!(
            tc.cl.exp(&tc.gq_delta, &package.cl_share, &mut meter),
            package.cl_public_share,
            "pk_i = (g_q^Delta)^{{k_i}}"
        );
        assert!(
            zkp::verify_part_dec(
                tc,
                &ctx,
                &package.cl_public_share,
                &cipher.c0,
                &pd,
                &proof,
                &mut meter
            ),
            "partial decryption proof for party {id}"
        );
        partials.push((*id, pd));
    }

    let recovered = tc.combine(&cipher, &partials, &quorum, &mut meter).expect("combine");
    assert_eq!(recovered, message, "t-CL decryption");

    // Any threshold-sized subset decrypts to the same value.
    let subset = vec![2usize, 3];
    let partials: Vec<(usize, QFI)> = subset
        .iter()
        .map(|id| (*id, tc.part_dec(&cipher, &keys[id].cl_share, &mut meter)))
        .collect();
    assert_eq!(
        tc.combine(&cipher, &partials, &subset, &mut meter).unwrap(),
        message
    );
}

#[test]
fn threshold_elgamal_round_trip() {
    let keys = keyset(3, 2);
    let mut meter = Meter::new();
    let reference = &keys[&1];
    let g1 = threshold_bbs::bls381::generator_g1();

    let secret = Scalar255::from_u64(99);
    let message = g1.scale(&secret);
    let randomness = Scalar255::from_u64(1234);
    let cipher = eg::encrypt_with(&g1, &reference.eg_public, &message, &randomness, &mut meter);

    let quorum = vec![1usize, 2, 3];
    let mut partials = BTreeMap::new();
    for id in &quorum {
        let package = &keys[id];
        let pd = eg::part_dec(&package.eg_share, &cipher, &mut meter);
        let ctx = zkp::context(b"tcl-smoke", b"eg-part", &[*id]);
        let proof = zkp::prove_ddh(
            &ctx,
            &g1,
            &package.eg_public_share,
            &cipher.a1,
            &pd,
            &package.eg_share,
            &mut rand_core::OsRng,
            &mut meter,
        );
        assert!(zkp::verify_ddh(
            &ctx,
            &g1,
            &package.eg_public_share,
            &cipher.a1,
            &pd,
            &proof,
            &mut meter
        ));
        partials.insert(*id, pd);
    }
    assert_eq!(
        eg::combine(&cipher, &partials, &quorum, &mut meter),
        message,
        "t-ElG decryption"
    );
}

#[test]
fn ciphertext_encryption_proof() {
    let keys = keyset(2, 2);
    let mut meter = Meter::new();
    let reference = &keys[&1];
    let tc = &reference.tc;

    let message = reference.x_share.clone();
    let rho = tc.cl.sample_dq(&mut tcl::random::fresh_rng());
    let cipher = tc.enc(&reference.cl_public, &message, &rho, &mut meter);
    let ctx = zkp::context(b"tcl-smoke", b"enc", &[1]);
    let statement = zkp::EncStatement {
        ek: &reference.cl_public,
        cipher: &cipher,
        point: Some(&reference.x_public_share),
    };
    let proof = zkp::prove_enc(
        tc,
        &ctx,
        &statement,
        &message,
        &rho,
        &mut tcl::random::fresh_rng(),
        &mut meter,
    );
    let _ = message;
    assert!(zkp::verify_enc(tc, &ctx, &statement, &proof, &mut meter));

    // A different plaintext claim must fail.
    let mut broken = proof.clone();
    broken.response_m = broken.response_m.add(&Scalar255::from_u64(1));
    assert!(!zkp::verify_enc(tc, &ctx, &statement, &broken, &mut meter));
}
