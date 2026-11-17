//! Adversarial cases: every field of pass 2 is load-bearing, and a swapped `beta_1` cannot be
//! papered over.

use twopass_bbs::cl;
use twopass_bbs::error::Error;
use twopass_bbs::meter::Meter;
use twopass_bbs::params::PublicParameters;
use twopass_bbs::session::run_dkg;
use twopass_bbs::sign::{SignerOne, SignerTwo};

use threshold_bbs::algebra::{Group, Scalar};
use threshold_bbs::bls381::Scalar255;

fn pair(params: &std::sync::Arc<PublicParameters>, session: &[u8]) -> (SignerOne, SignerTwo) {
    let mut meter = Meter::new();
    let outcome = run_dkg(params.clone(), session, &mut meter).expect("dkg");
    (SignerOne::new(outcome.first), SignerTwo::new(outcome.second))
}

fn message() -> Vec<Scalar255> {
    vec![Scalar255::from_u64(31), Scalar255::from_u64(32)]
}

#[test]
fn an_honest_run_through_the_same_harness_passes() {
    let params = PublicParameters::production(2);
    let (mut first, mut second) = pair(&params, b"neg-honest");
    let mut meter = Meter::new();
    let message = message();

    let pass1 = first.pass1(&message, b"sid", &mut meter).expect("pass1");
    let pass2 = second
        .pass2(&pass1, &message, b"sid", &mut meter)
        .expect("pass2");
    first
        .output(&pass2, &message, b"sid", &mut meter)
        .expect("output");
}

#[test]
fn a_forged_vrf_proof_is_rejected() {
    let params = PublicParameters::production(2);
    let (mut first, mut second) = pair(&params, b"neg-vrf");
    let mut meter = Meter::new();
    let message = message();

    let pass1 = first.pass1(&message, b"sid", &mut meter).expect("pass1");
    let mut pass2 = second
        .pass2(&pass1, &message, b"sid", &mut meter)
        .expect("pass2");
    pass2.vrf_proof.response = pass2.vrf_proof.response.add(&Scalar255::from_u64(1));

    let result = first.output(&pass2, &message, b"sid", &mut meter);
    assert!(matches!(result, Err(Error::Verify("VRF proof"))), "{result:?}");
}

#[test]
fn a_swapped_c_is_rejected() {
    let params = PublicParameters::production(2);
    let (mut first, mut second) = pair(&params, b"neg-c");
    let mut meter = Meter::new();
    let message = message();

    let pass1 = first.pass1(&message, b"sid", &mut meter).expect("pass1");
    let mut pass2 = second
        .pass2(&pass1, &message, b"sid", &mut meter)
        .expect("pass2");
    pass2.c = params.g1.scale(&Scalar255::from_u64(3));

    let result = first.output(&pass2, &message, b"sid", &mut meter);
    assert!(matches!(result, Err(Error::Verify(_))), "{result:?}");
}

#[test]
fn a_corrupted_ciphertext_is_rejected() {
    let params = PublicParameters::production(2);
    let (mut first, mut second) = pair(&params, b"neg-d");
    let mut meter = Meter::new();
    let message = message();

    let pass1 = first.pass1(&message, b"sid", &mut meter).expect("pass1");
    let mut pass2 = second
        .pass2(&pass1, &message, b"sid", &mut meter)
        .expect("pass2");
    // Add f^1 to the symmetric component: D now decrypts to r(x+e) + 1.
    pass2.d.c2 = params
        .cl
        .compose(&pass2.d.c2, &params.cl.f_exp(&Scalar255::from_u64(1)), &mut meter);

    let result = first.output(&pass2, &message, b"sid", &mut meter);
    assert!(matches!(result, Err(Error::Verify(_))), "{result:?}");
}

#[test]
fn a_tampered_w_breaks_the_pairing_check() {
    let params = PublicParameters::production(2);
    let (mut first, mut second) = pair(&params, b"neg-w");
    let mut meter = Meter::new();
    let message = message();

    let pass1 = first.pass1(&message, b"sid", &mut meter).expect("pass1");
    let mut pass2 = second
        .pass2(&pass1, &message, b"sid", &mut meter)
        .expect("pass2");
    pass2.lin_proof.w = params.g1.scale(&Scalar255::from_u64(7));

    let result = first.output(&pass2, &message, b"sid", &mut meter);
    assert!(matches!(result, Err(Error::Verify(_))), "{result:?}");
}

#[test]
fn a_swapped_beta1_is_caught() {
    let params = PublicParameters::production(2);
    let (mut first, mut second) = pair(&params, b"neg-beta");
    let mut meter = Meter::new();
    let message = message();

    let pass1 = first.pass1(&message, b"sid", &mut meter).expect("pass1");
    let mut swapped = pass1.clone();
    swapped.beta1[0] ^= 1;
    // P_2 answers the altered beta_1, so the nonces it derives differ from P_1's.
    let pass2 = second
        .pass2(&swapped, &message, b"sid", &mut meter)
        .expect("pass2");

    let result = first.output(&pass2, &message, b"sid", &mut meter);
    assert!(matches!(result, Err(Error::Verify(_))), "{result:?}");
}

#[test]
fn a_ciphertext_must_be_a_form_of_the_right_discriminant() {
    let params = PublicParameters::production(2);
    let mut meter = Meter::new();
    let mut rng = twopass_bbs::random::fresh_rng();
    let (ek, dk) = cl::keygen(&params.cl, &mut rng, &mut meter);
    let cipher = cl::encrypt(
        &params.cl,
        &ek,
        &Scalar255::from_u64(5),
        &params.cl.sample_dq(&mut rng),
        &mut meter,
    );

    // Decryption of an honest ciphertext recovers the plaintext.
    assert_eq!(
        cl::decrypt(&params.cl, &dk, &cipher, &mut meter).unwrap(),
        Scalar255::from_u64(5)
    );

    // A form that is not of Delta_q is refused before it reaches BICYCL.
    let bogus = bicycl::QFI::from_mpz(
        &bicycl::Mpz::from(5u64),
        &bicycl::Mpz::from(7u64),
        &bicycl::Mpz::from(11u64),
    );
    let broken = cl::Cipher {
        c1: cipher.c1.clone(),
        c2: bogus,
    };
    assert!(cl::decrypt(&params.cl, &dk, &broken, &mut meter).is_err());
}
