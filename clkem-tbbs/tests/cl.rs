//! CL framework and CL-KEM sanity: `Encap`/`Decap` agree, `CL.Solve` recovers the kernel
//! exponent, and the modified scaling really does hide the exponent mod `q`.

use bicycl::Mpz;

use clkem_tbbs::cl::{self, ClParameters};
use clkem_tbbs::params::PublicParameters;
use clkem_tbbs::stats::Meter;

use threshold_bbs::algebra::Scalar;
use threshold_bbs::bls381::Scalar255;

fn parameters() -> std::sync::Arc<PublicParameters> {
    PublicParameters::production(2)
}

#[test]
fn encap_and_decap_agree() {
    let pp = parameters();
    let class = &pp.cl;
    let mut meter = Meter::new();
    let mut rng = clkem_tbbs::random::fresh_rng();

    // A stand-alone CL key pair, exactly as the DKG produces one.
    let sk = class.sample_dq(&mut rng);
    let pk = class.exp(class.gq(), &sk, &mut meter);

    let r = class.sample_dq(&mut rng);
    let (phi, key) = cl::encap(class, &pk, &r, &mut meter);
    let recovered = class.exp(&phi, &sk, &mut meter);
    assert_eq!(key, recovered, "K = phi^sk");

    let message = Scalar255::from_u64(12345);
    let cipher = cl::dem(class, &key, &message, &mut meter);
    // Decap removes the hard component exactly, leaving f^m in the kernel.
    let kernel = class.compose(&cipher, &class.invert(&recovered, &mut meter), &mut meter);
    assert_eq!(class.solve(&kernel, &mut meter), message, "Dem, Decap, Solve");
}

#[test]
fn solve_is_defined_on_the_kernel() {
    let pp = parameters();
    let class = &pp.cl;
    let mut meter = Meter::new();

    // CL.Solve recovers the exponent of a kernel element, including one built by composition.
    let (a, b) = (Scalar255::from_u64(987654321), Scalar255::from_u64(123456789));
    let element = class.compose(&class.f_exp(&a), &class.f_exp(&b), &mut meter);
    assert_eq!(
        class.solve(&element, &mut meter),
        a.add(&b),
        "CL.Solve is exact on <f>"
    );

    // It is *not* defined on elements with a hard component: the projection onto the kernel
    // carries a coset-label offset, which is why the protocol only ever solves an exact
    // kernel element (prod pd_j = f^{Delta^2 gamma (x+e)}).
    let mut rng = clkem_tbbs::random::fresh_rng();
    let hard = class.exp(class.gq(), &class.sample_dq(&mut rng), &mut meter);
    let mixed = class.compose(&hard, &element, &mut meter);
    assert_ne!(class.solve(&mixed, &mut meter), a.add(&b));
}

#[test]
fn scaling_by_a_wide_exponent_keeps_the_kernel_component() {
    let pp = parameters();
    let class = &pp.cl;
    let mut meter = Meter::new();
    let mut rng = clkem_tbbs::random::fresh_rng();

    let sk = class.sample_dq(&mut rng);
    let pk = class.exp(class.gq(), &sk, &mut meter);
    let r = class.sample_dq(&mut rng);
    let (phi, key) = cl::encap(class, &pk, &r, &mut meter);

    let message = Scalar255::from_u64(7);
    let cipher = cl::dem(class, &key, &message, &mut meter);

    // The modified scaling: phi^(a+qr) and cipher^(a+qr), with a = gamma in [0, B).
    let gamma = class.sample_d(&mut rng);
    let scaled_phi = class.exp(&phi, &gamma, &mut meter);
    let scaled_cipher = class.exp(&cipher, &gamma, &mut meter);

    // Both scale by the same exponent, so Decap commutes with the scaling.
    assert_eq!(
        class.exp(&scaled_phi, &sk, &mut meter),
        // K^gamma is what the signer multiplies into the symmetric component.
        class.exp(&key, &gamma, &mut meter)
    );
    // And the kernel exponent is gamma * message mod q, once the hard part is removed.
    let scaled_key = class.exp(&key, &gamma, &mut meter);
    let kernel = class.compose(&scaled_cipher, &class.invert(&scaled_key, &mut meter), &mut meter);
    let expected = threshold_bbs::util::mpz_to_scalar(&gamma).mul(&message);
    assert_eq!(class.solve(&kernel, &mut meter), expected);
}

#[test]
fn randomness_bounds_follow_the_paper() {
    let pp = parameters();
    let class: &ClParameters = &pp.cl;
    let q = class.modulus();
    // B = q * B_q, and B_q = 2^{lambda_d} * s_bar with s_bar ~ sqrt(|Delta_K|).
    let expected = q.clone() * class.bound_bq().clone();
    assert_eq!(*class.bound_b(), expected);

    let bits = threshold_bbs::util::mpz_bits(class.bound_bq());
    let delta_bits = pp.config.delta_k_bits;
    assert_eq!(delta_bits, 1827);
    let expected_bits = delta_bits / 2 + pp.config.lambda_d;
    assert!(
        bits.abs_diff(expected_bits) <= 40,
        "B_q should be about {expected_bits} bits, got {bits}"
    );
}

#[test]
fn forms_are_recognised() {
    let pp = parameters();
    let mut meter = Meter::new();
    let element = pp.cl.exp(pp.cl.gq(), &Mpz::from(3u64), &mut meter);
    assert!(pp.cl.is_form(&element));
    let bogus = bicycl::QFI::from_mpz(&Mpz::from(5u64), &Mpz::from(7u64), &Mpz::from(11u64));
    assert!(!pp.cl.is_form(&bogus));
}
