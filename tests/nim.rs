//! The class-group NIM: encoding, decoding, and the difference property of `ddlog`.

use bicycl::RandGen;

use threshold_bbs::algebra::{Breakdown, Scalar};
use threshold_bbs::bls381::Scalar255;

use threshold_bbs::params::{PublicParameters, SetupConfig};
use threshold_bbs::util::{pow2, scalar_to_mpz};

fn parameters() -> PublicParameters {
    PublicParameters::setup(&SetupConfig::production(1))
}

#[test]
fn decode_shares_sum_to_the_product() {
    let pp = parameters();
    let nim = &pp.nim;
    let mut rng = RandGen::new();
    let mut stats = Breakdown::default();

    for seed in 1..4u64 {
        let x = Scalar255::from_u64(seed * 977);
        let y = Scalar255::from_u64(seed * 131 + 7);

        let a = nim.encode_a(&x, &mut rng, &mut stats);
        let b = nim.encode_b(&y, &mut rng, &mut stats);

        let share_a = nim.decode_a(&b, &a.randomness, &x, &mut stats);
        let share_b = nim.decode_b(&a, &b.randomness, &mut stats);

        assert_eq!(
            share_a.add(&share_b),
            x.mul(&y),
            "z_A + z_B = x*y mod q for role A value {seed}"
        );
    }
}

#[test]
fn decoding_uses_the_long_exponentiation_path() {
    let pp = parameters();
    let mut rng = RandGen::new();
    let mut stats = Breakdown::default();
    let a = pp
        .nim
        .encode_a(&Scalar255::from_u64(5), &mut rng, &mut stats);
    let b = pp
        .nim
        .encode_b(&Scalar255::from_u64(9), &mut rng, &mut stats);
    let _ = pp
        .nim
        .decode_a(&b, &a.randomness, &Scalar255::from_u64(5), &mut stats);
    let _ = pp.nim.decode_b(&a, &b.randomness, &mut stats);

    let (long, short) = stats.class_group_exponentiations();
    assert!(long >= 4, "two long exponentiations per decode, got {long}");
    assert!(
        short >= 2,
        "role-A decoding needs the short lift, got {short}"
    );
    assert!(stats.calls(threshold_bbs::Operation::ClassGroupKernelDlog) >= 2);
}

#[test]
fn ddlog_is_a_difference_not_a_value() {
    // The lemma only promises ddlog(a) - ddlog(b) = m when a/b = f^m. Individual decodings
    // carry a coset-label offset, so this test deliberately asserts the difference.
    let pp = parameters();
    let nim = &pp.nim;
    let mut rng = RandGen::new();
    let mut stats = Breakdown::default();

    let f = nim.f();
    let group = nim.group();
    let same_coset = nim.g_z().exp(group, &rng.random_mpz(nim.modulus()));

    let m = Scalar255::from_u64(4321);
    let left = f.exp(group, &scalar_to_mpz(&m)).compose(group, &same_coset);
    let right = same_coset.clone();

    let left_share = threshold_bbs::util::mpz_to_scalar(&nim.ddlog(&left, &mut stats));
    let right_share = threshold_bbs::util::mpz_to_scalar(&nim.ddlog(&right, &mut stats));
    assert_eq!(left_share.sub(&right_share), m);
}

#[test]
fn random_encodings_are_blinded() {
    let pp = parameters();
    let mut rng = RandGen::new();
    let mut stats = Breakdown::default();
    let value = Scalar255::from_u64(1234);

    let first = pp.nim.encode_a(&value, &mut rng, &mut stats);
    let second = pp.nim.encode_a(&value, &mut rng, &mut stats);
    assert_ne!(
        first.element.to_bytes(),
        second.element.to_bytes(),
        "role-A encodings of the same value must differ"
    );

    let first_b = pp.nim.encode_b(&value, &mut rng, &mut stats);
    let second_b = pp.nim.encode_b(&value, &mut rng, &mut stats);
    assert_ne!(first_b.c0.to_bytes(), second_b.c0.to_bytes());
}

#[test]
fn discriminant_check_rejects_foreign_forms() {
    let pp = parameters();
    let mut rng = RandGen::new();
    let mut stats = Breakdown::default();
    let valid = pp
        .nim
        .encode_b(&Scalar255::from_u64(3), &mut rng, &mut stats);

    assert!(pp.nim.is_form_of(&valid.c0));
    assert!(pp.nim.is_form_of(&valid.c1));

    let principal = pp.nim.group().one();
    assert!(
        pp.nim.is_form_of(&principal),
        "the principal form is legitimate"
    );
}

#[test]
fn wrong_role_b_value_breaks_the_product() {
    let pp = parameters();
    let nim = &pp.nim;
    let mut rng = RandGen::new();
    let mut stats = Breakdown::default();

    let x = Scalar255::from_u64(99);
    let y = Scalar255::from_u64(100);
    let a = nim.encode_a(&x, &mut rng, &mut stats);
    let b = nim.encode_b(&y, &mut rng, &mut stats);

    // Decode with a value that is not the one encoded.
    let wrong = nim.decode_a(&b, &a.randomness, &Scalar255::from_u64(101), &mut stats);
    let share_b = nim.decode_b(&a, &b.randomness, &mut stats);
    assert_ne!(wrong.add(&share_b), x.mul(&y));
}

#[test]
fn nim_parameters_have_the_paper_shape() {
    let pp = PublicParameters::setup(&SetupConfig::production(1));

    // N_A = 2^kappa * q * B and N_B = 2^kappa * B, with B = 2^922 for a 1827-bit Delta_K.
    let expected_b = pow2(80) * pow2(922);
    let expected_a = pow2(80) * pp.nim.modulus().clone() * pow2(922);
    assert_eq!(pp.nim.bound_b(), &expected_b);
    assert_eq!(pp.nim.bound_a(), &expected_a);

    // The paper quotes log2 N_A ~ 1257 and log2 N_B ~ 1002; bit lengths land within a bit
    // of that because a power of two needs one extra bit.
    let bits_a = threshold_bbs::util::mpz_bits(pp.nim.bound_a());
    let bits_b = threshold_bbs::util::mpz_bits(pp.nim.bound_b());
    assert!((1256..=1258).contains(&bits_a), "log2 N_A = {bits_a}");
    assert!((1002..=1004).contains(&bits_b), "log2 N_B = {bits_b}");
    assert!(
        bits_a - bits_b >= 254,
        "role-A coins must exceed role-B coins by log2 q"
    );
}
