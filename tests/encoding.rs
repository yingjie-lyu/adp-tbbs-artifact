//! Scalar and integer encodings.
//!
//! These are the tests that catch the expensive kind of bug: `bls12_381` reads its wide
//! buffers as little-endian, so a big-endian conversion that is only exercised with 32-byte
//! inputs looks correct and then silently corrupts a 16-byte Fiat–Shamir challenge.

use bicycl::Mpz;
use threshold_bbs::algebra::Scalar;
use threshold_bbs::bls381::Scalar255;
use threshold_bbs::util::{mpz_bytes, mpz_from_bytes, mpz_lt, mpz_to_scalar, pow2, scalar_to_mpz};

#[test]
fn be_bytes_round_trip_for_every_length() {
    for length in 1..=40usize {
        let bytes: Vec<u8> = (0..length)
            .map(|index| (index as u8).wrapping_mul(37).wrapping_add(11))
            .collect();
        let value = Scalar255::from_be_bytes_mod_order(&bytes);
        let round_trip = value.to_be_bytes();
        // Compare against a re-derivation through the same path.
        assert_eq!(
            Scalar255::from_be_bytes_mod_order(&round_trip),
            value,
            "length {length} must round-trip"
        );
    }
}

#[test]
fn short_challenges_map_to_the_same_integer() {
    // A 128-bit challenge must reduce to exactly the same scalar as its canonical encoding.
    let challenge = pow2(100) + Mpz::from(123_456_789u64);
    let bytes = mpz_bytes(&challenge);
    assert_eq!(bytes.len(), 13, "100-bit value plus offset fits 13 bytes");

    let scalar = mpz_to_scalar(&challenge);
    assert_eq!(scalar_to_mpz(&scalar), challenge);
    assert_eq!(Scalar255::from_be_bytes_mod_order(&bytes), scalar);
}

#[test]
fn leading_zero_bytes_do_not_change_the_value() {
    let padded = [0u8, 0, 0, 7];
    assert_eq!(
        Scalar255::from_be_bytes_mod_order(&padded),
        Scalar255::from_u64(7)
    );

    let mut with_zeros = vec![0u8; 5];
    with_zeros.extend_from_slice(&mpz_bytes(&Mpz::from(42u64)));
    assert_eq!(
        Scalar255::from_be_bytes_mod_order(&with_zeros),
        Scalar255::from_u64(42)
    );
}

#[test]
fn mpz_byte_helpers_round_trip() {
    for value in [0u64, 1, 255, 256, 65_537, u64::MAX] {
        let original = Mpz::from(value);
        let restored = mpz_from_bytes(&mpz_bytes(&original));
        assert_eq!(restored, original, "value {value}");
    }
    assert!(mpz_bytes(&Mpz::from(0u64)).is_empty());
}

#[test]
fn mpz_magnitude_order_is_total_on_non_negatives() {
    assert!(mpz_lt(&Mpz::from(9u64), &Mpz::from(10u64)));
    assert!(mpz_lt(&Mpz::from(0u64), &Mpz::from(1u64)));
    assert!(!mpz_lt(&Mpz::from(1u64), &Mpz::from(0u64)));
    assert!(!mpz_lt(&Mpz::from(7u64), &Mpz::from(7u64)));
    assert!(mpz_lt(&pow2(200), &pow2(201)));
    assert!(mpz_lt(&pow2(255), &(pow2(255) + Mpz::from(1u64))));
}

#[test]
fn scalar_bytes_are_canonical() {
    let value = Scalar255::from_u64(1234);
    let bytes = value.to_be_bytes();
    assert_eq!(bytes.len(), 32);
    assert_eq!(bytes[31], 0xd2);
    assert_eq!(bytes[30], 0x04);
    assert_eq!(Scalar255::from_be_bytes_mod_order(&bytes), value);
}
