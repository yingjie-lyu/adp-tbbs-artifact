//! `keygen`: four polynomials, blinded commitments, role-A encodings, pairwise seeds.

use bicycl::RandGen;

use threshold_bbs::algebra::{Breakdown, Group, Scalar};
use threshold_bbs::bls381::Scalar255;
use threshold_bbs::keygen::keygen;
use threshold_bbs::params::{PublicParameters, SetupConfig};
use threshold_bbs::shamir;

fn parameters() -> PublicParameters {
    PublicParameters::setup(&SetupConfig::production(2))
}

#[test]
fn every_party_gets_consistent_public_and_secret_state() {
    let pp = parameters();
    let (t, n) = (2usize, 4usize);
    let pkg = keygen(&pp, t, n).unwrap();

    assert_eq!(pkg.secret_shares.len(), n);
    assert_eq!(pkg.public_shares.len(), n);

    for id in 1..=n {
        let secret = pkg.share(id).unwrap();
        let public = pkg.public_share(id).unwrap();
        assert_eq!(secret.id, id);
        assert_eq!(public.id, id);
        assert_eq!(secret.seeds.len(), n - 1, "one seed per peer");

        // X_i = g2^{x_i} h2^{s_i}
        let expected_x = pp.g2.scale(&secret.x_i).combine(&pp.h2.scale(&secret.s_i));
        assert_eq!(public.x_commitment, expected_x);

        // Y_i = g1^{v_i} h1^{s~_i}
        let expected_y = pp
            .g1
            .scale(&secret.v_i)
            .combine(&pp.h1.scale(&secret.s_tilde_i));
        assert_eq!(public.vrf_commitment, expected_y);

        // The role-A encoding opens to x_i.
        assert!(pp.nim.is_form_of(&public.x_encoding));
    }
}

#[test]
fn pairwise_seeds_agree_between_parties() {
    let pp = parameters();
    let pkg = keygen(&pp, 2, 4).unwrap();
    for a in 1..=4 {
        for b in 1..=4 {
            if a == b {
                continue;
            }
            let left = pkg.share(a).unwrap().seed_with(b).unwrap();
            let right = pkg.share(b).unwrap().seed_with(a).unwrap();
            assert_eq!(left, right, "seed between {a} and {b} must match");
        }
    }
}

#[test]
fn shares_interpolate_to_the_public_key() {
    let pp = parameters();
    let pkg = keygen(&pp, 3, 5).unwrap();
    let quorum = [1usize, 3, 5];

    let mut x_at_zero = Scalar255::zero();
    for id in quorum {
        let share = pkg.share(id).unwrap();
        let lambda = shamir::lagrange_at_zero::<Scalar255>(id, &quorum).unwrap();
        x_at_zero = x_at_zero.add(&lambda.mul(&share.x_i));
    }
    assert_eq!(
        pp.g2.scale(&x_at_zero),
        pkg.public_key,
        "pk must equal g2 to the power x(0)"
    );
}

#[test]
fn the_pad_polynomial_vanishes_at_zero() {
    // s(0) = 0 in a real execution, so pk carries no h2 component.
    let pp = parameters();
    let pkg = keygen(&pp, 3, 5).unwrap();
    let quorum = [2usize, 4, 5];
    let mut s_at_zero = Scalar255::zero();
    for id in quorum {
        let share = pkg.share(id).unwrap();
        let lambda = shamir::lagrange_at_zero::<Scalar255>(id, &quorum).unwrap();
        s_at_zero = s_at_zero.add(&lambda.mul(&share.s_i));
    }
    assert_eq!(s_at_zero, Scalar255::zero());
}

#[test]
fn invalid_thresholds_are_refused() {
    let pp = parameters();
    assert!(keygen(&pp, 0, 3).is_err());
    assert!(keygen(&pp, 4, 3).is_err());
    assert!(keygen(&pp, 1, 1).is_ok());
}

#[test]
fn role_a_encoding_decodes_with_the_kept_randomness() {
    let pp = parameters();
    let pkg = keygen(&pp, 2, 3).unwrap();
    let mut rng = RandGen::new();
    let mut stats = Breakdown::default();

    let share = pkg.share(1).unwrap();
    let y = Scalar255::from_u64(555);
    let encoded = pp.nim.encode_b(&y, &mut rng, &mut stats);

    // decode_A(pe_{gamma,j}, r_{x,i}, x_i) = x_i * y
    let share_a = pp
        .nim
        .decode_a(&encoded, &share.randomness_x, &share.x_i, &mut stats);
    // decode_B(pe_{x,i}, r_{gamma,j}) is the matching role-B half.
    let role_a = threshold_bbs::nim::EncodedA {
        element: share.x_encoding.clone(),
        randomness: bicycl::Mpz::from(0u64),
    };
    let share_b = pp.nim.decode_b(&role_a, &encoded.randomness, &mut stats);
    assert_eq!(share_a.add(&share_b), share.x_i.mul(&y));
}
