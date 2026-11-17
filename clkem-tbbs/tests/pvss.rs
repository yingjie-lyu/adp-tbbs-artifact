//! PVSS: shares pass `SScheck`, `Delta L_i(0)` reconstructs `Delta^2 v`, and tampering is
//! caught.

use bicycl::Mpz;

use clkem_tbbs::params::PublicParameters;
use clkem_tbbs::pvss;
use clkem_tbbs::random::fresh_rng;
use clkem_tbbs::stats::Meter;
use clkem_tbbs::util::{add, factorial, mul, square};

fn parameters() -> std::sync::Arc<PublicParameters> {
    PublicParameters::production(1)
}

#[test]
fn shares_pass_the_public_check() {
    let pp = parameters();
    let (n, t) = (5usize, 3usize);
    let delta = factorial(n);
    let mut meter = Meter::new();
    let mut rng = fresh_rng();

    let value = pp.cl.sample_dq(&mut rng);
    let dealt = pvss::deal(&pp, b"pvss-test", &value, n, t, &delta, &mut rng, &mut meter);

    assert_eq!(dealt.commitments.len(), t);
    assert!(pvss::verify_deal(
        &pp,
        b"pvss-test",
        &delta,
        &dealt.commitments,
        &dealt.proofs,
        n,
        t,
        &mut meter
    ));

    for index in 1..=n {
        assert!(
            pvss::check_share(&pp.cl, &dealt.commitments, &delta, index, &dealt.shares[index - 1], &mut meter),
            "party {index} share"
        );
    }

    // A corrupted share breaks the check.
    let tampered = add(&dealt.shares[0], &Mpz::from(1u64));
    assert!(!pvss::check_share(&pp.cl, &dealt.commitments, &delta, 1, &tampered, &mut meter));
}

#[test]
fn any_threshold_subset_reconstructs_the_secret() {
    let pp = parameters();
    let (n, t) = (5usize, 3usize);
    let delta = factorial(n);
    let mut meter = Meter::new();
    let mut rng = fresh_rng();
    let value = pp.cl.sample_dq(&mut rng);
    let dealt = pvss::deal(&pp, b"pvss-reconstruct", &value, n, t, &delta, &mut rng, &mut meter);

    let quorums: Vec<Vec<usize>> = vec![
        vec![1, 2, 3],
        vec![1, 4, 5],
        vec![2, 3, 4],
        vec![3, 4, 5],
        vec![1, 2, 5],
    ];
    for quorum in quorums {
        let mut total = Mpz::from(0u64);
        for id in &quorum {
            let weight = pvss::delta_lagrange(&delta, *id, &quorum);
            total = add(&total, &mul(&weight, &dealt.shares[id - 1]));
        }
        // sum_i Delta L_i(0) y_i = Delta^2 v
        assert_eq!(total, mul(&square(&delta), &value), "quorum {quorum:?}");
    }
}

#[test]
fn lagrange_coefficients_sum_to_delta() {
    let delta = factorial(6);
    for quorum in [vec![1, 2], vec![2, 5], vec![1, 3, 6], vec![2, 3, 4, 5]] {
        assert!(
            pvss::check_lagrange_unit(&delta, &quorum),
            "quorum {quorum:?}"
        );
    }
}

#[test]
fn a_bad_commitment_proof_is_rejected() {
    let pp = parameters();
    let (n, t) = (3usize, 2usize);
    let delta = factorial(n);
    let mut meter = Meter::new();
    let mut rng = fresh_rng();
    let value = pp.cl.sample_dq(&mut rng);
    let mut dealt = pvss::deal(&pp, b"pvss-bad", &value, n, t, &delta, &mut rng, &mut meter);

    // Replace C_1 with a commitment to a different coefficient.
    let other = pp.cl.sample_dq(&mut rng);
    let bogus = pp
        .cl
        .exp(&pp.cl.gq_pow_delta(&delta, &mut meter), &other, &mut meter);
    dealt.commitments[1] = bogus;

    assert!(
        !pvss::verify_deal(&pp, b"pvss-bad", &delta, &dealt.commitments, &dealt.proofs, n, t, &mut meter),
        "proof no longer matches the commitment"
    );
}
