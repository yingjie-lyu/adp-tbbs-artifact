//! `F_zero`: the quorum's shares must sum to zero, and they must change with the session.

use std::collections::BTreeMap;

use clkem_tbbs::zero::Seeds;

use threshold_bbs::algebra::Scalar;
use threshold_bbs::bls381::Scalar255;

fn views(n: usize) -> Vec<Seeds> {
    let mut contributions = BTreeMap::new();
    for id in 1..=n {
        contributions.insert(id, [id as u8 + 7; 32]);
    }
    (1..=n)
        .map(|id| Seeds::from_contributions(id, &contributions).expect("seeds"))
        .collect()
}

#[test]
fn every_quorum_sums_to_zero() {
    let views = views(5);
    for quorum in [
        vec![1usize, 2],
        vec![2, 4],
        vec![1, 3, 5],
        vec![2, 3, 4],
        vec![1, 2, 3, 4, 5],
    ] {
        let mut total = Scalar255::from_u64(0);
        for id in &quorum {
            let share = views[id - 1]
                .sample(*id, &quorum, b"sid-zero", 0)
                .expect("alpha_i");
            total = total.add(&share);
        }
        assert_eq!(total, Scalar255::from_u64(0), "quorum {quorum:?}");
    }
}

#[test]
fn shares_are_fresh_per_session_and_counter() {
    let views = views(3);
    let quorum = vec![1usize, 2, 3];
    let first = views[0].sample(1, &quorum, b"sid-a", 0).unwrap();
    let second = views[0].sample(1, &quorum, b"sid-b", 0).unwrap();
    let third = views[0].sample(1, &quorum, b"sid-a", 1).unwrap();

    assert_ne!(first, second, "session id must domain-separate");
    assert_ne!(first, third, "the counter must advance the mask");
}

#[test]
fn pairwise_views_agree() {
    let views = views(4);
    let quorum = vec![1usize, 3];
    // Party 1 adds H(beta_13) and party 3 subtracts the same value, so the pair cancels
    // regardless of which side asks.
    let one = views[0].sample(1, &quorum, b"sid", 0).unwrap();
    let three = views[2].sample(3, &quorum, b"sid", 0).unwrap();
    assert_eq!(one.add(&three), Scalar255::from_u64(0));
}

#[test]
fn a_missing_seed_is_reported() {
    let views = views(2);
    let quorum = vec![1usize, 2, 3];
    assert!(views[0].sample(1, &quorum, b"sid", 0).is_err());
}
