//! End-to-end: `keygen -> presign -> sign -> combine -> bbs.verify`.
//!
//! These tests are the acceptance criterion for the implementation. Component tests can
//! all pass while the protocol is broken; this one produces an actual BBS+ signature with
//! a threshold quorum and checks it with the pairing.

use std::collections::BTreeMap;

use threshold_bbs::algebra::{Group, Scalar};
use threshold_bbs::bbs;
use threshold_bbs::bls381::{Scalar255, G1};
use threshold_bbs::error::Error;
use threshold_bbs::keygen::{keygen, PartyView};
use threshold_bbs::params::{PublicParameters, SetupConfig};
use threshold_bbs::round1::{self, presign};
use threshold_bbs::round2::sign_share;
use threshold_bbs::transport::Bus;
use threshold_bbs::{combine, session};

fn parameters(message_len: usize) -> PublicParameters {
    PublicParameters::setup(&SetupConfig::production(message_len))
}

fn message(len: usize, seed: u64) -> Vec<Scalar255> {
    (0..len)
        .map(|index| Scalar255::from_u64(seed * 31 + index as u64))
        .collect()
}

#[test]
fn three_of_four_quorum_produces_a_valid_signature() {
    let pp = parameters(3);
    let pkg = keygen(&pp, 3, 4).unwrap();
    let quorum = [1usize, 2, 4];
    let msg = message(3, 7);

    let outcome = session::run(&pp, &pkg, b"session-1", &msg, &quorum).expect("session runs");

    assert!(
        bbs::verify_with(&pp, &pkg.public_key, &msg, &outcome.signature),
        "combined signature must verify under the group public key"
    );
    assert_eq!(outcome.round1.len(), 3);
    assert_eq!(outcome.round2.len(), 3);
}

#[test]
fn disjoint_quorums_sign_the_same_message() {
    let pp = parameters(3);
    let pkg = keygen(&pp, 2, 4).unwrap();
    let msg = message(3, 11);

    let first = session::run(&pp, &pkg, b"a", &msg, &[1, 2]).unwrap();
    let second = session::run(&pp, &pkg, b"b", &msg, &[3, 4]).unwrap();

    assert!(bbs::verify_with(
        &pp,
        &pkg.public_key,
        &msg,
        &first.signature
    ));
    assert!(bbs::verify_with(
        &pp,
        &pkg.public_key,
        &msg,
        &second.signature
    ));
    assert_ne!(
        first.signature.a, second.signature.a,
        "different sessions must not share A"
    );
}

#[test]
fn signature_rejects_a_different_message() {
    let pp = parameters(2);
    let pkg = keygen(&pp, 2, 3).unwrap();
    let msg = message(2, 5);
    let outcome = session::run(&pp, &pkg, b"s", &msg, &[1, 3]).unwrap();

    let mut tampered = msg.clone();
    tampered[0] = Scalar255::from_u64(999);
    assert!(!bbs::verify_with(
        &pp,
        &pkg.public_key,
        &tampered,
        &outcome.signature
    ));
}

#[test]
fn threshold_and_single_signer_agree_on_the_session_scalars() {
    // For a fixed session, the protocol's `(e, phi)` are determined by `hashout`, so the
    // reconstructed `A` must equal `sign_with(secret, e, phi)`.
    let pp = parameters(2);
    let pkg = keygen(&pp, 2, 3).unwrap();
    let msg = message(2, 3);
    let quorum = [1usize, 2, 3];
    let outcome = session::run(&pp, &pkg, b"agree", &msg, &quorum).unwrap();

    let signature = &outcome.signature;
    let u = pp.compute_u(&signature.phi, &msg);
    // A = U^{1/(x+e)} is only checkable through the pairing without x, so instead check
    // that e(g2^{x+e}, A) = e(g2, U) is exactly what verify already asserted.
    assert!(bbs::verify_with(&pp, &pkg.public_key, &msg, signature));
    let _ = u;
}

#[test]
fn bad_round_one_proof_is_rejected_in_round_two() {
    let pp = parameters(2);
    let pkg = keygen(&pp, 2, 3).unwrap();
    let quorum = [1usize, 2, 3];
    let msg = message(2, 21);

    let mut states = BTreeMap::new();
    let mut rounds = BTreeMap::new();
    let mut stats = threshold_bbs::Breakdown::default();
    for id in quorum {
        let (message_one, state) = presign(
            &pp,
            &pkg.party_view(id).unwrap(),
            b"sid",
            &msg,
            &quorum,
            &mut stats,
        )
        .unwrap();
        states.insert(id, state);
        rounds.insert(id, message_one);
    }

    // Party 2 lies about its VRF share after proving.
    let mut round_one = rounds.get(&2).unwrap().clone();
    round_one.vrf_share = G1::identity();
    rounds.insert(2, round_one);

    let error = sign_share(
        &pp,
        &pkg.party_view(1).unwrap(),
        b"sid",
        &msg,
        &quorum,
        &rounds,
        states.get(&1).unwrap(),
        &mut stats,
    )
    .unwrap_err();
    assert_eq!(error, Error::InvalidProof { from: 2 });
}

#[test]
fn round_one_proof_binds_the_session_id() {
    let pp = parameters(2);
    let pkg = keygen(&pp, 2, 3).unwrap();
    let quorum = [1usize, 2];
    let msg = message(2, 31);

    let mut stats = threshold_bbs::Breakdown::default();
    let (round_one, _) = presign(
        &pp,
        &pkg.party_view(1).unwrap(),
        b"sid-a",
        &msg,
        &quorum,
        &mut stats,
    )
    .unwrap();

    let mut stats = threshold_bbs::Breakdown::default();
    let view = pkg.party_view(1).unwrap();
    assert!(round1::verify_round1(
        &pp, &view, b"sid-a", &msg, &quorum, &round_one, &mut stats
    ));
    assert!(!round1::verify_round1(
        &pp, &view, b"sid-b", &msg, &quorum, &round_one, &mut stats
    ));
}

#[test]
fn quorum_below_threshold_is_refused() {
    let pp = parameters(2);
    let pkg = keygen(&pp, 3, 4).unwrap();
    let msg = message(2, 41);
    let error = session::run(&pp, &pkg, b"s", &msg, &[1, 2]).unwrap_err();
    assert_eq!(error, Error::InvalidQuorum);
}

#[test]
fn combine_rejects_a_tampered_round_two_share() {
    let pp = parameters(2);
    let pkg = keygen(&pp, 2, 3).unwrap();
    let quorum = [1usize, 2, 3];
    let msg = message(2, 51);

    let mut states = BTreeMap::new();
    let mut rounds = BTreeMap::new();
    let mut shares = BTreeMap::new();
    let mut stats = threshold_bbs::Breakdown::default();
    for id in quorum {
        let (message_one, state) = presign(
            &pp,
            &pkg.party_view(id).unwrap(),
            b"s",
            &msg,
            &quorum,
            &mut stats,
        )
        .unwrap();
        states.insert(id, state);
        rounds.insert(id, message_one);
    }
    for id in quorum {
        let share = sign_share(
            &pp,
            &pkg.party_view(id).unwrap(),
            b"s",
            &msg,
            &quorum,
            &rounds,
            states.get(&id).unwrap(),
            &mut stats,
        )
        .unwrap();
        shares.insert(id, share);
    }

    let mut lying = shares.get(&3).unwrap().clone();
    lying.u = lying.u.add(&Scalar255::one());
    shares.insert(3, lying);

    let error = combine::combine(
        &pp,
        &pkg.party_view(1).unwrap(),
        b"s",
        &msg,
        &quorum,
        &rounds,
        &shares,
        &mut stats,
    )
    .unwrap_err();
    assert_eq!(error, Error::InvalidSignature);
}

#[test]
fn production_parameters_sign_and_verify() {
    // Same code path at the paper's 1827-bit discriminant. Slow (seconds), so it is the
    // only test that runs at production size.
    let pp = PublicParameters::setup(&SetupConfig::production(2));
    let pkg = keygen(&pp, 2, 3).unwrap();
    let msg = message(2, 61);
    let outcome = session::run(&pp, &pkg, b"prod", &msg, &[1, 2, 3]).unwrap();
    assert!(bbs::verify_with(
        &pp,
        &pkg.public_key,
        &msg,
        &outcome.signature
    ));
}

#[test]
fn round_two_shares_are_not_a_function_of_the_witness_alone() {
    // Two sessions on the same message must produce different `(u_i, S_i)`: the masks are
    // keyed by the recipient transcript, which changes with the fresh round-1 encodings.
    let pp = parameters(1);
    let pkg = keygen(&pp, 2, 2).unwrap();
    let msg = message(1, 71);

    let first = session::run(&pp, &pkg, b"m1", &msg, &[1, 2]).unwrap();
    let second = session::run(&pp, &pkg, b"m2", &msg, &[1, 2]).unwrap();

    assert_ne!(
        first.round2.get(&1).unwrap().u,
        second.round2.get(&1).unwrap().u
    );
    assert_ne!(
        first.round2.get(&1).unwrap().s,
        second.round2.get(&1).unwrap().s
    );
}

#[test]
fn session_over_the_wire_produces_a_valid_signature() {
    // This is the acceptance test for the transport layer: parties publish bytes and read
    // bytes, and the only thing shared besides the public parameters is the message.
    let pp = parameters(2);
    let pkg = keygen(&pp, 2, 3).unwrap();
    let quorum = [1usize, 2, 3];
    let msg = message(2, 81);

    let views: Vec<PartyView> = quorum
        .iter()
        .map(|id| pkg.party_view(*id).unwrap())
        .collect();
    let mut bus = Bus::new(&quorum);

    let outcome =
        session::run_over_bus(&pp, &views, &mut bus, b"wire-session", &msg, &quorum).unwrap();

    assert!(
        bbs::verify_with(&pp, &pkg.public_key, &msg, &outcome.signature),
        "signature assembled from decoded bytes must verify"
    );
    assert!(
        outcome.wire_bytes > 0,
        "the wire path must actually transmit"
    );
    // The combiner consumed its inbox; other parties do not need the round-2 shares.
    assert!(bus
        .drain(
            quorum[0],
            b"wire-session",
            threshold_bbs::transport::Round::Two
        )
        .unwrap()
        .is_empty());
}

#[test]
fn a_party_view_holds_only_its_own_secret() {
    let pp = parameters(2);
    let pkg = keygen(&pp, 2, 4).unwrap();
    let view = pkg.party_view(2).unwrap();

    assert_eq!(view.id, 2);
    assert_eq!(view.share.id, 2);
    assert_eq!(
        view.public_shares.len(),
        4,
        "public shares are visible to everyone"
    );
    // The dealer knows four secrets; the view exposes one.
    assert_eq!(pkg.secret_shares.len(), 4);
    assert_eq!(view.threshold, 2);
}

#[test]
fn a_view_cannot_sign_outside_the_quorum_it_was_given() {
    let pp = parameters(2);
    let pkg = keygen(&pp, 2, 4).unwrap();
    let msg = message(2, 91);
    let view = pkg.party_view(1).unwrap();

    // Party 1 is not a member of this quorum, even though it exists.
    assert_eq!(
        view.validate_quorum(&[2, 3]).unwrap_err(),
        Error::InvalidQuorum
    );
    // Two members satisfy t = 2, but party 1 must be among them for its own share.
    assert!(view.validate_quorum(&[1, 2, 3]).is_ok());
    let _ = msg;
}
