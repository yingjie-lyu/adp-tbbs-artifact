//! The single-base instantiation of Appendix `sec:sb`, in both coin lengths.
//!
//! These are the two variants the paper benchmarks next to the two-base construction: the
//! role-B encoding is one class-group element instead of a pair, and with short coins the
//! role-B exponentiations become short rather than long.

use threshold_bbs::algebra::Scalar;
use threshold_bbs::bls381::Scalar255;
use threshold_bbs::keygen::keygen;
use threshold_bbs::nim::NimVariant;
use threshold_bbs::params::{PublicParameters, SetupConfig};
use threshold_bbs::{bbs, session, wire};

fn message(len: usize) -> Vec<Scalar255> {
    (0..len)
        .map(|index| Scalar255::from_u64(index as u64 + 1))
        .collect()
}

/// Run one full session for the given variant and return `(round-1 wire bytes, verified)`.
fn run(short: bool) -> (usize, bool) {
    let pp = PublicParameters::setup(&SetupConfig::single_base(2, short));
    assert_eq!(
        pp.nim.variant(),
        if short {
            NimVariant::SingleBaseShort
        } else {
            NimVariant::SingleBase
        }
    );

    let package = keygen(&pp, 3, 4).expect("keygen");
    let quorum = [1usize, 2, 3];
    let message = message(2);
    let views: Vec<_> = quorum
        .iter()
        .map(|id| package.party_view(*id).unwrap())
        .collect();

    let outcome = session::run_views(&pp, &views, b"single-base", &message, &quorum)
        .expect("session");
    let verified = bbs::verify_with(&pp, &package.public_key, &message, &outcome.signature);

    let round_one = outcome.round1.get(&quorum[0]).expect("round-1 message");
    let mut bytes = Vec::new();
    wire::encode_round1(&mut bytes, round_one, &pp.nim);
    let decoded = wire::decode_round1(&bytes, &pp.nim).expect("decode");
    assert_eq!(decoded.c0, round_one.c0);
    assert_eq!(decoded.proof.z_r, round_one.proof.z_r);

    (bytes.len(), verified)
}

#[test]
fn single_base_full_coins_sign() {
    let (bytes, verified) = run(false);
    assert!(verified, "single-base signature must verify");
    // 8 (id) + 48 (W_i) + 48 (Gamma_i) + ~220 (one class-group element) + ~296 (proof).
    assert!(
        (600..640).contains(&bytes),
        "round-1 message was {bytes} bytes, expected ~620"
    );
}

#[test]
fn single_base_short_coins_sign() {
    let (bytes, verified) = run(true);
    assert!(verified, "single-base short-coin signature must verify");
    // Same minus the shorter z_r: ~519 bytes plus the 8-byte id.
    assert!(
        (505..545).contains(&bytes),
        "round-1 message was {bytes} bytes, expected ~527"
    );
}

#[test]
fn short_coins_shrink_the_proof_by_about_ninety_bytes() {
    let (full, _) = run(false);
    let (short, _) = run(true);
    assert!(
        full - short > 70,
        "short coins should save ~90 bytes, got {}",
        full - short
    );
}
