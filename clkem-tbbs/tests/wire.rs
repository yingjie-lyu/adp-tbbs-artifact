//! Wire format: round trips, canonicality, and the sizes the paper's Table 3 reports.

use bicycl::Mpz;

use clkem_tbbs::keygen::{KeygenCommitMsg, KeygenOpenMsg, PvssMsg, SeedCommitMsg, SeedOpenMsg, ShareMsg};
use clkem_tbbs::params::{Bases, PublicParameters};
use clkem_tbbs::pvss;
use clkem_tbbs::random::fresh_rng;
use clkem_tbbs::sign::{SignCommitMsg, SignOpenMsg, SignShareMsg};
use clkem_tbbs::stats::Meter;
use clkem_tbbs::util::factorial;
use clkem_tbbs::wire;
use clkem_tbbs::zkp::{self, EncProof};

use threshold_bbs::algebra::{Group, Scalar};
use threshold_bbs::bls381::Scalar255;

fn parameters() -> std::sync::Arc<PublicParameters> {
    PublicParameters::production(3)
}

#[test]
fn seed_messages_round_trip() {
    let commit = SeedCommitMsg {
        id: 7,
        commitment: [9u8; 32],
    };
    let decoded = SeedCommitMsg::decode(&commit.encode()).unwrap();
    assert_eq!(decoded.id, commit.id);
    assert_eq!(decoded.commitment, commit.commitment);

    let open = SeedOpenMsg {
        id: 3,
        contribution: [1u8; 32],
    };
    let decoded = SeedOpenMsg::decode(&open.encode()).unwrap();
    assert_eq!(decoded.id, open.id);
    assert_eq!(decoded.contribution, open.contribution);
}

#[test]
fn pvss_messages_round_trip() {
    let pp = parameters();
    let mut meter = Meter::new();
    let mut rng = fresh_rng();
    let delta = factorial(3);
    let value = pp.cl.sample_dq(&mut rng);
    let dealt = pvss::deal(&pp, b"wire", &value, 3, 2, &delta, &mut rng, &mut meter);
    let message = PvssMsg {
        id: 2,
        commitments: dealt.commitments,
        proofs: dealt.proofs,
    };
    let decoded = PvssMsg::decode(&message.encode(), &pp.cl).unwrap();
    assert_eq!(decoded.id, message.id);
    assert_eq!(decoded.commitments, message.commitments);
    assert_eq!(decoded.proofs.len(), message.proofs.len());
    for (lhs, rhs) in decoded.proofs.iter().zip(&message.proofs) {
        assert_eq!(lhs.challenge, rhs.challenge);
        assert_eq!(lhs.response, rhs.response);
    }
}

#[test]
fn share_messages_round_trip_with_signs() {
    let share = ShareMsg {
        from: 4,
        share: Mpz::from(0u64) - Mpz::from(123456789u64),
    };
    let decoded = ShareMsg::decode(&share.encode()).unwrap();
    assert_eq!(decoded.from, share.from);
    assert_eq!(decoded.share.to_string(), share.share.to_string());
}

#[test]
fn keygen_messages_round_trip() {
    let pp = parameters();
    let mut meter = Meter::new();
    let mut rng = fresh_rng();
    let target = pp.cl.exp(pp.cl.gq(), &Mpz::from(11u64), &mut meter);
    let proof = zkp::prove_dl(
        &pp,
        zkp::DOMAIN_DLC,
        b"wire",
        pp.cl.gq(),
        &target,
        &Mpz::from(11u64),
        pp.cl.bound_bq(),
        &mut rng,
        &mut meter,
    );

    let commit = KeygenCommitMsg {
        id: 5,
        d_i: target.clone(),
        d_proof: proof,
        commitment: [3u8; 32],
    };
    let decoded = KeygenCommitMsg::decode(&commit.encode(), &pp.cl).unwrap();
    assert_eq!(decoded.id, commit.id);
    assert_eq!(decoded.d_i, commit.d_i);
    assert_eq!(decoded.commitment, commit.commitment);

    let bases = Bases::derive(&pp, b"wire-bases");
    let open = KeygenOpenMsg {
        id: 5,
        phi_i: target.clone(),
        x_bar_i: pp.cl.identity().clone(),
        x_g2_i: pp.g2.scale(&Scalar255::from_u64(3)),
        bases_i: bases,
        enc_proof: EncProof {
            challenge: Mpz::from(1234u64),
            response_r: Mpz::from(5678u64),
            response_m: Scalar255::from_u64(9),
        },
    };
    let decoded = KeygenOpenMsg::decode(&open.encode(), &pp.cl).unwrap();
    assert_eq!(decoded.id, open.id);
    assert_eq!(decoded.phi_i, open.phi_i);
    assert_eq!(decoded.bases_i.message.len(), open.bases_i.message.len());
    assert_eq!(decoded.x_g2_i, open.x_g2_i);
}

#[test]
fn signing_messages_round_trip() {
    let pp = parameters();
    let mut meter = Meter::new();
    let mut rng = fresh_rng();
    let target = pp.cl.exp(pp.cl.gq(), &Mpz::from(5u64), &mut meter);
    let proof = zkp::prove_dl(
        &pp,
        zkp::DOMAIN_DLS,
        b"wire-sign",
        pp.cl.gq(),
        &target,
        &Mpz::from(5u64),
        pp.cl.bound_b(),
        &mut rng,
        &mut meter,
    );
    let commit = SignCommitMsg {
        id: 2,
        commitment: [4u8; 32],
        phi_gamma: target.clone(),
        proof,
    };
    let decoded = SignCommitMsg::decode(&commit.encode(), &pp.cl).unwrap();
    assert_eq!(decoded.id, commit.id);
    assert_eq!(decoded.phi_gamma, commit.phi_gamma);

    let open = SignOpenMsg {
        id: 2,
        e_i: Scalar255::from_u64(17),
        s_i: Scalar255::from_u64(19),
    };
    let decoded = SignOpenMsg::decode(&open.encode()).unwrap();
    assert_eq!(decoded.e_i, open.e_i);
    assert_eq!(decoded.s_i, open.s_i);

    let share = SignShareMsg {
        id: 2,
        r_i: pp.g1.scale(&Scalar255::from_u64(3)),
        pd_i: target,
    };
    let decoded = SignShareMsg::decode(&share.encode(), &pp.cl).unwrap();
    assert_eq!(decoded.id, share.id);
    assert_eq!(decoded.r_i, share.r_i);
    assert_eq!(decoded.pd_i, share.pd_i);
}

#[test]
fn trailing_bytes_and_non_canonical_forms_are_rejected() {
    let pp = parameters();
    let mut meter = Meter::new();
    let target = pp.cl.exp(pp.cl.gq(), &Mpz::from(2u64), &mut meter);

    let message = SignShareMsg {
        id: 1,
        r_i: pp.g1.scale(&Scalar255::from_u64(1)),
        pd_i: target,
    };
    let mut bytes = message.encode();
    bytes.push(0);
    assert!(SignShareMsg::decode(&bytes, &pp.cl).is_err(), "trailing byte");

    // Flipping the length prefix of the first compressed component breaks canonicity or the
    // discriminant check; either way the decoder must refuse.
    let mut broken = message.encode();
    let index = 8 + 48; // id + R_i, now the form
    broken[index] ^= 0x1f;
    assert!(SignShareMsg::decode(&broken, &pp.cl).is_err());
}

#[test]
fn compressed_forms_are_smaller_than_three_integers() {
    let pp = parameters();
    let mut meter = Meter::new();
    let element = pp.cl.exp(pp.cl.gq(), &Mpz::from(3u64), &mut meter);
    let compressed = wire::qfi_len(&element);
    let raw = element.a().to_bytes().len() + element.b().to_bytes().len() + element.c().to_bytes().len();
    assert!(
        compressed + 20 < raw,
        "DGS compression should beat raw coefficients: {compressed} vs {raw}"
    );
}
