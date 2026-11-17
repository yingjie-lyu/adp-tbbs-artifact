//! The Σ-protocol for the presigning relation.
//!
//! The last test here is the important one: it pins the assumption that makes the
//! Fiat–Shamir compilation work, namely that a verifier rebuilding the five commitments
//! from `(c, z)` obtains *byte-identical* encodings of what the prover committed to.

use bicycl::RandGen;

use threshold_bbs::algebra::{Group, Scalar};
use threshold_bbs::bls381::Scalar255;
use threshold_bbs::hash::hashvrf;
use threshold_bbs::params::{PublicParameters, SetupConfig};
use threshold_bbs::sigma::{self, Statement, Witness};

struct Fixture {
    pp: PublicParameters,
    statement: Statement,
    witness: Witness,
}

fn fixture(message_len: usize, id: usize, quorum: Vec<usize>) -> Fixture {
    let pp = PublicParameters::setup(&SetupConfig::production(message_len));
    let session = b"session-42";
    let message = pp.encode_message(&vec![Scalar255::from_u64(9); message_len]);
    let (base_1, base_2) = hashvrf(session, &message, &quorum);

    let v = Scalar255::from_u64(1111);
    let s_tilde = Scalar255::from_u64(2222);
    let gamma = Scalar255::from_u64(3333);
    let rho = Scalar255::from_u64(4444);

    let mut rng = RandGen::new();
    let mut stats = threshold_bbs::Breakdown::default();
    let encoded = pp.nim.encode_b(&gamma, &mut rng, &mut stats);

    let statement = Statement {
        id,
        session: session.to_vec(),
        message,
        quorum,
        base_1: base_1.clone(),
        base_2: base_2.clone(),
        vrf_commitment: pp.g1.scale(&v).combine(&pp.h1.scale(&s_tilde)),
        vrf_share: base_1.scale(&v).combine(&base_2.scale(&s_tilde)),
        gamma_commitment: pp.g1.scale(&gamma).combine(&pp.hh.scale(&rho)),
        c0: encoded.c0,
        c1: encoded.c1,
    };
    let witness = Witness {
        v_i: v,
        s_tilde_i: s_tilde,
        gamma_i: gamma,
        rho_i: rho,
        randomness_gamma: encoded.randomness,
    };
    Fixture {
        pp,
        statement,
        witness,
    }
}

#[test]
fn honest_proof_verifies() {
    let fixture = fixture(2, 1, vec![1, 2]);
    let mut stats = threshold_bbs::Breakdown::default();
    let proof = sigma::prove(
        &fixture.pp,
        &fixture.statement,
        &fixture.witness,
        &mut stats,
    );
    assert!(sigma::verify(
        &fixture.pp,
        &fixture.statement,
        &proof,
        &mut stats
    ));
}

#[test]
fn tampered_responses_are_rejected() {
    let fixture = fixture(2, 1, vec![1, 2]);
    let mut stats = threshold_bbs::Breakdown::default();
    let proof = sigma::prove(
        &fixture.pp,
        &fixture.statement,
        &fixture.witness,
        &mut stats,
    );

    for tamper in 0..5 {
        let mut broken = proof.clone();
        match tamper {
            0 => broken.z_v = broken.z_v.add(&Scalar255::one()),
            1 => broken.z_s = broken.z_s.add(&Scalar255::one()),
            2 => broken.z_gamma = broken.z_gamma.add(&Scalar255::one()),
            3 => broken.z_rho = broken.z_rho.add(&Scalar255::one()),
            _ => broken.z_r = broken.z_r.clone() + bicycl::Mpz::from(1u64),
        }
        assert!(
            !sigma::verify(&fixture.pp, &fixture.statement, &broken, &mut stats),
            "tampered response {tamper} must be rejected"
        );
    }
}

#[test]
fn statement_binding_rejects_a_moved_share() {
    let fixture = fixture(1, 1, vec![1]);
    let mut stats = threshold_bbs::Breakdown::default();
    let proof = sigma::prove(
        &fixture.pp,
        &fixture.statement,
        &fixture.witness,
        &mut stats,
    );
    assert!(sigma::verify(
        &fixture.pp,
        &fixture.statement,
        &proof,
        &mut stats
    ));

    let mut moved = fixture.statement.clone();
    moved.vrf_share = fixture.pp.g1.scale(&Scalar255::from_u64(1));
    assert!(!sigma::verify(&fixture.pp, &moved, &proof, &mut stats));

    let mut replayed = fixture.statement.clone();
    replayed.session = b"other-session".to_vec();
    assert!(!sigma::verify(&fixture.pp, &replayed, &proof, &mut stats));
}

#[test]
fn out_of_range_response_is_rejected() {
    let fixture = fixture(1, 1, vec![1]);
    let mut stats = threshold_bbs::Breakdown::default();
    let proof = sigma::prove(
        &fixture.pp,
        &fixture.statement,
        &fixture.witness,
        &mut stats,
    );

    // Push z_r past the mask interval; the range check must fire before any group work.
    let mut huge = proof.clone();
    huge.z_r = sigma::mask_bound(&fixture.pp) * bicycl::Mpz::from(2u64);
    assert!(!sigma::verify(
        &fixture.pp,
        &fixture.statement,
        &huge,
        &mut stats
    ));
}

#[test]
fn challenge_must_fit_in_ell_c_bits() {
    let fixture = fixture(1, 1, vec![1]);
    let mut stats = threshold_bbs::Breakdown::default();
    let proof = sigma::prove(
        &fixture.pp,
        &fixture.statement,
        &fixture.witness,
        &mut stats,
    );

    let mut wide = proof;
    wide.challenge = threshold_bbs::util::pow2(fixture.pp.challenge_bits) + bicycl::Mpz::from(1u64);
    assert!(!sigma::verify(
        &fixture.pp,
        &fixture.statement,
        &wide,
        &mut stats
    ));
}

/// The Fiat–Shamir compilation only works if recomputation is byte-identical. BICYCL
/// reduces composed forms to a canonical representative, so it is; this test keeps that
/// dependency honest across backend and parameter changes.
#[test]
fn commitment_recomputation_is_byte_identical() {
    for _ in 0..3 {
        let fixture = fixture(2, 1, vec![1, 2]);
        let mut stats = threshold_bbs::Breakdown::default();
        let (prover, nonces) = sigma::commit(&fixture.pp, &fixture.statement, &mut stats);
        let challenge = sigma::challenge_from(&fixture.pp, &fixture.statement, &prover);
        let proof = sigma::respond(&fixture.witness, &nonces, &challenge);
        let verifier = sigma::recompute_first(&fixture.pp, &fixture.statement, &proof, &mut stats);

        assert!(prover.t_y == verifier.t_y, "T_Y encoding mismatch");
        assert!(prover.t_w == verifier.t_w, "T_W encoding mismatch");
        assert!(
            prover.t_gamma == verifier.t_gamma,
            "T_Gamma encoding mismatch"
        );
        assert!(
            prover.t_0.to_bytes() == verifier.t_0.to_bytes(),
            "class-group T_0 encoding mismatch"
        );
        assert!(
            prover.t_1.to_bytes() == verifier.t_1.to_bytes(),
            "class-group T_1 encoding mismatch"
        );
        let c_prover = sigma::challenge_from(&fixture.pp, &fixture.statement, &prover);
        let c_verifier = sigma::challenge_from(&fixture.pp, &fixture.statement, &verifier);
        assert_eq!(c_prover, c_verifier, "challenge mismatch");
        assert_eq!(proof.challenge, c_verifier, "proof challenge must match");
    }
}

#[test]
fn proof_size_has_the_paper_floor() {
    let fixture = fixture(1, 1, vec![1]);
    let mut stats = threshold_bbs::Breakdown::default();
    let proof = sigma::prove(
        &fixture.pp,
        &fixture.statement,
        &fixture.witness,
        &mut stats,
    );
    let encoded = proof.encoded_len(&fixture.pp);

    // ell_c (16 bytes) + four 32-byte field responses, plus the integer response.
    assert!(encoded > 16 + 4 * 32, "proof is {encoded} bytes");
}
