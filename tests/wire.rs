//! Wire format: round-trips, size, and strict rejection of malformed input.

use bicycl::{RandGen, QFI};

use threshold_bbs::algebra::{Group, Scalar};
use threshold_bbs::bbs;
use threshold_bbs::bls381::Scalar255;
use threshold_bbs::error::Error;
use threshold_bbs::hash::{hashvrf, Transcript};
use threshold_bbs::keygen::keygen;
use threshold_bbs::params::{PublicParameters, SetupConfig};
use threshold_bbs::round1::presign;
use threshold_bbs::sigma::{self, Statement, Witness};
use threshold_bbs::{transport, wire};

fn parameters() -> PublicParameters {
    PublicParameters::setup(&SetupConfig::production(2))
}

fn message(len: usize, seed: u64) -> Vec<Scalar255> {
    (0..len)
        .map(|index| Scalar255::from_u64(seed * 17 + index as u64))
        .collect()
}

#[test]
fn round1_round_trips_through_bytes() {
    let pp = parameters();
    let pkg = keygen(&pp, 2, 3).unwrap();
    let msg = message(2, 3);
    let quorum = [1usize, 2];
    let mut stats = threshold_bbs::Breakdown::default();

    let (round1, _) = presign(
        &pp,
        &pkg.party_view(1).unwrap(),
        b"wire",
        &msg,
        &quorum,
        &mut stats,
    )
    .unwrap();

    let mut bytes = Vec::new();
    wire::encode_round1(&mut bytes, &round1, &pp.nim);
    let decoded = wire::decode_round1(&bytes, &pp.nim).unwrap();

    assert_eq!(decoded.id, round1.id);
    assert_eq!(decoded.vrf_share, round1.vrf_share);
    assert_eq!(decoded.gamma_commitment, round1.gamma_commitment);
    assert_eq!(decoded.c0.to_bytes(), round1.c0.to_bytes());
    assert_eq!(decoded.c1.to_bytes(), round1.c1.to_bytes());
    assert_eq!(decoded.proof.challenge, round1.proof.challenge);
    assert_eq!(decoded.proof.z_r, round1.proof.z_r);
    assert_eq!(decoded.proof.z_v, round1.proof.z_v);
    assert_eq!(decoded.proof.z_gamma, round1.proof.z_gamma);

    // A decoded message must still verify: the transcript hashes the form coefficients, and
    // `c` was recomputed on the receiving side.
    let mut fresh = threshold_bbs::Breakdown::default();
    assert!(threshold_bbs::round1::verify_round1(
        &pp,
        &pkg.party_view(2).unwrap(),
        b"wire",
        &msg,
        &quorum,
        &decoded,
        &mut fresh
    ));
}

#[test]
fn round1_size_matches_the_paper() {
    let pp = PublicParameters::setup(&SetupConfig::production(2));
    let pkg = keygen(&pp, 2, 3).unwrap();
    let msg = message(2, 5);
    let quorum = [1usize, 2];
    let mut stats = threshold_bbs::Breakdown::default();
    let (round1, _) = presign(
        &pp,
        &pkg.party_view(1).unwrap(),
        b"size",
        &msg,
        &quorum,
        &mut stats,
    )
    .unwrap();

    let mut bytes = Vec::new();
    wire::encode_round1(&mut bytes, &round1, &pp.nim);

    // The paper's table says 831 bytes: 48 (W) + 439 (role-B encoding) + 48 (Gamma) + 296
    // (proof). We add an 8-byte party id and 5 sign/flag bytes across the two forms.
    assert!(
        (820..=880).contains(&bytes.len()),
        "round-1 message is {} bytes",
        bytes.len()
    );

    // Raw coefficients would be 878 bytes for the two forms alone.
    let uncompressed = round1.c0.to_bytes().len() + round1.c1.to_bytes().len();
    let compressed = bytes.len() - (8 + 48 + 48 + round1.proof.encoded_len(&pp));
    assert!(
        compressed * 10 < uncompressed * 6,
        "expected DGS to beat (a,b,c) by >1.6x: {compressed} vs {uncompressed}"
    );
}

#[test]
fn round2_and_signature_round_trip() {
    let pp = parameters();
    let pkg = keygen(&pp, 2, 3).unwrap();
    let msg = message(2, 7);
    let outcome = threshold_bbs::session::run(&pp, &pkg, b"rt", &msg, &[1, 2]).unwrap();

    let share = outcome.round2.get(&1).unwrap();
    let mut bytes = Vec::new();
    wire::encode_round2(&mut bytes, share);
    assert_eq!(bytes.len(), 8 + 32 + 48);
    let decoded = wire::decode_round2(&bytes).unwrap();
    assert_eq!(decoded.id, share.id);
    assert_eq!(decoded.u, share.u);
    assert_eq!(decoded.s, share.s);

    let mut signature_bytes = Vec::new();
    wire::encode_signature(&mut signature_bytes, &outcome.signature);
    assert_eq!(signature_bytes.len(), 112);
    let decoded_signature = wire::decode_signature(&signature_bytes).unwrap();
    assert_eq!(decoded_signature, outcome.signature);
    assert!(bbs::verify_with(
        &pp,
        &pkg.public_key,
        &msg,
        &decoded_signature
    ));
}

#[test]
fn message_vector_round_trips() {
    let msg = message(4, 11);
    let mut bytes = Vec::new();
    wire::encode_messages(&mut bytes, &msg);
    assert_eq!(bytes.len(), 4 * 32);
    assert_eq!(wire::decode_messages(&bytes).unwrap(), msg);
    assert!(matches!(
        wire::decode_messages(&bytes[..bytes.len() - 1]),
        Err(Error::Wire(_))
    ));
}

#[test]
fn truncated_and_padded_messages_are_rejected() {
    let pp = parameters();
    let pkg = keygen(&pp, 2, 3).unwrap();
    let msg = message(2, 13);
    let mut stats = threshold_bbs::Breakdown::default();
    let (round1, _) = presign(
        &pp,
        &pkg.party_view(1).unwrap(),
        b"bad",
        &msg,
        &[1, 2],
        &mut stats,
    )
    .unwrap();

    let mut bytes = Vec::new();
    wire::encode_round1(&mut bytes, &round1, &pp.nim);

    assert!(matches!(
        wire::decode_round1(&bytes[..bytes.len() - 1], &pp.nim),
        Err(Error::Wire(_))
    ));

    let mut padded = bytes.clone();
    padded.push(0);
    assert!(matches!(
        wire::decode_round1(&padded, &pp.nim),
        Err(Error::Wire(_))
    ));

    assert!(matches!(
        wire::decode_round1(&[], &pp.nim),
        Err(Error::Wire(_))
    ));
}

#[test]
fn invalid_curve_points_are_rejected() {
    let pp = parameters();
    let pkg = keygen(&pp, 2, 3).unwrap();
    let msg = message(2, 17);
    let mut stats = threshold_bbs::Breakdown::default();
    let (round1, _) = presign(
        &pp,
        &pkg.party_view(1).unwrap(),
        b"pt",
        &msg,
        &[1, 2],
        &mut stats,
    )
    .unwrap();

    let mut bytes = Vec::new();
    wire::encode_round1(&mut bytes, &round1, &pp.nim);
    // The 48-byte compressed point lives right after the 8-byte id.
    for index in 8..56 {
        bytes[index] = 0xff;
    }
    assert!(matches!(
        wire::decode_round1(&bytes, &pp.nim),
        Err(Error::Wire(_))
    ));
}

#[test]
fn malformed_forms_are_rejected() {
    let pp = parameters();
    let nim = &pp.nim;

    // flags, then four u8-length-prefixed magnitudes.
    let encode_parts = |flags: u8, parts: [&[u8]; 4]| {
        let mut bytes = vec![flags];
        for part in parts {
            bytes.push(part.len() as u8);
            bytes.extend_from_slice(part);
        }
        bytes
    };
    let decode = |bytes: &[u8]| {
        let mut reader = wire::Reader::new(bytes);
        reader.qfi(nim)
    };

    // Reserved flag bits must not decode.
    assert!(matches!(
        decode(&encode_parts(0x20, [&[1], &[1], &[1], &[1]])),
        Err(Error::Wire(_))
    ));

    // a = 0 cannot be a form.
    assert!(matches!(
        decode(&encode_parts(0, [&[], &[1], &[1], &[1]])),
        Err(Error::Wire(_))
    ));

    // A negative leading coefficient is not a valid compressed form.
    assert!(matches!(
        decode(&encode_parts(0b0001, [&[1], &[1], &[1], &[1]])),
        Err(Error::Wire(_))
    ));

    // tp = 0 with a non-zero b0 is inconsistent with every special case.
    assert!(matches!(
        decode(&encode_parts(0, [&[1], &[1], &[], &[7]])),
        Err(Error::Wire(_))
    ));

    // Well-formed framing but meaningless integers: the discriminant check must fire.
    assert!(matches!(
        decode(&encode_parts(0, [&[3], &[5], &[7], &[11]])),
        Err(Error::Wire(_))
    ));
}

#[test]
fn form_with_negative_second_coefficient_round_trips() {
    // `Mpz::to_bytes` is magnitude-only, so a form whose b is negative is the case that
    // catches a missing sign byte.
    let pp = parameters();
    let nim = &pp.nim;
    let mut rng = RandGen::new();
    let mut stats = threshold_bbs::Breakdown::default();

    let mut found = None;
    for _ in 0..32 {
        let encoded = nim.encode_b(&Scalar255::from_u64(9), &mut rng, &mut stats);
        if threshold_bbs::util::mpz_sign(&encoded.c1.b()) < 0 {
            found = Some(encoded.c1);
            break;
        }
    }
    let form = found.expect("sampling should hit a negative b within 32 tries");

    let mut bytes = Vec::new();
    wire::encode_qfi(&mut bytes, &form);
    let mut reader = wire::Reader::new(&bytes);
    let decoded = reader.qfi(nim).unwrap();
    reader.finish().unwrap();

    assert_eq!(decoded.to_bytes(), form.to_bytes());
    assert_eq!(
        threshold_bbs::util::mpz_sign(&decoded.b()),
        threshold_bbs::util::mpz_sign(&form.b())
    );
}

#[test]
fn transcript_separates_b_from_minus_b() {
    // Two forms that share a discriminant but differ in the sign of b must not hash the same.
    let pp = parameters();
    let mut rng = RandGen::new();
    let mut stats = threshold_bbs::Breakdown::default();
    let encoded = pp
        .nim
        .encode_b(&Scalar255::from_u64(21), &mut rng, &mut stats);

    let original = encoded.c0.clone();
    let mirrored = QFI::from_mpz(
        &original.a(),
        &threshold_bbs::util::mpz_neg(&original.b()),
        &original.c(),
    );

    let mut left = Transcript::new(b"t");
    left.absorb_qfi(b"form", &original);
    let mut right = Transcript::new(b"t");
    right.absorb_qfi(b"form", &mirrored);
    assert_ne!(left.digest32(), right.digest32());
}

#[test]
fn sigma_proof_survives_a_wire_round_trip() {
    let pp = parameters();
    let pkg = keygen(&pp, 2, 2).unwrap();
    let msg = message(2, 23);
    let quorum = [1usize, 2];
    let (base_1, base_2) = hashvrf(b"rt", &pp.encode_message(&msg), &quorum);
    let view = pkg.party_view(1).unwrap();
    let share = &view.share;

    let mut rng = RandGen::new();
    let mut stats = threshold_bbs::Breakdown::default();
    let encoded = pp
        .nim
        .encode_b(&Scalar255::from_u64(5), &mut rng, &mut stats);
    let statement = Statement {
        id: 1,
        session: b"rt".to_vec(),
        message: pp.encode_message(&msg),
        quorum: quorum.to_vec(),
        base_1: base_1.clone(),
        base_2: base_2.clone(),
        vrf_commitment: view.public_share(1).unwrap().vrf_commitment.clone(),
        vrf_share: base_1
            .scale(&share.v_i)
            .combine(&base_2.scale(&share.s_tilde_i)),
        gamma_commitment: pp
            .g1
            .scale(&Scalar255::from_u64(5))
            .combine(&pp.hh.scale(&Scalar255::from_u64(6))),
        c0: encoded.c0.clone(),
        c1: encoded.c1.clone(),
    };
    let witness = Witness {
        v_i: share.v_i.clone(),
        s_tilde_i: share.s_tilde_i.clone(),
        gamma_i: Scalar255::from_u64(5),
        rho_i: Scalar255::from_u64(6),
        randomness_gamma: encoded.randomness,
    };
    let proof = sigma::prove(&pp, &statement, &witness, &mut stats);

    let mut bytes = Vec::new();
    wire::encode_proof(&mut bytes, &proof);
    let mut reader = wire::Reader::new(&bytes);
    let decoded = wire::decode_proof(&mut reader).unwrap();
    reader.finish().unwrap();

    assert_eq!(decoded.challenge, proof.challenge);
    assert_eq!(decoded.z_r, proof.z_r);
    assert!(sigma::verify(&pp, &statement, &decoded, &mut stats));
}

#[test]
fn bus_delivers_to_every_party_including_the_sender() {
    let mut bus = transport::Bus::new(&[1, 2, 3]);
    bus.publish(b"s", transport::Round::One, 2, vec![9, 9])
        .unwrap();

    for id in [1, 2, 3] {
        let drained = bus.drain(id, b"s", transport::Round::One).unwrap();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].from, 2);
        assert_eq!(drained[0].payload, vec![9, 9]);
    }
    assert_eq!(bus.pending(), 0);

    // A different session is not delivered.
    bus.publish(b"s", transport::Round::One, 1, vec![1])
        .unwrap();
    assert!(bus
        .drain(2, b"other", transport::Round::One)
        .unwrap()
        .is_empty());
    assert_eq!(bus.pending(), 3);
}

#[test]
fn compressed_forms_stay_small_across_shapes() {
    let pp = parameters();
    let nim = &pp.nim;
    let mut rng = RandGen::new();
    let mut stats = threshold_bbs::Breakdown::default();

    let encoded = nim.encode_b(&Scalar255::from_u64(11), &mut rng, &mut stats);
    let small_order = nim.f().exp(
        nim.group(),
        &threshold_bbs::util::scalar_to_mpz(&Scalar255::from_u64(12345)),
    );
    let principal = nim.group().one();

    for (name, form) in [
        ("random role-B component", encoded.c1),
        ("small-order kernel element", small_order),
        ("principal form", principal),
    ] {
        let mut bytes = Vec::new();
        wire::encode_qfi(&mut bytes, &form);
        let raw = form.to_bytes().len();
        assert!(
            bytes.len() < raw,
            "{name}: compressed {} bytes should beat raw {raw}",
            bytes.len()
        );

        let mut reader = wire::Reader::new(&bytes);
        let decoded = reader.qfi(nim).expect("round trip");
        reader.finish().unwrap();
        assert_eq!(
            decoded.to_bytes(),
            form.to_bytes(),
            "{name} must round trip"
        );
    }
}
