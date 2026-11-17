//! Wire format: every message of the two protocols round-trips, and the decoder is strict.

use rand_core::OsRng;

use twopass_bbs::bbs::Signature;
use twopass_bbs::cl;
use twopass_bbs::keygen::{commit_share, DkgPass1, DkgPass2, DkgPass3};
use twopass_bbs::meter::Meter;
use twopass_bbs::params::PublicParameters;
use twopass_bbs::random::fresh_rng;
use twopass_bbs::sign::{Pass1, Pass2};
use twopass_bbs::vrf;
use twopass_bbs::wire;
use twopass_bbs::zkp::{self, ClDlStatement, LinProof, LinStatement, LinWitness};

use threshold_bbs::algebra::{Group, Scalar};
use threshold_bbs::bls381::Scalar255;

fn parameters() -> std::sync::Arc<PublicParameters> {
    PublicParameters::production(2)
}

#[test]
fn dkg_messages_round_trip() {
    let pp = parameters();
    let mut meter = Meter::new();
    let mut rng = fresh_rng();

    let x_g2 = pp.g2.scale(&Scalar255::from_u64(3));
    let pass1 = DkgPass1 {
        commitment: commit_share(&pp, &x_g2),
    };
    let decoded = DkgPass1::decode(&pass1.encode()).unwrap();
    assert_eq!(decoded.commitment, pass1.commitment);

    let vk = pp.g1.scale(&Scalar255::from_u64(5));
    let proof = zkp::prove_dl(&pp, b"wire", &pp.g1, &vk, &Scalar255::from_u64(5), &mut OsRng, &mut meter);
    let pass2 = DkgPass2 {
        x_g2: x_g2.clone(),
        vk: vk.clone(),
        proof,
    };
    let decoded = DkgPass2::decode(&pass2.encode()).unwrap();
    assert_eq!(decoded.x_g2, pass2.x_g2);
    assert_eq!(decoded.vk, pass2.vk);
    assert_eq!(decoded.proof.response, pass2.proof.response);

    let (ek, _dk) = cl::keygen(&pp.cl, &mut rng, &mut meter);
    let x = Scalar255::from_u64(9);
    let rho = pp.cl.sample_dq(&mut rng);
    let c_key = cl::encrypt(&pp.cl, &ek, &x, &rho, &mut meter);
    let statement = ClDlStatement {
        ek: &ek,
        x_g2: &x_g2,
        cipher: &c_key,
    };
    let cl_proof = zkp::prove_cl_dl(&pp, b"wire", &statement, &x, &rho, &mut rng, &mut meter);
    let pass3 = DkgPass3 {
        x_g2: x_g2.clone(),
        ek: ek.clone(),
        c_key: c_key.clone(),
        proof: cl_proof,
    };
    let decoded = DkgPass3::decode(&pass3.encode(), &pp).unwrap();
    assert_eq!(decoded.x_g2, pass3.x_g2);
    assert_eq!(decoded.ek, pass3.ek);
    assert_eq!(decoded.c_key, pass3.c_key);
    assert_eq!(decoded.proof.response_rho, pass3.proof.response_rho);
}

#[test]
fn signing_messages_round_trip() {
    let pp = parameters();
    let mut meter = Meter::new();
    let mut rng = fresh_rng();

    let pass1 = Pass1 { beta1: [7u8; 32] };
    let decoded = Pass1::decode(&pass1.encode()).unwrap();
    assert_eq!(decoded.beta1, pass1.beta1);

    let (ek, _dk) = cl::keygen(&pp.cl, &mut rng, &mut meter);
    let x1 = Scalar255::from_u64(11);
    let c_key = cl::encrypt(&pp.cl, &ek, &x1, &pp.cl.sample_dq(&mut rng), &mut meter);

    let message: Vec<Scalar255> = (0..2).map(|index| Scalar255::from_u64(index + 2)).collect();
    let e = Scalar255::from_u64(77);
    let s = Scalar255::from_u64(88);
    let base = pp.big_b(&s, &message).unwrap();
    let r = Scalar255::from_u64(13);
    let x2 = Scalar255::from_u64(21);
    let x_g2 = pp.g2.scale(&x2);
    let scaled = base.scale(&r);
    let rho2 = pp.cl.sample_dq(&mut rng);
    let d = cl::add(
        &pp.cl,
        &cl::scale(&pp.cl, &c_key, &r, &mut meter),
        &cl::encrypt(&pp.cl, &ek, &r.mul(&x2.add(&e)), &rho2, &mut meter),
        &mut meter,
    );
    let statement = LinStatement {
        ek: &ek,
        base: &base,
        scaled: &scaled,
        x_g2: &x_g2,
        ct_a: &c_key,
        ct_b: &d,
        e: &e,
    };
    let lin_proof: LinProof = zkp::prove_cl_lin(
        &pp,
        b"wire",
        &statement,
        &LinWitness {
            r: &r,
            x: &x2,
            rho: &rho2,
        },
        &mut rng,
        &mut meter,
    );

    let key = vrf::VrfKey::generate(&pp, &mut OsRng);
    let (_, vrf_proof) = vrf::eval(&pp, &key, b"alpha", &mut OsRng, &mut meter);

    let pass2 = Pass2 {
        vrf_proof,
        c: scaled,
        d: d.clone(),
        lin_proof,
    };
    let decoded = Pass2::decode(&pass2.encode(), &pp).unwrap();
    assert_eq!(decoded.c, pass2.c);
    assert_eq!(decoded.d, pass2.d);
    assert_eq!(decoded.lin_proof.w, pass2.lin_proof.w);
    assert_eq!(decoded.lin_proof.response_r, pass2.lin_proof.response_r);
    assert_eq!(
        decoded.vrf_proof.challenge,
        pass2.vrf_proof.challenge
    );
}

#[test]
fn signatures_round_trip() {
    let pp = parameters();
    let signature = Signature {
        a: pp.g1.scale(&Scalar255::from_u64(4)),
        e: Scalar255::from_u64(5),
        s: Scalar255::from_u64(6),
    };
    let decoded = Signature::decode(&signature.encode()).unwrap();
    assert_eq!(decoded, signature);
    assert_eq!(signature.encoded_len(), 112);
}

#[test]
fn trailing_bytes_are_rejected() {
    let pp = parameters();
    let message = Pass1 { beta1: [1u8; 32] };
    let mut bytes = message.encode();
    bytes.push(0);
    assert!(Pass1::decode(&bytes).is_err());

    let signature = Signature {
        a: pp.g1.scale(&Scalar255::from_u64(1)),
        e: Scalar255::from_u64(2),
        s: Scalar255::from_u64(3),
    };
    let mut bytes = signature.encode();
    bytes.push(0);
    assert!(Signature::decode(&bytes).is_err());

    // A class-group element must keep its canonical encoding: `x_g2` occupies the first 96
    // bytes, so byte 96 is the flags byte of `ek`'s compressed form.
    let mut bytes = DkgPass3 {
        x_g2: pp.g2.scale(&Scalar255::from_u64(2)),
        ek: pp.cl.exp(pp.cl.gq(), &bicycl::Mpz::from(3u64), &mut Meter::new()),
        c_key: cl::Cipher {
            c1: pp.cl.identity().clone(),
            c2: pp.cl.identity().clone(),
        },
        proof: zkp::ClDlProof {
            challenge: Scalar255::from_u64(1),
            response_x: Scalar255::from_u64(1),
            response_rho: bicycl::Mpz::from(1u64),
        },
    }
    .encode();
    let mut bad_flags = bytes.clone();
    bad_flags[96] = 0x1f;
    assert!(DkgPass3::decode(&bad_flags, &pp).is_err());

    let truncated = &bytes[..bytes.len() - 1];
    assert!(DkgPass3::decode(truncated, &pp).is_err());
    bytes.push(0);
    assert!(DkgPass3::decode(&bytes, &pp).is_err(), "trailing byte");
}

#[test]
fn element_sizes_are_the_ones_the_report_uses() {
    let pp = parameters();
    let mut meter = Meter::new();
    let element = pp.cl.exp(pp.cl.gq(), &bicycl::Mpz::from(3u64), &mut meter);
    let size = wire::qfi_len(&element);
    // A DGS-compressed form is 225 bytes at the paper's 1827-bit discriminant.
    assert!((200..250).contains(&size), "unexpected element size {size}");
}
