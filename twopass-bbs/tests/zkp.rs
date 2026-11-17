//! The three Σ-protocols: completeness, and rejection once any part of the statement or the
//! proof is changed.

use bicycl::Mpz;
use rand_core::OsRng;

use twopass_bbs::cl::{self, Cipher};
use twopass_bbs::meter::Meter;
use twopass_bbs::params::PublicParameters;
use twopass_bbs::random::fresh_rng;
use twopass_bbs::zkp::{self, ClDlStatement, LinStatement, LinWitness};

use threshold_bbs::algebra::{Group, Scalar};
use threshold_bbs::bls381::Scalar255;

fn parameters() -> std::sync::Arc<PublicParameters> {
    PublicParameters::production(2)
}

#[test]
fn r_dl_round_trip() {
    let pp = parameters();
    let mut meter = Meter::new();
    let secret = Scalar255::from_u64(1234567);
    let target = pp.g1.scale(&secret);

    let proof = zkp::prove_dl(&pp, b"ctx", &pp.g1, &target, &secret, &mut OsRng, &mut meter);
    assert!(zkp::verify_dl(&pp, b"ctx", &pp.g1, &target, &proof, &mut meter));

    // Wrong context, wrong statement, tampered response.
    assert!(!zkp::verify_dl(&pp, b"other", &pp.g1, &target, &proof, &mut meter));
    let other = pp.g1.scale(&Scalar255::from_u64(9));
    assert!(!zkp::verify_dl(&pp, b"ctx", &pp.g1, &other, &proof, &mut meter));
    let mut bad = proof.clone();
    bad.response = bad.response.add(&Scalar255::from_u64(1));
    assert!(!zkp::verify_dl(&pp, b"ctx", &pp.g1, &target, &bad, &mut meter));
}

#[test]
fn r_cl_dl_round_trip() {
    let pp = parameters();
    let mut meter = Meter::new();
    let mut rng = fresh_rng();

    let (ek, _dk) = cl::keygen(&pp.cl, &mut rng, &mut meter);
    let x = Scalar255::from_u64(7654321);
    let rho = pp.cl.sample_dq(&mut rng);
    let x_g2 = pp.g2.scale(&x);
    let cipher = cl::encrypt(&pp.cl, &ek, &x, &rho, &mut meter);

    let statement = ClDlStatement {
        ek: &ek,
        x_g2: &x_g2,
        cipher: &cipher,
    };
    let proof = zkp::prove_cl_dl(&pp, b"ctx", &statement, &x, &rho, &mut rng, &mut meter);
    assert!(zkp::verify_cl_dl(&pp, b"ctx", &statement, &proof, &mut meter));

    // A ciphertext of another value must not verify.
    let other = cl::encrypt(&pp.cl, &ek, &Scalar255::from_u64(7), &rho, &mut meter);
    let bad_statement = ClDlStatement {
        ek: &ek,
        x_g2: &x_g2,
        cipher: &other,
    };
    assert!(!zkp::verify_cl_dl(
        &pp,
        b"ctx",
        &bad_statement,
        &proof,
        &mut meter
    ));

    // A response outside the honest interval is rejected outright.
    let mut bad = proof.clone();
    bad.response_rho = pp.response_bound_dq() + Mpz::from(1u64);
    assert!(!zkp::verify_cl_dl(&pp, b"ctx", &statement, &bad, &mut meter));
}

#[test]
fn r_cl_lin_round_trip() {
    let pp = parameters();
    let mut meter = Meter::new();
    let mut rng = fresh_rng();

    // P_1's long-term ciphertext of x_1.
    let (ek, _dk) = cl::keygen(&pp.cl, &mut rng, &mut meter);
    let x1 = Scalar255::from_u64(111);
    let rho1 = pp.cl.sample_dq(&mut rng);
    let c_key = cl::encrypt(&pp.cl, &ek, &x1, &rho1, &mut meter);

    // P_2's values for one signature.
    let message: Vec<Scalar255> = (0..2).map(|i| Scalar255::from_u64(i + 5)).collect();
    let e = Scalar255::from_u64(424242);
    let s = Scalar255::from_u64(17);
    let base = pp.big_b(&s, &message).unwrap();

    let r = Scalar255::from_u64(999);
    let x2 = Scalar255::from_u64(222);
    let x_g2 = pp.g2.scale(&x2);
    let scaled = base.scale(&r);

    let rho2 = pp.cl.sample_dq(&mut rng);
    let plaintext = r.mul(&x2.add(&e));
    let d = cl::add(
        &pp.cl,
        &cl::scale(&pp.cl, &c_key, &r, &mut meter),
        &cl::encrypt(&pp.cl, &ek, &plaintext, &rho2, &mut meter),
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
    let witness = LinWitness {
        r: &r,
        x: &x2,
        rho: &rho2,
    };
    let proof = zkp::prove_cl_lin(&pp, b"lin", &statement, &witness, &mut rng, &mut meter);
    assert!(zkp::verify_cl_lin(&pp, b"lin", &statement, &proof, &mut meter));

    // Wrong e (the nonce the statement commits to).
    let other_e = e.add(&Scalar255::from_u64(1));
    let bad_statement = LinStatement {
        e: &other_e,
        ..LinStatement {
            ek: &ek,
            base: &base,
            scaled: &scaled,
            x_g2: &x_g2,
            ct_a: &c_key,
            ct_b: &d,
            e: &e,
        }
    };
    assert!(!zkp::verify_cl_lin(
        &pp,
        b"lin",
        &bad_statement,
        &proof,
        &mut meter
    ));

    // A wrong W breaks the public pairing check.
    let mut bad = proof.clone();
    bad.w = base.scale(&r.add(&Scalar255::from_u64(1)));
    assert!(!zkp::verify_cl_lin(&pp, b"lin", &statement, &bad, &mut meter));

    // A `D` that encrypts something else fails the FS equations.
    let wrong_d: Cipher = cl::encrypt(&pp.cl, &ek, &plaintext, &rho2, &mut meter);
    let bad_statement = LinStatement {
        ek: &ek,
        base: &base,
        scaled: &scaled,
        x_g2: &x_g2,
        ct_a: &c_key,
        ct_b: &wrong_d,
        e: &e,
    };
    assert!(!zkp::verify_cl_lin(
        &pp,
        b"lin",
        &bad_statement,
        &proof,
        &mut meter
    ));
}

#[test]
fn a_forged_r_cl_lin_cannot_hide_a_wrong_plaintext() {
    let pp = parameters();
    let mut meter = Meter::new();
    let mut rng = fresh_rng();

    let (ek, _dk) = cl::keygen(&pp.cl, &mut rng, &mut meter);
    let x1 = Scalar255::from_u64(3);
    let rho1 = pp.cl.sample_dq(&mut rng);
    let c_key = cl::encrypt(&pp.cl, &ek, &x1, &rho1, &mut meter);

    let message: Vec<Scalar255> = vec![Scalar255::from_u64(1), Scalar255::from_u64(2)];
    let e = Scalar255::from_u64(9);
    let s = Scalar255::from_u64(10);
    let base = pp.big_b(&s, &message).unwrap();
    let r = Scalar255::from_u64(4);
    let x2 = Scalar255::from_u64(6);
    let x_g2 = pp.g2.scale(&x2);
    let scaled = base.scale(&r);
    let rho2 = pp.cl.sample_dq(&mut rng);

    // The malicious plaintext: r(x_2 + e) + 1.
    let honest = r.mul(&x2.add(&e));
    let tampered_plaintext = honest.add(&Scalar255::from_u64(1));
    let d = cl::add(
        &pp.cl,
        &cl::scale(&pp.cl, &c_key, &r, &mut meter),
        &cl::encrypt(&pp.cl, &ek, &tampered_plaintext, &rho2, &mut meter),
        &mut meter,
    );

    // The prover tries to prove the honest statement; the equations cannot be satisfied
    // because it does not know a witness for the tampered ciphertext.
    let statement = LinStatement {
        ek: &ek,
        base: &base,
        scaled: &scaled,
        x_g2: &x_g2,
        ct_a: &c_key,
        ct_b: &d,
        e: &e,
    };
    let witness = LinWitness {
        r: &r,
        x: &x2,
        rho: &rho2,
    };
    let proof = zkp::prove_cl_lin(&pp, b"lin", &statement, &witness, &mut rng, &mut meter);
    assert!(
        !zkp::verify_cl_lin(&pp, b"lin", &statement, &proof, &mut meter),
        "an inconsistent D must not verify"
    );
}
