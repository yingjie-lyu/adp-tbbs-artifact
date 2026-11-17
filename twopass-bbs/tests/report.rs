//! The measurements the paper's Table 1 reports: passes, bytes on the wire, and wall clock.
//!
//! Run with `cargo test -p twopass-bbs --test report -- --nocapture`.

use bicycl::Mpz;
use rand_core::OsRng;

use twopass_bbs::cl::{self, Cipher};
use twopass_bbs::keygen::{DkgPass1, DkgPass2, DkgPass3};
use twopass_bbs::meter::{Meter, Op, Stage};
use twopass_bbs::params::PublicParameters;
use twopass_bbs::random::fresh_rng;
use twopass_bbs::session::{run_dkg, run_signing};
use twopass_bbs::sign::{Pass1, Pass2, SignerOne, SignerTwo};
use twopass_bbs::vrf;
use twopass_bbs::wire;
use twopass_bbs::zkp::{self, LinStatement, LinWitness};

use threshold_bbs::algebra::{Group, Scalar};
use threshold_bbs::bls381::Scalar255;

fn kib(bytes: usize) -> f64 {
    bytes as f64 / 1024.0
}

#[test]
fn signing_bandwidth_and_timing() {
    println!("\ntwo-pass signing at |Delta_K| = 1827 bits");
    println!(
        "{:<6} {:>10} {:>10} {:>10} {:>12}",
        "ell", "pass1 (B)", "pass2 (B)", "total (B)", "total KiB"
    );

    for len in [1usize, 2, 10, 50] {
        let params = PublicParameters::production(len);
        let mut meter = Meter::new();
        let dkg = run_dkg(params.clone(), b"report-dkg", &mut meter).expect("dkg");
        let mut first = SignerOne::new(dkg.first);
        let mut second = SignerTwo::new(dkg.second);

        let message: Vec<Scalar255> = (0..len)
            .map(|index| Scalar255::from_u64(index as u64 + 1))
            .collect();
        let mut sign_meter = Meter::new();
        let mut outcome = None;
        // Median of three runs is overkill here; one run per size is enough for the shape.
        for round in 0..3 {
            let session = format!("report-{len}-{round}");
            outcome = Some(
                run_signing(&mut first, &mut second, &message, session.as_bytes(), &mut sign_meter)
                    .expect("signing"),
            );
        }
        let outcome = outcome.expect("a signature");
        println!(
            "{:<6} {:>10} {:>10} {:>10} {:>12.3}",
            len,
            outcome.bytes_pass1,
            outcome.bytes_pass2,
            outcome.total_bytes(),
            kib(outcome.total_bytes())
        );

        for stage in [Stage::DkgOne, Stage::DkgTwo, Stage::DkgThree, Stage::DkgFinish, Stage::SignOne, Stage::SignTwo, Stage::SignOutput] {
            let (calls, elapsed) = sign_meter.stage(stage);
            if calls > 0 {
                println!(
                    "      {:<30} {:>4} calls  {:>8.2} ms total  {:>8.2} ms each",
                    stage.label(),
                    calls,
                    elapsed.as_secs_f64() * 1000.0,
                    elapsed.as_secs_f64() * 1000.0 / calls as f64
                );
            }
        }
        println!(
            "      primitives per signature: {} long exp, {} short exp, {} compose, {} solve, \
             {} pairing, {} proof verify",
            sign_meter.count(Op::ClassExpLong) / 3,
            sign_meter.count(Op::ClassExpShort) / 3,
            sign_meter.count(Op::Compose) / 3,
            sign_meter.count(Op::Solve) / 3,
            sign_meter.count(Op::Pairing) / 3,
            sign_meter.count(Op::Verify) / 3,
        );
    }
}

/// The per-signature byte counts at the paper's own parameters (1827-bit discriminant).
///
/// Only the wire sizes are measured here; the protocol itself is exercised in
/// `signing_bandwidth_and_timing`, also at 1827 bits.
#[test]
fn signing_sizes_at_production_parameters() {
    let pp = PublicParameters::production(10);
    let mut meter = Meter::new();
    let mut rng = fresh_rng();

    let x_g2 = pp.g2.scale(&Scalar255::from_u64(3));
    let pass1 = DkgPass1 {
        commitment: twopass_bbs::keygen::commit_share(&pp, &x_g2),
    };
    let vk = pp.g1.scale(&Scalar255::from_u64(9));
    let dl_proof = zkp::prove_dl(
        &pp,
        b"sizes",
        &pp.g1,
        &vk,
        &Scalar255::from_u64(9),
        &mut OsRng,
        &mut meter,
    );
    let pass2 = DkgPass2 {
        x_g2: x_g2.clone(),
        vk,
        proof: dl_proof,
    };

    let (ek, _dk) = cl::keygen(&pp.cl, &mut rng, &mut meter);
    let x1 = Scalar255::from_u64(11);
    let rho1 = pp.cl.sample_dq(&mut rng);
    let c_key = cl::encrypt(&pp.cl, &ek, &x1, &rho1, &mut meter);
    let statement = zkp::ClDlStatement {
        ek: &ek,
        x_g2: &x_g2,
        cipher: &c_key,
    };
    let cl_proof = zkp::prove_cl_dl(&pp, b"sizes", &statement, &x1, &rho1, &mut rng, &mut meter);
    let pass3 = DkgPass3 {
        x_g2: x_g2.clone(),
        ek: ek.clone(),
        c_key: c_key.clone(),
        proof: cl_proof,
    };

    // One signing pass 2, measured the same way.
    let message: Vec<Scalar255> = (0..10).map(|index| Scalar255::from_u64(index + 1)).collect();
    let e = Scalar255::from_u64(123);
    let s = Scalar255::from_u64(456);
    let base = pp.big_b(&s, &message).unwrap();
    let r = Scalar255::from_u64(789);
    let x2 = Scalar255::from_u64(321);
    let x2_g2 = pp.g2.scale(&x2);
    let scaled = base.scale(&r);
    let rho2 = pp.cl.sample_dq(&mut rng);
    let d: Cipher = cl::add(
        &pp.cl,
        &cl::scale(&pp.cl, &c_key, &r, &mut meter),
        &cl::encrypt(&pp.cl, &ek, &r.mul(&x2.add(&e)), &rho2, &mut meter),
        &mut meter,
    );
    let lin_statement = LinStatement {
        ek: &ek,
        base: &base,
        scaled: &scaled,
        x_g2: &x2_g2,
        ct_a: &c_key,
        ct_b: &d,
        e: &e,
    };
    let lin_proof = zkp::prove_cl_lin(
        &pp,
        b"sizes",
        &lin_statement,
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
    let vrf_len = vrf_proof.encoded_len();
    let pass_one = Pass1 { beta1: [0u8; 32] };
    let pass_two = Pass2 {
        vrf_proof,
        c: scaled,
        d,
        lin_proof,
    };

    let element = wire::qfi_len(&pp.cl.exp(pp.cl.gq(), &Mpz::from(3u64), &mut meter));
    let dkg = [
        pass1.encode().len(),
        pass2.encode().len(),
        pass3.encode().len(),
    ];
    let sign = [pass_one.encode().len(), pass_two.encode().len()];
    let total = sign[0] + sign[1];

    println!("\nper-signature traffic at |Delta_K| = 1827 bits");
    println!("  class-group element (DGS compressed): {element} bytes  (paper: 219)");
    println!("  VRF proof: {vrf_len} bytes, C: 48 bytes, D: {} bytes", pass_two.d.encoded_len());
    println!("  pass 1 (P_1 -> P_2): {} bytes", sign[0]);
    println!("  pass 2 (P_2 -> P_1): {} bytes", sign[1]);
    println!(
        "  total: {total} bytes = {:.3} KiB   (paper's Table 1: 0.85 KB, 2 passes)",
        kib(total)
    );
    println!(
        "  key generation: pass 1 {} B, pass 2 {} B, pass 3 {} B",
        dkg[0], dkg[1], dkg[2]
    );

    assert!(total < 1100, "per-signature traffic {total} B is above the paper's ballpark");
}
