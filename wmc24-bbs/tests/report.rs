//! Per-signer communication of the four-round protocol.
//!
//! `cargo test -p wmc24-bbs --test report -- --nocapture`

use std::sync::Arc;

use bicycl::Mpz;

use tcl::cl::ClParameters;
use tcl::meter::Meter;

use threshold_bbs::algebra::Scalar;
use threshold_bbs::bls381::{Scalar255, SCALAR_MODULUS_DECIMAL};

use wmc24_bbs::bbs::PublicParameters;
use wmc24_bbs::session::run_signing;

#[test]
fn signing_bandwidth_per_round() {
    let cl = Arc::new(ClParameters::setup(
        &Mpz::from(SCALAR_MODULUS_DECIMAL),
        1827,
        128,
        80,
    ));
    let parties: Vec<usize> = (1..=4).collect();
    let mut meter = Meter::new();
    let keys = tcl::setup(cl.clone(), &parties, 2, b"report-dkg", &mut meter).expect("dkg");

    println!("\nfour-round threshold BBS+ (WMC24), 4 signers, t = 2");
    println!(
        "{:<6} {:>10} {:>10} {:>10} {:>10} {:>12}",
        "ell", "step1", "step3", "step5", "step7", "total KiB"
    );
    for len in [1usize, 2, 10] {
        let params = PublicParameters::new(cl.clone(), len);
        let message: Vec<Scalar255> = (0..len)
            .map(|index| Scalar255::from_u64(index as u64 + 1))
            .collect();
        let outcome =
            run_signing(&keys, params, &parties, &message, b"report", &mut meter).expect("signing");
        let per = |index: usize| outcome.bytes[index] / parties.len();
        println!(
            "{:<6} {:>10} {:>10} {:>10} {:>10} {:>12.3}",
            len,
            per(0),
            per(1),
            per(2),
            per(3),
            outcome.total_bytes() as f64 / 1024.0
        );
    }
    println!("  staged breakdown: {}", meter.summary());
}
