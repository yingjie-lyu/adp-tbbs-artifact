//! Per-signer communication of the two-round protocol.
//!
//! `cargo test -p robot-bbs --test report -- --nocapture`

use std::sync::Arc;

use bicycl::Mpz;

use robot_bbs::bbs::{Bases, PublicParameters};
use robot_bbs::session::run_signing;
use tcl::cl::ClParameters;
use tcl::meter::Meter;

use threshold_bbs::algebra::Scalar;
use threshold_bbs::bls381::{Scalar255, SCALAR_MODULUS_DECIMAL};

#[test]
fn signing_bandwidth_is_constant_in_the_signer_set() {
    let cl = Arc::new(ClParameters::setup(
        &Mpz::from(SCALAR_MODULUS_DECIMAL),
        1827,
        128,
        80,
    ));
    let parties: Vec<usize> = (1..=4).collect();
    let mut meter = Meter::new();
    let keys = tcl::setup(cl.clone(), &parties, 2, b"report-dkg", &mut meter).expect("dkg");
    println!("\ntwo-pass threshold BBS+ (ROBOT), 4 signers, t = 2");
    println!(
        "{:<6} {:>12} {:>12} {:>12} {:>12}",
        "ell", "r1/signer", "r2/signer", "total KiB", "per signer KiB"
    );
    for len in [1usize, 2, 10] {
        let params = PublicParameters::new(cl.clone(), len);
        let bases = Bases::derive(&keys[&1].x_public, len);
        let message: Vec<Scalar255> = (0..len)
            .map(|index| Scalar255::from_u64(index as u64 + 1))
            .collect();
        let outcome =
            run_signing(&keys, &bases, params, &parties, &message, b"report", &mut meter)
                .expect("signing");
        let per_signer = outcome.per_party.values().max().copied().unwrap_or(0);
        println!(
            "{:<6} {:>12} {:>12} {:>12.3} {:>15.3}",
            len,
            outcome.bytes_round1 / parties.len(),
            outcome.bytes_round2 / parties.len(),
            outcome.total_bytes() as f64 / 1024.0,
            per_signer as f64 / 1024.0
        );
    }
    println!("  staged breakdown: {}", meter.summary());
}
