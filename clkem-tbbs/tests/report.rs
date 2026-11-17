//! The measurements the paper's evaluation section reports: bytes per signer, class-group
//! operations per signer, and wall clock per round.
//!
//! Run with `cargo test -p clkem-tbbs --test report -- --nocapture` to see the tables.

use bicycl::Mpz;

use clkem_tbbs::params::PublicParameters;
use clkem_tbbs::random::fresh_rng;
use clkem_tbbs::session::{run_keygen, run_signing};
use clkem_tbbs::stats::{Meter, Op, Stage};
use clkem_tbbs::transport::Round;
use clkem_tbbs::wire;
use clkem_tbbs::zkp;

use threshold_bbs::algebra::Scalar;
use threshold_bbs::bls381::Scalar255;

fn kib(bytes: usize) -> f64 {
    bytes as f64 / 1024.0
}

#[test]
fn signing_bandwidth_and_cost() {
    println!(
        "\n{:<8} {:<10} {:>9} {:>9} {:>9} {:>12} {:>10}",
        "parties", "threshold", "r1 (B)", "r2 (B)", "r3 (B)", "total KiB", "class exps"
    );

    for (n, t) in [(2usize, 2usize), (3, 2), (5, 3)] {
        let pp = PublicParameters::production(4);
        let mut keygen_meter = Meter::new();
        let keygen =
            run_keygen(pp.clone(), n, t, format!("report-{n}-{t}").as_bytes(), &mut keygen_meter)
                .expect("keygen");

        let quorum: Vec<usize> = (1..=t).collect();
        let message: Vec<Scalar255> = (0..4).map(|index| Scalar255::from_u64(index + 100)).collect();
        let mut meter = Meter::new();
        let outcome = run_signing(&keygen.parties, &quorum, &message, b"report-sign", &mut meter)
            .expect("signing");

        let first = quorum[0];
        let round_one = outcome.bus.outgoing_in(first, Round::SignCommit).1;
        let round_two = outcome.bus.outgoing_in(first, Round::SignOpen).1;
        let round_three = outcome.bus.outgoing_in(first, Round::SignShare).1;
        let total = outcome.bus.outgoing(first).1;
        let long = meter.count(Op::ClassExpLong) / quorum.len() as u64;
        let short = meter.count(Op::ClassExpShort) / quorum.len() as u64;

        println!(
            "{:<8} {:<10} {:>9} {:>9} {:>9} {:>12.3} {:>10}",
            n,
            t,
            round_one,
            round_two,
            round_three,
            kib(total),
            format!("{long}L+{short}S")
        );

        assert_eq!(round_one + round_two + round_three, total);
        // One CL.Solve per signer: the threshold decryption of gamma (x + e).
        assert_eq!(meter.count(Op::Solve), quorum.len() as u64);
        for stage in [
            Stage::SignCommit,
            Stage::SignOpen,
            Stage::SignShare,
            Stage::SignCombine,
            Stage::SignVerify,
        ] {
            let (calls, elapsed) = meter.stage(stage);
            let mean = if calls == 0 {
                0.0
            } else {
                elapsed.as_secs_f64() * 1000.0 / calls as f64
            };
            println!("         {:<26} {:>8.2} ms/party", stage.label(), mean);
        }
    }
}

#[test]
fn keygen_bandwidth_per_party() {
    println!("\nkey generation, outgoing bytes per party");
    for (n, t) in [(2usize, 2usize), (3, 2), (5, 3)] {
        let pp = PublicParameters::production(2);
        let mut meter = Meter::new();
        let outcome =
            run_keygen(pp.clone(), n, t, format!("report-kg-{n}-{t}").as_bytes(), &mut meter)
                .expect("keygen");
        let per_round: Vec<usize> = [
            Round::SeedCommit,
            Round::SeedOpen,
            Round::Pvss,
            Round::KeygenCommit,
            Round::KeygenOpen,
        ]
        .iter()
        .map(|round| outcome.bus.outgoing_in(1, *round).1)
        .collect();
        println!(
            "  n={n} t={t}: seed {} / {} / PVSS {} / D_i {} / open {} = {:.1} KiB",
            per_round[0],
            per_round[1],
            per_round[2],
            per_round[3],
            per_round[4],
            kib(per_round.iter().sum::<usize>())
        );
        println!(
            "           class-group exponentiations per party: {} long, {} short; CL.Solve {}",
            meter.count(Op::ClassExpLong) / n as u64,
            meter.count(Op::ClassExpShort) / n as u64,
            meter.count(Op::Solve)
        );
    }
}

/// The numbers Table 3 is built from, at the paper's 1827-bit discriminant.
///
/// Only sizes are measured here; the protocol itself is exercised in `signing_bandwidth_and_cost`,
/// which also runs at 1827 bits.
#[test]
fn signing_wire_sizes_at_production_parameters() {
    let pp = PublicParameters::production(10);
    let mut meter = Meter::new();
    let mut rng = fresh_rng();

    let element = wire::qfi_len(&pp.cl.exp(pp.cl.gq(), &Mpz::from(3u64), &mut meter));
    let target = pp.cl.exp(pp.cl.gq(), &Mpz::from(11u64), &mut meter);
    let proof = zkp::prove_dl(
        &pp,
        zkp::DOMAIN_DLS,
        b"sizes",
        pp.cl.gq(),
        &target,
        &Mpz::from(11u64),
        pp.cl.bound_b(),
        &mut rng,
        &mut meter,
    )
    .encoded_len();

    let round_one = 8 + 32 + element + proof; // id, commit, phi^gamma, R_dls
    let round_two = 8 + 64; // id, e_i, s_i
    let round_three = 8 + 48 + element; // id, R_i, pd_i
    let total = round_one + round_two + round_three;

    println!("\nper-signer signing traffic at |Delta_K| = 1827 bits");
    println!("  class-group element (DGS compressed): {element} bytes  (paper: 219)");
    println!("  R_dls / R_dlc proof: {proof} bytes");
    println!("  round 1: {round_one} B, round 2: {round_two} B, round 3: {round_three} B");
    println!(
        "  total: {total} B = {:.3} KiB  (paper's Table 3: 0.78 KiB)",
        kib(total)
    );
    println!(
        "  B_q = {} bits, B = {} bits",
        threshold_bbs::util::mpz_bits(pp.cl.bound_bq()),
        threshold_bbs::util::mpz_bits(pp.cl.bound_b())
    );

    assert!(element >= 200 && element <= 240, "unexpected element size {element}");
    assert!(total < 900, "per-signer traffic of {total} B is above the paper's ballpark");
}
