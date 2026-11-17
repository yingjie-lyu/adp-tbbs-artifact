//! How the cost scales with the quorum size.
//!
//! `cargo test --test scaling -- --nocapture` prints, for each quorum size, the per-signer
//! cost of round 1 and round 2, and the marginal cost of adding one more signer.

use std::time::Duration;

use threshold_bbs::algebra::{Breakdown, Operation, Phase, Scalar};
use threshold_bbs::bls381::Scalar255;
use threshold_bbs::keygen::{keygen, KeyPackage};
use threshold_bbs::params::{PublicParameters, SetupConfig};
use threshold_bbs::session;

fn ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1e3
}

struct Row {
    quorum: usize,
    round1_per_signer: f64,
    round2_per_signer: f64,
    verify_per_peer: f64,
    decode_per_peer: f64,
    session_total: f64,
    long_mean: f64,
    short_mean: f64,
}

fn measure(pp: &PublicParameters, pkg: &KeyPackage, quorum_size: usize) -> Row {
    let quorum: Vec<usize> = (1..=quorum_size).collect();
    let message = vec![Scalar255::from_u64(99); pp.message_bases.len()];
    let views: Vec<_> = quorum
        .iter()
        .map(|id| pkg.party_view(*id).unwrap())
        .collect();

    let mut stats = Breakdown::default();
    let session =
        session::run_views_with(pp, &views, b"scaling", &message, &quorum, &mut stats).unwrap();
    assert!(threshold_bbs::bbs::verify_with(
        &pp,
        &pkg.public_key,
        &message,
        &session.signature
    ));

    let signers = quorum_size as f64;
    let round1 = ms(stats.phase(Phase::Round1Hash).elapsed)
        + ms(stats.phase(Phase::Round1VrfShare).elapsed)
        + ms(stats.phase(Phase::Round1EncodeB).elapsed)
        + ms(stats.phase(Phase::Round1Proof).elapsed);

    // Round 2 as seen by one signer. `Round2Session` also runs once inside `combine`, so it
    // is divided by the number of signers plus one caller.
    let round2 = ms(stats.phase(Phase::Round2Verify).elapsed)
        + ms(stats.phase(Phase::Round2Decode).elapsed)
        + ms(stats.phase(Phase::Round2Masks).elapsed)
        + ms(stats.phase(Phase::Round2Assemble).elapsed)
        + ms(stats.phase(Phase::Round2Session).elapsed) * signers / (signers + 1.0);

    Row {
        quorum: quorum_size,
        round1_per_signer: round1 / signers,
        round2_per_signer: round2 / signers,
        verify_per_peer: ms(stats.phase(Phase::Round2Verify).mean()),
        decode_per_peer: ms(stats.phase(Phase::Round2Decode).elapsed) / signers / (signers - 1.0),
        session_total: ms(stats.phase(Phase::Session).elapsed),
        long_mean: ms(stats.get(Operation::ClassGroupExponentiationLong).elapsed)
            / stats.calls(Operation::ClassGroupExponentiationLong).max(1) as f64,
        short_mean: ms(stats.get(Operation::ClassGroupExponentiationShort).elapsed)
            / stats.calls(Operation::ClassGroupExponentiationShort).max(1) as f64,
    }
}

#[test]
fn print_quorum_scaling() {
    let pp = PublicParameters::setup(&SetupConfig::production(4));
    let pkg = keygen(&pp, 2, 6).unwrap();

    // Warm up once so the first measurement is not paying for lazy allocation.
    let _ = measure(&pp, &pkg, 3);

    let mut rows = Vec::new();
    for quorum_size in 2..=6 {
        rows.push(measure(&pp, &pkg, quorum_size));
    }

    println!("\n=== cost vs quorum size (production parameters, 4 messages) ===");
    println!(
        "{:>7} {:>16} {:>16} {:>14} {:>14} {:>14}",
        "quorum", "round1/signer", "round2/signer", "verify/peer", "decode/peer", "session total"
    );
    for row in &rows {
        println!(
            "{:>7} {:>13.1} ms {:>13.1} ms {:>11.1} ms {:>11.1} ms {:>11.1} ms",
            row.quorum,
            row.round1_per_signer,
            row.round2_per_signer,
            row.verify_per_peer,
            row.decode_per_peer,
            row.session_total
        );
    }

    println!("\n=== marginal cost of one more signer ===");
    println!(
        "{:>14} {:>22} {:>22} {:>20}",
        "quorum -> +1", "round2/signer grows", "round1/signer grows", "session grows"
    );
    for pair in rows.windows(2) {
        let (before, after) = (&pair[0], &pair[1]);
        println!(
            "{:>14} {:>19.1} ms {:>19.1} ms {:>17.1} ms",
            format!("{} -> {}", before.quorum, after.quorum),
            after.round2_per_signer - before.round2_per_signer,
            after.round1_per_signer - before.round1_per_signer,
            after.session_total - before.session_total
        );
    }

    // Compare the measured increment with what the cost model predicts.
    let model = rows.last().unwrap();
    println!(
        "
unit costs at this parameter set: long = {:.2} ms, short = {:.2} ms",
        model.long_mean, model.short_mean
    );
    println!(
        "paper model per extra peer per signer: 4 long + 3 short = {:.1} ms",
        4.0 * model.long_mean + 3.0 * model.short_mean
    );
    println!(
        "measured: verify/peer {:.1} ms + decode/peer {:.1} ms = {:.1} ms",
        model.verify_per_peer,
        model.decode_per_peer,
        model.verify_per_peer + model.decode_per_peer
    );

    // Round 1 must not depend on the quorum.
    let first = rows.first().unwrap().round1_per_signer;
    for row in &rows {
        let drift = (row.round1_per_signer - first).abs() / first;
        assert!(
            drift < 0.25,
            "round 1 should not depend on the quorum: drift {:.1}%",
            drift * 100.0
        );
    }
    // Round 2 grows with every added signer.
    let mut last = 0.0;
    for row in &rows {
        assert!(
            row.round2_per_signer > last,
            "round 2 must grow with the quorum"
        );
        last = row.round2_per_signer;
    }
}
