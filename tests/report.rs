//! What the implementation actually costs: bytes, and wall clock per protocol step.
//!
//! `cargo test --test report -- --nocapture` prints five tables:
//!
//! 1. **sizes** — wire sizes at the paper's parameters,
//! 2. **wall clock by step** — every phase of the protocol, with call counts, mean per call,
//!    share of the session, and the primitives that dominated each step,
//! 3. **class-group work per step** — long/short exponentiations, compositions, coset labels,
//!    kernel discrete logs, `G_1` multi-exponentiations and pairings, per step,
//! 4. **primitives** — whole-session totals per operation,
//! 5. **serialization overhead** — the same session run over the in-memory bus.
//!
//! The typed session is the headline (protocol cost only).

use std::time::{Duration, Instant};

use bicycl::RandGen;

use threshold_bbs::algebra::{Breakdown, Operation, Phase, Scalar};
use threshold_bbs::bls381::Scalar255;
use threshold_bbs::keygen::{keygen_with_stats, KeyPackage};
use threshold_bbs::params::{PublicParameters, SetupConfig};
use threshold_bbs::round1::presign;
use threshold_bbs::session;
use threshold_bbs::transport::Bus;
use threshold_bbs::util::mpz_bits;
use threshold_bbs::{keygen, wire};

fn ms(duration: Duration) -> String {
    format!("{:.2}", duration.as_secs_f64() * 1e3)
}

fn share(part: Duration, whole: Duration) -> String {
    if whole.is_zero() {
        "0.0%".to_string()
    } else {
        format!("{:.1}%", 100.0 * part.as_secs_f64() / whole.as_secs_f64())
    }
}

struct Sizes {
    role_a_encoding: usize,
    role_b_uncompressed: usize,
    role_b_encoding: usize,
    proof: usize,
    public_share: usize,
    round1: usize,
    round2: usize,
    signature: usize,
}

fn form_len(form: &bicycl::QFI) -> usize {
    let mut bytes = Vec::new();
    wire::encode_qfi(&mut bytes, form);
    bytes.len()
}

fn measure_sizes(pp: &PublicParameters, pkg: &KeyPackage, id: usize) -> Sizes {
    let view = pkg.party_view(id).unwrap();
    let message = vec![Scalar255::from_u64(1); pp.message_bases.len()];
    let quorum = vec![id];
    let mut stats = Breakdown::default();
    let (round1, _) = presign(pp, &view, b"size", &message, &quorum, &mut stats).unwrap();

    let share = pkg.public_share(id).unwrap();
    let role_a_encoding = form_len(&share.x_encoding);
    let role_b_uncompressed = round1.c0.to_bytes().len() + round1.c1.to_bytes().len();
    let role_b_encoding = form_len(&round1.c0) + form_len(&round1.c1);
    let proof = round1.proof.encoded_len(pp);

    let mut round1_wire = Vec::new();
    wire::encode_round1(&mut round1_wire, &round1, &pp.nim);

    Sizes {
        role_a_encoding,
        role_b_uncompressed,
        role_b_encoding,
        proof,
        public_share: 96 + 48 + role_a_encoding,
        round1: round1_wire.len(),
        round2: 8 + 32 + 48,
        signature: 48 + 32 + 32,
    }
}

#[test]
fn print_size_and_cost_report() {
    let mut stats = Breakdown::default();

    let start = Instant::now();
    let pp = PublicParameters::setup_with_stats(&SetupConfig::production(10), &mut stats);
    let setup_wall = start.elapsed();

    let start = Instant::now();
    let pkg = keygen_with_stats(&pp, 3, 4, &mut stats).unwrap();
    let keygen_wall = start.elapsed();

    let sizing = keygen(&pp, 1, 1).unwrap();
    let sizes = measure_sizes(&pp, &sizing, 1);

    println!("\n=== 1. sizes, 128-bit computational / 80-bit statistical security ===");
    println!(
        "log2 |Delta_K|              : {}",
        mpz_bits(&pp.nim.group().discriminant_K())
    );
    println!(
        "log2 |Delta_q|              : {}",
        mpz_bits(&pp.nim.group().discriminant())
    );
    println!(
        "log2 N_A (role-A coins)     : {}",
        mpz_bits(pp.nim.bound_a())
    );
    println!(
        "log2 N_B (role-B coins)     : {}",
        mpz_bits(pp.nim.bound_b())
    );
    println!(
        "role-A encoding pe_x        : {} bytes",
        sizes.role_a_encoding
    );
    println!(
        "role-B encoding pe_gamma    : {} bytes",
        sizes.role_b_encoding
    );
    println!("proof pi_i                  : {} bytes", sizes.proof);
    println!("public share pk_i           : {} bytes", sizes.public_share);
    println!(
        "round-1 message pspm_i      : {} bytes (incl. 8-byte party id)",
        sizes.round1
    );
    println!(
        "round-2 message spm_i       : {} bytes ({} without the party id)",
        sizes.round2,
        sizes.round2 - 8
    );
    println!("signature (A, e, phi)       : {} bytes", sizes.signature);
    println!(
        "role-B uncompressed would be: {} bytes (a,b,c per form)",
        sizes.role_b_uncompressed
    );

    // One session, typed, into the same profile that already holds setup and keygen.
    let message = vec![Scalar255::from_u64(1234); 10];
    let quorum = [1usize, 2, 3];
    let views: Vec<_> = quorum
        .iter()
        .map(|id| pkg.party_view(*id).unwrap())
        .collect();

    let typed =
        session::run_views_with(&pp, &views, b"report", &message, &quorum, &mut stats).unwrap();
    assert!(threshold_bbs::bbs::verify_with(
        &pp,
        &pkg.public_key,
        &message,
        &typed.signature
    ));

    // The same session again, this time with every message encoded and decoded.
    let mut wire_stats = Breakdown::default();
    let mut bus = Bus::new(&quorum);
    let over_bus = session::run_over_bus_with(
        &pp,
        &views,
        &mut bus,
        b"report-wire",
        &message,
        &quorum,
        &mut wire_stats,
    )
    .unwrap();
    assert!(threshold_bbs::bbs::verify_with(
        &pp,
        &pkg.public_key,
        &message,
        &over_bus.signature
    ));

    let total = stats.phase(Phase::Session).elapsed;
    let profile_total =
        stats.phase(Phase::Setup).elapsed + stats.phase(Phase::Keygen).elapsed + total;

    println!("\n=== 2. wall clock by step, 3-of-3 quorum, 10 messages ===");
    println!(
        "setup(10) = {:.2} ms   keygen(3,4) = {:.2} ms   session = {:.2} ms",
        setup_wall.as_secs_f64() * 1e3,
        keygen_wall.as_secs_f64() * 1e3,
        total.as_secs_f64() * 1e3
    );
    println!(
        "{:<28} {:>6} {:>11} {:>11} {:>8}   {}",
        "step", "calls", "total ms", "mean ms", "share", "top primitives"
    );
    let mut accounted = Duration::ZERO;
    for (phase, phase_stats) in stats.phases() {
        if phase == Phase::Session || phase_stats.calls == 0 {
            continue;
        }
        accounted += phase_stats.elapsed;
        println!(
            "{:<28} {:>6} {:>11} {:>11} {:>8}   {}",
            phase.label(),
            phase_stats.calls,
            ms(phase_stats.elapsed),
            ms(phase_stats.mean()),
            share(phase_stats.elapsed, profile_total),
            top_primitives(phase_stats)
        );
    }
    println!(
        "{:<28} {:>6} {:>11} {:>11} {:>8}",
        "(session total)",
        stats.phase(Phase::Session).calls,
        ms(total),
        ms(stats.phase(Phase::Session).mean()),
        share(total, profile_total)
    );
    println!(
        "{:<28} {:>6} {:>11} {:>11} {:>8}",
        "(profile total)",
        "",
        ms(profile_total),
        "",
        "100.0%"
    );
    println!(
        "{:<28} {:>6} {:>11} {:>11} {:>8}",
        "(glue inside session)",
        "",
        ms(total.saturating_sub(accounted)),
        "",
        share(total.saturating_sub(accounted), profile_total)
    );
    println!(
        "note: setup is class-group CRS generation, which BICYCL does not meter as exponentiations; its row is wall clock only."
    );

    println!("\n=== 3. class-group and pairing work per step ===");
    println!(
        "{:<28} {:>5} {:>6} {:>8} {:>6} {:>5} {:>7} {:>8}",
        "step", "long", "short", "compose", "label", "dlog", "G1exp", "pairing"
    );
    for (phase, phase_stats) in stats.phases() {
        if phase == Phase::Session || phase_stats.calls == 0 {
            continue;
        }
        println!(
            "{:<28} {:>5} {:>6} {:>8} {:>6} {:>5} {:>7} {:>8}",
            phase.label(),
            phase_stats.calls_of(Operation::ClassGroupExponentiationLong),
            phase_stats.calls_of(Operation::ClassGroupExponentiationShort),
            phase_stats.calls_of(Operation::ClassGroupComposition),
            phase_stats.calls_of(Operation::ClassGroupCosetLabel),
            phase_stats.calls_of(Operation::ClassGroupKernelDlog),
            phase_stats.calls_of(Operation::G1Exponentiation),
            phase_stats.calls_of(Operation::Pairing),
        );
    }

    println!("\n=== 4. primitives over the whole profile (setup + keygen + one session) ===");
    for (operation, measurement) in stats.iter() {
        if measurement.calls == 0 {
            continue;
        }
        println!(
            "{:<34} {:>8} calls {:>11} ms  mean {:>8} ms",
            format!("{operation:?}"),
            measurement.calls,
            ms(measurement.elapsed),
            ms(measurement.elapsed / measurement.calls as u32)
        );
    }

    println!("\n=== 5. serialization overhead (same session over the bus) ===");
    let wired_total = wire_stats.phase(Phase::Session).elapsed;
    println!(
        "typed session {:.2} ms, wired session {:.2} ms, delta {:.2} ms (separate runs, so this includes run-to-run variance)",
        total.as_secs_f64() * 1e3,
        wired_total.as_secs_f64() * 1e3,
        (wired_total.as_secs_f64() - total.as_secs_f64()) * 1e3
    );
    let wire_phase = wire_stats.phase(Phase::Wire);
    println!(
        "wire encode/decode: {} calls, {:.2} ms total, {:.3} ms per message",
        wire_phase.calls,
        wire_phase.elapsed.as_secs_f64() * 1e3,
        wire_phase.mean().as_secs_f64() * 1e3
    );
    println!("payload bytes published: {}", over_bus.wire_bytes);

    // Per signer per peer: verification plus the two decodes of each peer.
    let peers = stats.phase(Phase::Round2Verify).calls as f64;
    let long = stats
        .phase(Phase::Round2Verify)
        .calls_of(Operation::ClassGroupExponentiationLong)
        + stats
            .phase(Phase::Round2Decode)
            .calls_of(Operation::ClassGroupExponentiationLong);
    let short = stats
        .phase(Phase::Round2Verify)
        .calls_of(Operation::ClassGroupExponentiationShort)
        + stats
            .phase(Phase::Round2Decode)
            .calls_of(Operation::ClassGroupExponentiationShort);
    println!(
        "per signer per peer: {:.2} long + {:.2} short (paper: 4 long + 3 short)",
        long as f64 / peers,
        short as f64 / peers
    );

    assert_eq!(sizes.signature, 112, "48-byte A + two 32-byte scalars");
    assert_eq!(sizes.round2 - 8, 80, "one Z_q element and one G_1 point");
    assert_eq!(stats.phase(Phase::Setup).calls, 1);
    assert_eq!(stats.phase(Phase::Keygen).calls, 1);
    assert_eq!(stats.phase(Phase::Session).calls, 1);
    assert!(wire_stats.phase(Phase::Wire).calls > 0);
    assert!(
        (long as f64 / peers - 4.0).abs() < 1e-9,
        "4 long per signer per peer"
    );
    assert!(
        (short as f64 / peers - 3.0).abs() < 1e-9,
        "3 short per signer per peer"
    );
}

/// The three operations that dominate a step, for the one-line summary column.
fn top_primitives(phase_stats: &threshold_bbs::algebra::PhaseStats) -> String {
    let mut entries: Vec<(Operation, u64)> = phase_stats
        .ops
        .iter()
        .enumerate()
        .filter(|(_, measurement)| measurement.calls > 0)
        .map(|(index, measurement)| (operation_at(index), measurement.calls))
        .collect();
    entries.sort_by_key(|(_, calls)| std::cmp::Reverse(*calls));

    entries
        .into_iter()
        .take(3)
        .map(|(operation, calls)| format!("{operation:?}x{calls}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn operation_at(index: usize) -> Operation {
    const OPS: [Operation; Operation::Count as usize] = [
        Operation::Pairing,
        Operation::G1Exponentiation,
        Operation::G2Exponentiation,
        Operation::TargetExponentiation,
        Operation::ClassGroupExponentiationLong,
        Operation::ClassGroupExponentiationShort,
        Operation::ClassGroupComposition,
        Operation::ClassGroupReduction,
        Operation::ClassGroupMembership,
        Operation::ClassGroupCosetLabel,
        Operation::ClassGroupKernelDlog,
        Operation::HashToGroup,
        Operation::HashToScalar,
        Operation::ProofVerification,
    ];
    OPS[index]
}

#[test]
fn print_single_party_presign_cost() {
    let mut stats = Breakdown::default();
    let pp = PublicParameters::setup_with_stats(&SetupConfig::production(4), &mut stats);
    let pkg = keygen_with_stats(&pp, 2, 4, &mut stats).unwrap();

    let message = vec![Scalar255::from_u64(7); 4];
    let view = pkg.party_view(1).unwrap();
    let start = Instant::now();
    let _ = presign(&pp, &view, b"cost", &message, &[1, 2], &mut stats).unwrap();
    let presign_wall = start.elapsed();
    let _ = RandGen::new();

    println!("\n--- one party's presign, production parameters ---");
    println!("wall clock: {:.2} ms", presign_wall.as_secs_f64() * 1e3);
    for phase in [
        Phase::Round1Hash,
        Phase::Round1VrfShare,
        Phase::Round1EncodeB,
        Phase::Round1Proof,
    ] {
        let phase_stats = stats.phase(phase);
        println!(
            "  {:<26} {:>3} calls {:>10} ms   {}",
            phase.label(),
            phase_stats.calls,
            ms(phase_stats.elapsed),
            top_primitives(phase_stats)
        );
    }
    assert!(stats.phase(Phase::Round1EncodeB).calls >= 1);
}
