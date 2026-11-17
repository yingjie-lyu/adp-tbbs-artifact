//! Our construction (the parent crate): per-phase runtime, split into the six logical stages
//! the paper reports.
//!
//! Every phase of [`threshold_bbs::algebra::Phase`] is attributed to exactly one logical stage;
//! the fine-grained phases are kept as sub-rows so the six numbers can be audited.

use std::collections::BTreeMap;
use std::time::Duration;

use threshold_bbs::algebra::{Breakdown, Phase};
use threshold_bbs::bls381::Scalar255;
use threshold_bbs::nim::NimVariant;
use threshold_bbs::params::{PublicParameters, SetupConfig};
use threshold_bbs::transport::Bus;
use threshold_bbs::{bbs, keygen, session};

use threshold_bbs::algebra::Scalar;

/// The paper's six logical stages, in order, with the internal phases behind each.
pub const GROUPS: [(&str, &[Phase]); 6] = [
    (
        "1. generating presigning message",
        &[
            Phase::Round1Hash,
            Phase::Round1VrfShare,
            Phase::Round1EncodeB,
        ],
    ),
    ("2. generating presigning proof", &[Phase::Round1Proof]),
    (
        "3. verifying each peer's presigning proof",
        &[Phase::Round2Verify],
    ),
    ("4. NIM decoding with each peer", &[Phase::Round2Decode]),
    (
        "5. finalizing online signing message",
        &[
            Phase::Round2Session,
            Phase::Round2Masks,
            Phase::Round2Assemble,
        ],
    ),
    (
        "6. signature combination",
        &[Phase::CombineAggregate, Phase::CombineVerify],
    ),
];

/// Which stages are paid once per *peer* (so the per-peer unit cost is also reported).
pub fn is_per_peer(phase: Phase) -> bool {
    matches!(phase, Phase::Round2Verify | Phase::Round2Decode)
}

/// Stages that assemble the signature from the responses.
///
/// Every party runs them locally to obtain the signature, so they are charged in full against
/// each party's runtime instead of being divided by the number of signers.
pub fn is_combine(phase: Phase) -> bool {
    matches!(phase, Phase::CombineAggregate | Phase::CombineVerify)
}

/// How one phase's measured time converts to per-party runtime.
pub fn divisor(phase: Phase, t: usize) -> f64 {
    if is_combine(phase) {
        1.0
    } else {
        t as f64
    }
}

pub fn phase_order() -> Vec<Phase> {
    Phase::ALL.to_vec()
}

/// One measurement series for a given `(ell, t)`.
pub struct Sample {
    /// Per signer, mean over repetitions.
    pub per_phase_ms: BTreeMap<&'static str, f64>,
    /// Per signer, mean over repetitions, grouped into the six logical stages.
    pub per_stage_ms: BTreeMap<&'static str, f64>,
    /// Sum of the six stages, per signer.
    pub total_ms: f64,
    /// Wire encode/decode, per signer (a separate run through [`Bus`]).
    pub wire_ms: f64,
    /// Raw per-repetition series, so the report can show spread instead of only means.
    pub total_reps: Vec<f64>,
    pub wire_reps: Vec<f64>,
}

fn ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1e3
}

/// Run `reps` typed sessions plus `reps` wire sessions for `(ell, t)`.
///
/// Setup and key generation happen once, before the loop, and are **not** measured.
pub fn measure(
    message_len: usize,
    t: usize,
    reps: usize,
    variant: NimVariant,
) -> Result<Sample, String> {
    let config = match variant {
        NimVariant::TwoBase => SetupConfig::production(message_len),
        NimVariant::SingleBase => SetupConfig::single_base(message_len, false),
        NimVariant::SingleBaseShort => SetupConfig::single_base(message_len, true),
    };
    let pp = PublicParameters::setup(&config);
    let package = keygen(&pp, t, t).map_err(|error| format!("keygen: {error}"))?;
    let quorum: Vec<usize> = (1..=t).collect();
    let message: Vec<Scalar255> = (0..message_len)
        .map(|index| Scalar255::from_u64(index as u64 + 1))
        .collect();
    let views: Vec<_> = quorum
        .iter()
        .map(|id| package.party_view(*id).map_err(|error| format!("view: {error}")))
        .collect::<Result<_, _>>()?;

    let mut phase_samples: BTreeMap<&'static str, Vec<f64>> = BTreeMap::new();
    let mut stage_samples: BTreeMap<&'static str, Vec<f64>> = BTreeMap::new();
    let mut total_samples: Vec<f64> = Vec::new();
    let mut wire_samples: Vec<f64> = Vec::new();

    for rep in 0..reps {
        let mut stats = Breakdown::default();
        let session_id = format!("bench-{message_len}-{t}-{rep}");
        let outcome = session::run_views_with(
            &pp,
            &views,
            session_id.as_bytes(),
            &message,
            &quorum,
            &mut stats,
        )
        .map_err(|error| format!("session: {error}"))?;
        if !bbs::verify_with(&pp, &package.public_key, &message, &outcome.signature) {
            return Err("a measured signature did not verify".into());
        }
        let mut this_rep: BTreeMap<&'static str, f64> = BTreeMap::new();
        for (phase, phase_stats) in stats.phases() {
            if phase == Phase::Session {
                continue;
            }
            let value = ms(phase_stats.elapsed) / divisor(phase, t);
            phase_samples
                .entry(phase.label())
                .or_default()
                .push(value);
            this_rep.insert(phase.label(), value);
        }
        let mut total_this_rep = 0.0;
        for (label, phases) in GROUPS {
            let value: f64 = phases
                .iter()
                .map(|phase| this_rep.get(phase.label()).copied().unwrap_or(0.0))
                .sum();
            stage_samples.entry(label).or_default().push(value);
            total_this_rep += value;
        }
        total_samples.push(total_this_rep);

        // The same session again, every message encoded and decoded.
        let mut wire_stats = Breakdown::default();
        let mut bus = Bus::new(&quorum);
        let wire_id = format!("bench-wire-{message_len}-{t}-{rep}");
        session::run_over_bus_with(
            &pp,
            &views,
            &mut bus,
            wire_id.as_bytes(),
            &message,
            &quorum,
            &mut wire_stats,
        )
        .map_err(|error| format!("wire session: {error}"))?;
        wire_samples.push(ms(wire_stats.phase(Phase::Wire).elapsed) / t as f64);
    }

    let per_phase_ms: BTreeMap<&'static str, f64> = phase_samples
        .iter()
        .map(|(phase, values)| (*phase, mean(values)))
        .collect();

    let mut per_stage_ms = BTreeMap::new();
    let mut total_ms = 0.0;
    for (label, phases) in GROUPS {
        let value: f64 = phases
            .iter()
            .map(|phase| per_phase_ms.get(phase.label()).copied().unwrap_or(0.0))
            .sum();
        per_stage_ms.insert(label, value);
        total_ms += value;
    }

    Ok(Sample {
        per_phase_ms,
        per_stage_ms,
        total_ms,
        wire_ms: mean(&wire_samples),
        total_reps: total_samples,
        wire_reps: wire_samples,
    })
}

fn mean(values: &[f64]) -> f64 {
    if values.is_empty() {
        0.0
    } else {
        values.iter().sum::<f64>() / values.len() as f64
    }
}
