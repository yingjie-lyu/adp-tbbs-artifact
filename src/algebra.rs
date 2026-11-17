//! Minimal algebraic abstraction used by the scheme.
//!
//! The protocol itself is instantiated over BLS12-381 (see [`crate::bls381`]); the traits
//! exist so that the pairing-side code (`bbs`, `sigma`) reads the same way as the paper's
//! equations, and so that operation-level cost accounting can be attached to every call.

use std::{
    fmt::Debug,
    time::{Duration, Instant},
};

/// An element of the scalar field `Z_q`.
pub trait Scalar: Clone + Debug + Eq {
    fn zero() -> Self;
    fn one() -> Self;
    fn add(&self, rhs: &Self) -> Self;
    fn sub(&self, rhs: &Self) -> Self;
    fn mul(&self, rhs: &Self) -> Self;
    fn invert(&self) -> Option<Self>;
    fn from_u64(value: u64) -> Self;

    /// Reduce a big-endian byte string modulo `q`.
    ///
    /// Used to move integer challenges and class-group decodings into `Z_q` without
    /// ever materialising a fixed-width buffer, so the reduction is exact for inputs of
    /// any length.
    fn from_be_bytes_mod_order(bytes: &[u8]) -> Self;

    /// Canonical big-endian encoding, 32 bytes for BLS12-381.
    fn to_be_bytes(&self) -> Vec<u8>;

    fn is_zero(&self) -> bool {
        *self == Self::zero()
    }
}

pub trait Group: Clone + Debug + Eq {
    type Scalar: Scalar;

    fn identity() -> Self;
    fn combine(&self, rhs: &Self) -> Self;
    fn inverse(&self) -> Self;
    fn scale(&self, exponent: &Self::Scalar) -> Self;
}

/// A group element with a canonical byte encoding.
///
/// `to_bytes` must be canonical (for BLS12-381: compressed affine), because every
/// Fiat–Shamir challenge in this crate hashes group elements through it. A non-canonical
/// encoding would let a prover present two byte strings for the same element.
///
/// Only `G_1` and `G_2` implement this; the pairing target is never hashed, and the backend
/// exposes no canonical encoding for it.
pub trait Encodable: Group {
    fn to_bytes(&self) -> Vec<u8>;
}

/// A pairing-friendly group triple with `e: G2 x G1 -> Target`.
pub trait PairingGroup: Encodable {
    type G2: Encodable<Scalar = Self::Scalar>;
    type Target: Group<Scalar = Self::Scalar>;

    fn pairing(g2: &Self::G2, g1: &Self) -> Self::Target;
}

/// Cost centres reported by the paper's performance section.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub enum Operation {
    Pairing,
    G1Exponentiation,
    G2Exponentiation,
    TargetExponentiation,
    ClassGroupExponentiationLong,
    ClassGroupExponentiationShort,
    ClassGroupComposition,
    ClassGroupReduction,
    ClassGroupMembership,
    ClassGroupCosetLabel,
    ClassGroupKernelDlog,
    HashToGroup,
    HashToScalar,
    ProofVerification,
    Count,
}

/// Protocol steps, used as the second axis of the cost report.
///
/// Phases nest: an outer step's wall clock includes its children, while primitive counts are
/// attributed to the innermost step only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub enum Phase {
    /// `PublicParameters::setup`, including the class-group CRS.
    Setup,
    /// `keygen`: four polynomials, commitments, role-A encodings.
    Keygen,
    /// `hashvrf` inside `presign`.
    Round1Hash,
    /// `W_i = B_1^{v_i} B_2^{s~_i}`.
    Round1VrfShare,
    /// Role-B NIM encoding of `gamma_i`.
    Round1EncodeB,
    /// The Sigma-protocol prover.
    Round1Proof,
    ///Encoding or decoding a message for the wire.
    Wire,
    /// Verifying one peer proof.
    Round2Verify,
    /// Cross-term NIM decoding (`mu`, `nu`).
    Round2Decode,
    /// Interpolating `W`, deriving `(e, phi)`, computing `U`, building `tr`.
    Round2Session,
    /// Pairwise masks in `Z_q` and `G_1`.
    Round2Masks,
    /// `u_i` / `S_i` assembly and message encode/decode.
    Round2Assemble,
    /// Summing `u_j`, multiplying `S_j`, inverting, scaling.
    CombineAggregate,
    /// The final BBS+ pairing check.
    CombineVerify,
    /// Everything in a session.
    Session,
    Count,
}

impl Phase {
    pub const ALL: [Phase; Phase::Count as usize] = [
        Phase::Setup,
        Phase::Keygen,
        Phase::Round1Hash,
        Phase::Round1VrfShare,
        Phase::Round1EncodeB,
        Phase::Round1Proof,
        Phase::Wire,
        Phase::Round2Verify,
        Phase::Round2Decode,
        Phase::Round2Session,
        Phase::Round2Masks,
        Phase::Round2Assemble,
        Phase::CombineAggregate,
        Phase::CombineVerify,
        Phase::Session,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Phase::Setup => "setup",
            Phase::Keygen => "keygen",
            Phase::Round1Hash => "round1: hashvrf",
            Phase::Round1VrfShare => "round1: W_i",
            Phase::Round1EncodeB => "round1: encode_B",
            Phase::Round1Proof => "round1: sigma prove",
            Phase::Wire => "wire encode/decode",
            Phase::Round2Verify => "round2: verify pi_j",
            Phase::Round2Decode => "round2: decode mu/nu",
            Phase::Round2Session => "round2: W,(e,phi),U,tr",
            Phase::Round2Masks => "round2: masks",
            Phase::Round2Assemble => "round2: u_i,S_i",
            Phase::CombineAggregate => "combine: aggregate",
            Phase::CombineVerify => "combine: bbs verify",
            Phase::Session => "session total",
            Phase::Count => "count",
        }
    }
}

/// Per-operation call counts and wall-clock time.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Measurement {
    pub calls: u64,
    pub elapsed: Duration,
}

/// One protocol step: how often it ran, how long it took, and what it spent that time on.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PhaseStats {
    /// Number of times the step ran (for example once per party for `presign`).
    pub calls: u64,
    /// Inclusive wall clock.
    pub elapsed: Duration,
    /// Primitives measured inside this step.
    pub ops: [Measurement; Operation::Count as usize],
}

impl Default for PhaseStats {
    fn default() -> Self {
        Self {
            calls: 0,
            elapsed: Duration::ZERO,
            ops: [Measurement::default(); Operation::Count as usize],
        }
    }
}

impl PhaseStats {
    pub fn op(&self, operation: Operation) -> Measurement {
        self.ops[operation as usize]
    }

    pub fn calls_of(&self, operation: Operation) -> u64 {
        self.ops[operation as usize].calls
    }

    pub fn mean(&self) -> Duration {
        if self.calls == 0 {
            Duration::ZERO
        } else {
            self.elapsed / self.calls as u32
        }
    }
}

thread_local! {
    /// Steps currently being timed on this thread. `record` attributes each primitive to the
    /// innermost one.
    static PHASE_STACK: std::cell::RefCell<Vec<Phase>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Which step is being timed right now, if any.
pub fn current_phase() -> Option<Phase> {
    PHASE_STACK.with(|stack| stack.borrow().last().copied())
}

struct PhaseScope;

impl PhaseScope {
    fn enter(phase: Phase) -> Self {
        PHASE_STACK.with(|stack| stack.borrow_mut().push(phase));
        PhaseScope
    }
}

impl Drop for PhaseScope {
    fn drop(&mut self) {
        PHASE_STACK.with(|stack| {
            stack.borrow_mut().pop();
        });
    }
}

/// Call counts and wall-clock time, sliced by primitive and by protocol step.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Breakdown {
    entries: [Measurement; Operation::Count as usize],
    phases: [PhaseStats; Phase::Count as usize],
}

impl Breakdown {
    /// Record one measured primitive. It is attributed to the innermost active step.
    pub fn record(&mut self, op: Operation, elapsed: Duration) {
        let entry = &mut self.entries[op as usize];
        entry.calls += 1;
        entry.elapsed += elapsed;

        if let Some(phase) = current_phase() {
            let stats = &mut self.phases[phase as usize];
            stats.ops[op as usize].calls += 1;
            stats.ops[op as usize].elapsed += elapsed;
        }
    }

    /// Time `f` as `phase`, so every primitive recorded inside is attributed to it.
    ///
    /// Nesting is allowed and expected: the outer step's wall clock then includes the inner
    /// one, which is what you want when a step is a composite of others.
    pub fn step<T>(&mut self, phase: Phase, f: impl FnOnce(&mut Self) -> T) -> T {
        let scope = PhaseScope::enter(phase);
        let start = Instant::now();
        let result = f(&mut *self);
        let elapsed = start.elapsed();
        drop(scope);

        let stats = &mut self.phases[phase as usize];
        stats.calls += 1;
        stats.elapsed += elapsed;
        result
    }

    /// Record a step that was timed elsewhere.
    pub fn record_phase(&mut self, phase: Phase, elapsed: Duration) {
        let stats = &mut self.phases[phase as usize];
        stats.calls += 1;
        stats.elapsed += elapsed;
    }

    pub fn get(&self, op: Operation) -> Measurement {
        self.entries[op as usize]
    }

    pub fn calls(&self, op: Operation) -> u64 {
        self.entries[op as usize].calls
    }

    pub fn phase(&self, phase: Phase) -> &PhaseStats {
        &self.phases[phase as usize]
    }

    pub fn phases(&self) -> impl Iterator<Item = (Phase, &PhaseStats)> + '_ {
        Phase::ALL
            .into_iter()
            .map(|phase| (phase, &self.phases[phase as usize]))
    }

    /// Total class-group exponentiations, split into long and short.
    pub fn class_group_exponentiations(&self) -> (u64, u64) {
        (
            self.calls(Operation::ClassGroupExponentiationLong),
            self.calls(Operation::ClassGroupExponentiationShort),
        )
    }

    pub fn iter(&self) -> impl Iterator<Item = (Operation, Measurement)> + '_ {
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
        OPS.into_iter().map(|op| (op, self.get(op)))
    }
}

pub fn measure<T>(breakdown: &mut Breakdown, op: Operation, f: impl FnOnce() -> T) -> T {
    let start = Instant::now();
    let result = f();
    breakdown.record(op, start.elapsed());
    result
}
