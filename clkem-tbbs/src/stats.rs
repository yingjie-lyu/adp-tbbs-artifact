//! Cost accounting.
//!
//! Two axes, as in the parent crate: what primitive ran ([`Op`]) and which protocol step
//! spent the time ([`Stage`]). The counters are what the paper's comparison table reports
//! (class-group exponentiations per signer); the durations are only there so the report test
//! can print something useful.

use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub enum Op {
    /// Class-group exponentiation with a ~1000-bit exponent: `phi^gamma` and friends.
    ClassExpLong,
    /// Class-group exponentiation with a ~255-bit exponent.
    ClassExpShort,
    Compose,
    /// `CL.Solve`: coset label, lift, kernel division, `dlog_in_F`.
    Solve,
    Pairing,
    G1Exp,
    G2Exp,
    Prove,
    Verify,
    Count,
}

pub const OP_COUNT: usize = Op::Count as usize;

impl Op {
    pub const ALL: [Op; OP_COUNT] = [
        Op::ClassExpLong,
        Op::ClassExpShort,
        Op::Compose,
        Op::Solve,
        Op::Pairing,
        Op::G1Exp,
        Op::G2Exp,
        Op::Prove,
        Op::Verify,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Op::ClassExpLong => "class-group exp (long)",
            Op::ClassExpShort => "class-group exp (short)",
            Op::Compose => "class-group compose",
            Op::Solve => "CL.Solve",
            Op::Pairing => "pairing",
            Op::G1Exp => "G1 exp",
            Op::G2Exp => "G2 exp",
            Op::Prove => "proof produced",
            Op::Verify => "proof verified",
            Op::Count => "count",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(usize)]
pub enum Stage {
    SeedCommit,
    SeedOpen,
    KeygenDeal,
    KeygenCommit,
    KeygenOpen,
    KeygenFinish,
    SignCommit,
    SignOpen,
    SignShare,
    SignCombine,
    SignVerify,
    Count,
}

pub const STAGE_COUNT: usize = Stage::Count as usize;

impl Stage {
    pub const ALL: [Stage; STAGE_COUNT] = [
        Stage::SeedCommit,
        Stage::SeedOpen,
        Stage::KeygenDeal,
        Stage::KeygenCommit,
        Stage::KeygenOpen,
        Stage::KeygenFinish,
        Stage::SignCommit,
        Stage::SignOpen,
        Stage::SignShare,
        Stage::SignCombine,
        Stage::SignVerify,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Stage::SeedCommit => "keygen r1: seed commit",
            Stage::SeedOpen => "keygen r2: seed open",
            Stage::KeygenDeal => "keygen r3: PVSS deal",
            Stage::KeygenCommit => "keygen r4: D_i, encap, commit",
            Stage::KeygenOpen => "keygen r5: open + pi_enc",
            Stage::KeygenFinish => "keygen: aggregate",
            Stage::SignCommit => "sign r1: commit, phi^gamma",
            Stage::SignOpen => "sign r2: open (e_i, s_i)",
            Stage::SignShare => "sign r3: R_i, pd_i",
            Stage::SignCombine => "sign: combine",
            Stage::SignVerify => "sign: BBS+ verify",
            Stage::Count => "count",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Meter {
    ops: [u64; OP_COUNT],
    stage_calls: [u64; STAGE_COUNT],
    stage_time: [Duration; STAGE_COUNT],
}

impl Default for Meter {
    fn default() -> Self {
        Self {
            ops: [0; OP_COUNT],
            stage_calls: [0; STAGE_COUNT],
            stage_time: [Duration::ZERO; STAGE_COUNT],
        }
    }
}

impl Meter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, op: Op) {
        self.ops[op as usize] += 1;
    }

    pub fn add_n(&mut self, op: Op, count: u64) {
        self.ops[op as usize] += count;
    }

    pub fn count(&self, op: Op) -> u64 {
        self.ops[op as usize]
    }

    pub fn total(&self) -> u64 {
        self.ops.iter().sum()
    }

    /// Time `f` as `stage`. Nested calls are allowed; the outer stage then includes the
    /// inner one, which is what a composite step should report.
    pub fn step<T>(&mut self, stage: Stage, f: impl FnOnce(&mut Self) -> T) -> T {
        let start = Instant::now();
        let result = f(self);
        let elapsed = start.elapsed();
        self.stage_calls[stage as usize] += 1;
        self.stage_time[stage as usize] += elapsed;
        result
    }

    pub fn stage(&self, stage: Stage) -> (u64, Duration) {
        (self.stage_calls[stage as usize], self.stage_time[stage as usize])
    }

    pub fn mean(&self, stage: Stage) -> Duration {
        let calls = self.stage_calls[stage as usize];
        if calls == 0 {
            Duration::ZERO
        } else {
            self.stage_time[stage as usize] / calls as u32
        }
    }
}
