//! Cost accounting, on the same two axes as the sibling crates: primitive counters and
//! per-pass wall clock.

use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub enum Op {
    /// Class-group exponentiation with an exponent longer than ~400 bits (`rho`, `D_q` masks).
    ClassExpLong,
    /// Class-group exponentiation with a `Z_q` exponent.
    ClassExpShort,
    Compose,
    /// `CL.Solve`, i.e. the decryption of `D`.
    Solve,
    Pairing,
    G1Exp,
    G2Exp,
    /// Exponentiation in the pairing target, used by the `R_CL-Lin` pairing equation.
    TargetExp,
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
        Op::TargetExp,
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
            Op::TargetExp => "GT exp",
            Op::Prove => "proof produced",
            Op::Verify => "proof verified",
            Op::Count => "count",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(usize)]
pub enum Stage {
    DkgOne,
    DkgTwo,
    DkgThree,
    DkgFinish,
    SignOne,
    SignTwo,
    SignOutput,
    Count,
}

pub const STAGE_COUNT: usize = Stage::Count as usize;

impl Stage {
    pub const ALL: [Stage; STAGE_COUNT] = [
        Stage::DkgOne,
        Stage::DkgTwo,
        Stage::DkgThree,
        Stage::DkgFinish,
        Stage::SignOne,
        Stage::SignTwo,
        Stage::SignOutput,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Stage::DkgOne => "dkg pass 1 (x1, h)",
            Stage::DkgTwo => "dkg pass 2 (x2, vk2, R_DL)",
            Stage::DkgThree => "dkg pass 3 (ek1, C_key1, R_CL-DL)",
            Stage::DkgFinish => "dkg finish (checks, X)",
            Stage::SignOne => "sign pass 1 (beta1)",
            Stage::SignTwo => "sign pass 2 (VRF, C, D, R_CL-Lin)",
            Stage::SignOutput => "sign output (verify, decrypt)",
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

    pub fn reset(&mut self) {
        *self = Self::default();
    }

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
