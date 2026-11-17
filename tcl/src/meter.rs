//! Cost accounting: primitive counters plus named, timed steps.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub enum Op {
    ClassExpLong,
    ClassExpShort,
    Compose,
    Solve,
    G1Exp,
    G2Exp,
    Prove,
    Verify,
    Pairing,
    Count,
}

pub const OP_COUNT: usize = Op::Count as usize;

impl Op {
    pub const ALL: [Op; OP_COUNT] = [
        Op::ClassExpLong,
        Op::ClassExpShort,
        Op::Compose,
        Op::Solve,
        Op::G1Exp,
        Op::G2Exp,
        Op::Prove,
        Op::Verify,
        Op::Pairing,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Op::ClassExpLong => "class-group exp (long)",
            Op::ClassExpShort => "class-group exp (short)",
            Op::Compose => "class-group compose",
            Op::Solve => "CL.Solve",
            Op::G1Exp => "G1 exp",
            Op::G2Exp => "G2 exp",
            Op::Prove => "proof produced",
            Op::Verify => "proof verified",
            Op::Pairing => "pairing",
            Op::Count => "count",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Meter {
    ops: [u64; OP_COUNT],
    steps: BTreeMap<&'static str, (u64, Duration)>,
}

impl Default for Meter {
    fn default() -> Self {
        Self {
            ops: [0; OP_COUNT],
            steps: BTreeMap::new(),
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

    pub fn step<T>(&mut self, name: &'static str, f: impl FnOnce(&mut Self) -> T) -> T {
        let start = Instant::now();
        let result = f(self);
        let elapsed = start.elapsed();
        let entry = self.steps.entry(name).or_insert((0, Duration::ZERO));
        entry.0 += 1;
        entry.1 += elapsed;
        result
    }

    pub fn step_stats(&self, name: &str) -> Option<(u64, Duration)> {
        self.steps.get(name).copied()
    }

    pub fn steps(&self) -> impl Iterator<Item = (&'static str, (u64, Duration))> + '_ {
        self.steps.iter().map(|(name, value)| (*name, *value))
    }

    pub fn summary(&self) -> String {
        Op::ALL
            .iter()
            .filter(|op| self.count(**op) > 0)
            .map(|op| format!("{}={}", op.label(), self.count(*op)))
            .collect::<Vec<_>>()
            .join(", ")
    }
}
