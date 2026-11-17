//! The DKLs18 two-round OT multiplication `pi_Mul` (Protocol 5 of DKLs18), instantiated with
//! SoftSpokenOT.
//!
//! ```text
//! ell := 2*kappa + 2*s                              (672)
//! Bob   : gamma <- {0,1}^{kappa+2s};  omega := Bits(beta - <g^R,gamma>) || gamma
//! Alice : alpha_hat <- Z_q;  the correlation of every OT is the pair (alpha, alpha_hat)
//! COT   : batch of ell OTs, each carrying 2*kappa bits
//! chi,chi_hat <- H(transcript)
//! Alice -> Bob: r_j = chi*t_Aj + chi_hat*t_Ahat_j  (j < ell),  u = chi*alpha + chi_hat*alpha_hat
//! Bob rejects unless  forall j:  chi*t_Bj + chi_hat*t_Bhat_j == omega_j*u - r_j
//! shares: t_A = sum_j g_j*t_Aj,  t_B = sum_j g_j*t_Bj
//! ```
//!
//! # Two instantiations of `F_COTe`
//!
//! DKLs18 obtain the correlated OT `t_Aj + t_Bj = omega_j * alpha` from an OT extension. The pads
//! a random OT extension hands over are *not* the ones the correlation needs, so the sender pays to
//! convert them. How much depends on how the conversion is done, and this is the difference between
//! the two [`MulVariant`]s:
//!
//! * [`MulVariant::Masked`] — treat the sender's two pads `v_0, v_1` as unrelated and publish both
//!   masked candidates `v_0 - a` and `v_1 + alpha - a` per component. That is `4*kappa` bits per
//!   OT, the pessimistic price of not looking at the relation between `v_0` and `v_1`.
//! * [`MulVariant::Correction`] — the realisation DKLs18 actually charge for. The sender keeps
//!   `t_Aj = -v_0j` as its share and publishes the single value `alpha - Delta_j` per component,
//!   where `Delta_j = v_1j - v_0j` is known to the sender because it holds both pads. The receiver
//!   recovers `t_Bj = v_omega,j + omega_j*(alpha - Delta_j)`, which equals `-v_0j` for
//!   `omega_j = 0` and `alpha - v_0j` for `omega_j = 1`. That is `2*kappa` bits per OT, i.e.
//!   `ell*n/2` bits per party with `n = 2*kappa` — exactly DKLST's `COTeCost`.
//!
//! `Correction` is the default because it is both faithful to the paper and strictly cheaper. The
//! old `Masked` accounting is kept so the two can be measured side by side.

use bls12_381::Scalar;
use ff::Field;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use sha2::{Digest, Sha256};

use crate::ot::{self, Backend, Counters, OtSetup, ReceiverPads};
use crate::params::{DERANDOMISE_BITS, ELL, KAPPA, L, STAT, WIDTH};

/// How the sender turns random-OT pads into DKLs18's correlated OT.
///
/// See the module docs; the two differ only in what the sender publishes per OT.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MulVariant {
    /// One correction `alpha - Delta_j` per component: `2*kappa` bits per OT (paper-faithful).
    Correction,
    /// Two masked candidates per component: `4*kappa` bits per OT.
    Masked,
}

impl MulVariant {
    pub fn name(self) -> &'static str {
        match self {
            MulVariant::Correction => "correction",
            MulVariant::Masked => "masked",
        }
    }

    /// Bits the sender publishes per OT.
    pub fn bits_per_ot(self) -> usize {
        match self {
            MulVariant::Correction => WIDTH * KAPPA,
            MulVariant::Masked => 2 * WIDTH * KAPPA,
        }
    }
}

impl Default for MulVariant {
    fn default() -> Self {
        MulVariant::Correction
    }
}

/// `g^R`: public random vector over `Z_q`, `kappa + 2s` entries.
pub fn public_grip(seed: &[u8]) -> Vec<Scalar> {
    let mut out = Vec::with_capacity(KAPPA + 2 * STAT);
    for index in 0..(KAPPA + 2 * STAT) {
        let mut hasher = Sha256::new();
        hasher.update(b"dklst/pimul/grip");
        hasher.update(seed);
        hasher.update((index as u64).to_be_bytes());
        let digest = hasher.finalize();
        let mut wide = [0u8; 64];
        for (dst, src) in wide.iter_mut().zip(digest.iter().rev()) {
            *dst = *src;
        }
        out.push(Scalar::from_bytes_wide(&wide));
    }
    out
}

fn reduce_bits(bytes: &[u8; 32]) -> Scalar {
    let mut wide = [0u8; 64];
    for (index, byte) in bytes.iter().rev().enumerate() {
        wide[index] = *byte;
    }
    Scalar::from_bytes_wide(&wide)
}

/// `Bits(x)` of `kappa` bits, little-endian bit order within bytes.
fn bits_of(value: &Scalar, out: &mut [u8], offset: usize) {
    // `to_bytes` is little-endian, which is also the bit order `g^G = (1,2,4,...)` expects.
    let bytes = value.to_bytes();
    for index in 0..KAPPA {
        let bit = (bytes[index / 8] >> (index % 8)) & 1;
        let position = offset + index;
        if bit == 1 {
            out[position / 8] |= 1 << (position % 8);
        }
    }
}

/// Bob's encoding: `omega = Bits(beta - <g^R, gamma>) || gamma`, `kappa + 2s` bits.
pub fn encode(grip: &[Scalar], beta: &Scalar, gamma: &[u8]) -> Vec<u8> {
    let mut dot = Scalar::ZERO;
    for (index, coefficient) in grip.iter().enumerate() {
        let bit = (gamma[index / 8] >> (index % 8)) & 1;
        if bit == 1 {
            dot += coefficient;
        }
    }
    let masked = *beta - dot;
    let mut omega = vec![0u8; (2 * KAPPA + 2 * STAT + 7) / 8];
    bits_of(&masked, &mut omega, 0);
    for index in 0..(KAPPA + 2 * STAT) {
        let bit = (gamma[index / 8] >> (index % 8)) & 1;
        let position = KAPPA + index;
        if bit == 1 {
            omega[position / 8] |= 1 << (position % 8);
        }
    }
    omega
}

/// `sum_j g_j * omega_j`, i.e. the value the encoding is supposed to represent.
pub fn omega_as_scalar(grip: &[Scalar], omega: &[u8]) -> Scalar {
    let mut acc = Scalar::ZERO;
    for index in 0..ELL {
        if choice_bit(omega, index) {
            acc += gadget(grip, index);
        }
    }
    acc
}

fn choice_bit(omega: &[u8], index: usize) -> bool {
    (omega[index / 8] >> (index % 8)) & 1 == 1
}

/// The gadget vector: `g = (1, 2, 4, ..., 2^{kappa-1}) || g^R`.
fn gadget(grip: &[Scalar], index: usize) -> Scalar {
    if index < KAPPA {
        let mut wide = [0u8; 64];
        wide[index / 8] = 1 << (index % 8);
        Scalar::from_bytes_wide(&wide)
    } else {
        grip[index - KAPPA]
    }
}

/// Sender-side reply of one `pi_Mul`.
#[derive(Clone)]
pub enum MulReply {
    Correction {
        /// `alpha - Delta_j` per component.
        correction: Vec<[Scalar; 2]>,
        r: Vec<Scalar>,
        u: Scalar,
    },
    Masked {
        /// `[m_0, m_1, mhat_0, mhat_1]` per OT.
        masked: Vec<[Scalar; 4]>,
        r: Vec<Scalar>,
        u: Scalar,
    },
}

impl MulReply {
    pub fn variant(&self) -> MulVariant {
        match self {
            MulReply::Correction { .. } => MulVariant::Correction,
            MulReply::Masked { .. } => MulVariant::Masked,
        }
    }

    fn u(&self) -> Scalar {
        match self {
            MulReply::Correction { u, .. } | MulReply::Masked { u, .. } => *u,
        }
    }

    fn r(&self, index: usize) -> Scalar {
        match self {
            MulReply::Correction { r, .. } | MulReply::Masked { r, .. } => r[index],
        }
    }
}

/// Bob's state between the choice message and the reply.
pub struct ReceiverState {
    pub omega: Vec<u8>,
    pub message: Vec<u8>,
    pub pads: ReceiverPads,
}

fn coins(session: &[u8], message: &[u8], reply: &MulReply) -> (Scalar, Scalar) {
    let started = Instant::now();
    let mut hasher = Sha256::new();
    hasher.update(b"dklst/pimul/coins");
    hasher.update(session);
    hasher.update(message);
    // Only the correlation data enters the coin toss: `r, u` are derived from the coins, so
    // binding them here would make the two sides disagree on the input.
    match reply {
        MulReply::Correction { correction, .. } => {
            for entry in correction {
                for value in entry {
                    hasher.update(value.to_bytes());
                }
            }
        }
        MulReply::Masked { masked, .. } => {
            for entry in masked {
                for value in entry {
                    hasher.update(value.to_bytes());
                }
            }
        }
    }
    let digest = hasher.finalize();
    let mut first = [0u8; 32];
    first.copy_from_slice(&digest);
    let mut second = Sha256::new();
    second.update(b"dklst/pimul/coins2");
    second.update(digest);
    let second = second.finalize();
    let mut block = [0u8; 32];
    block.copy_from_slice(&second);
    COIN_NS.fetch_add(started.elapsed().as_nanos() as u64, Ordering::Relaxed);
    (reduce_bits(&first), reduce_bits(&block))
}

/// Bob's first half: encode `beta` and produce the extension choice message.
pub fn receive(
    session: &[u8],
    setup: &crate::ot::OtSetup,
    beta: &Scalar,
    grip: &[Scalar],
    counters: &mut Counters,
) -> Result<(ReceiverState, Vec<u8>), &'static str> {
    let mut gamma = vec![0u8; (KAPPA + 2 * STAT + 7) / 8];
    rand::Rng::fill(&mut rand::thread_rng(), &mut gamma[..]);
    let omega = encode(grip, beta, &gamma);

    let (pads, message) = ot::extend_receiver(session, setup, &omega, counters)?;
    Ok((
        ReceiverState {
            omega,
            message: message.clone(),
            pads,
        },
        message,
    ))
}

/// Alice's half: publish the correlation correction and `r, u`.
pub fn reply(
    session: &[u8],
    setup: &crate::ot::OtSetup,
    message: &[u8],
    alpha: &Scalar,
    grip: &[Scalar],
    variant: MulVariant,
    counters: &mut Counters,
) -> Result<(MulReply, Scalar), &'static str> {
    let pads = ot::extend_sender(session, setup, message, counters)?;
    let mut rng = rand::thread_rng();
    let alpha_hat = Scalar::random(&mut rng);

    // Alice's own shares `t_Aj = -v_0j` (Correction) or random `a_j` (Masked), and the public part.
    let mut t_a = Vec::with_capacity(WIDTH * ELL);
    let mut t_a_hat = Vec::with_capacity(WIDTH * ELL);
    let mut correction = Vec::with_capacity(ELL);
    let mut masked = Vec::with_capacity(ELL);

    for index in 0..ELL {
        let v0 = [
            reduce_bits(&pads.v0[WIDTH * index]),
            reduce_bits(&pads.v0[WIDTH * index + 1]),
        ];
        let v1 = [
            reduce_bits(&pads.v1[WIDTH * index]),
            reduce_bits(&pads.v1[WIDTH * index + 1]),
        ];
        match variant {
            MulVariant::Correction => {
                // One value per component: the gap between the two pads, shifted to alpha.
                correction.push([*alpha - (v1[0] - v0[0]), alpha_hat - (v1[1] - v0[1])]);
                t_a.push(-v0[0]);
                t_a_hat.push(-v0[1]);
            }
            MulVariant::Masked => {
                let a = Scalar::random(&mut rng);
                let a_hat = Scalar::random(&mut rng);
                masked.push([
                    v0[0] - a,
                    v1[0] + *alpha - a,
                    v0[1] - a_hat,
                    v1[1] + alpha_hat - a_hat,
                ]);
                t_a.push(a);
                t_a_hat.push(a_hat);
            }
        }
    }
    counters.bits += (ELL * variant.bits_per_ot()) as u64;

    let mut draft = match variant {
        MulVariant::Correction => MulReply::Correction {
            correction,
            r: vec![Scalar::ZERO; ELL],
            u: Scalar::ZERO,
        },
        MulVariant::Masked => MulReply::Masked {
            masked,
            r: vec![Scalar::ZERO; ELL],
            u: Scalar::ZERO,
        },
    };
    let (chi, chi_hat) = coins(session, message, &draft);
    let u = chi * *alpha + chi_hat * alpha_hat;
    let r: Vec<Scalar> = (0..ELL)
        .map(|index| chi * t_a[index] + chi_hat * t_a_hat[index])
        .collect();
    counters.bits += ((ELL + 1) * KAPPA) as u64;

    match &mut draft {
        MulReply::Correction { r: slot, u: value, .. } => {
            *slot = r;
            *value = u;
        }
        MulReply::Masked { r: slot, u: value, .. } => {
            *slot = r;
            *value = u;
        }
    }

    let mut share_a = Scalar::ZERO;
    for index in 0..ELL {
        share_a += gadget(grip, index) * t_a[index];
    }
    Ok((draft, share_a))
}

/// Bob's second half: verify the reply against his pads and return his share `t_B`.
pub fn finish(
    session: &[u8],
    state: &ReceiverState,
    reply: &MulReply,
    grip: &[Scalar],
) -> Result<Scalar, &'static str> {
    let (chi, chi_hat) = coins(session, &state.message, reply);
    let u = reply.u();
    let mut t_b = Scalar::ZERO;
    for index in 0..ELL {
        let vx = [
            reduce_bits(&state.pads.vx[WIDTH * index]),
            reduce_bits(&state.pads.vx[WIDTH * index + 1]),
        ];
        let bit = choice_bit(&state.omega, index);

        // Bob reconstructs his two component shares from his own pad and, only if his choice bit
        // is one, from the sender's public correction.
        let (share, share_hat) = match reply {
            MulReply::Correction { correction, .. } => {
                if bit {
                    (
                        vx[0] + correction[index][0],
                        vx[1] + correction[index][1],
                    )
                } else {
                    (vx[0], vx[1])
                }
            }
            MulReply::Masked { masked, .. } => {
                let entry = masked[index];
                if bit {
                    (entry[1] - vx[0], entry[3] - vx[1])
                } else {
                    (entry[0] - vx[0], entry[2] - vx[1])
                }
            }
        };

        let lhs = chi * share + chi_hat * share_hat;
        let rhs = if bit { u - reply.r(index) } else { -reply.r(index) };
        if lhs != rhs {
            return Err("pi_Mul consistency check failed");
        }
        t_b += gadget(grip, index) * share;
    }
    Ok(t_b)
}

/// Run `pi_Mul`: returns `(t_A, t_B)` with `t_A + t_B = alpha * beta`.
///
/// `alice` is the extension sender, `bob` the extension receiver.
pub fn multiply(
    session: &[u8],
    alice: &OtSetup,
    bob: &OtSetup,
    alpha: &Scalar,
    beta: &Scalar,
    grip: &[Scalar],
    variant: MulVariant,
    counters: &mut Counters,
) -> Result<(Scalar, Scalar), &'static str> {
    let (state, message) = receive(session, bob, beta, grip, counters)?;
    // The libOTe backend runs both halves inside `extend_receiver`, so the sender's pads live in
    // the receiver's setup object.
    let sender_setup = if backend_of(bob) == Backend::LibOte {
        bob
    } else {
        alice
    };
    let (draft, share_a) = reply(
        session,
        sender_setup,
        &message,
        alpha,
        grip,
        variant,
        counters,
    )?;
    let share_b = finish(session, &state, &draft, grip)?;
    Ok((share_a, share_b))
}

/// Nanoseconds spent hashing the coin transcript (SHA-256), for the profiling split.
pub static COIN_NS: AtomicU64 = AtomicU64::new(0);

pub fn coin_ns() -> u64 {
    COIN_NS.load(Ordering::Relaxed)
}

/// Size of the `L`-wide extension batch in bits, for the driver's report.
pub fn extension_bits() -> usize {
    L * DERANDOMISE_BITS
}

/// Field elements per OT, exposed for the report.
pub const fn width() -> usize {
    WIDTH
}

/// Backend of the setup object, re-exported so `sign` and the tests can branch without importing
/// `ot` directly.
pub fn backend_of(setup: &OtSetup) -> Backend {
    setup.backend()
}
