//! OT layer: base OTs (setup) and the SoftSpokenOT extension (per multiplication).
//!
//! Two interchangeable backends realise the same interface:
//!
//! * [`Backend::SlOblivious`] — the vendored copy of `sl-oblivious` in the sibling directory
//!   `../sl-oblivious`, patched to `L = 768` and `OT_WIDTH = 2`, so one extension instance covers
//!   OTs. This is the backend the paper-facing numbers were produced with.
//! * [`Backend::LibOte`] — the reference SoftSpokenOT implementation of
//!   <https://github.com/osu-crypto/libOTe>, wired in through the C++ shim in `cpp/libote_shim.cc`.
//!   One extension instance is `ELL * BLOCKS_PER_OT = 2688` 128-bit OTs; the four blocks of one
//!   `pi_Mul` OT are concatenated pairwise into the same 256-bit pads the other backend produces.
//!
//! Both backends are driven on a single thread, so the measured wall time is the joint cost of
//! the two parties and is directly comparable across backends.
//!
//! # Measurement split
//!
//! [`base_ot`] is the one-time setup ([`crate::params::BASE_OT_MSG_BYTES`] per message, two
//! messages, `2*LAMBDA_C` EC scalar multiplications per party); the `extend_*` functions are the
//! per-session extension. They are counted and timed separately by the driver.
//!
//! # Single-process model
//!
//! As in the rest of this project, all parties run in one process. For the `sl-oblivious` backend
//! the extension seeds are materialised with the library's own `generate_all_but_one_seed_ot`,
//! which is the "assume the base OTs happened" path; [`base_ot`] is still executed and measured so
//! that the setup cost is a real measurement rather than a formula. The `libOTe` backend runs the
//! base OTs for real over an in-process socket pair.

#[cfg(feature = "libote")]
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use sl_oblivious::endemic_ot::{
    EndemicOTMsg1, EndemicOTMsg2, EndemicOTReceiver, EndemicOTSender, ReceiverOutput, SenderOutput,
};
use sl_oblivious::soft_spoken::{
    generate_all_but_one_seed_ot, ReceiverExtendedOutput, ReceiverOTSeed, Round1Output,
    SenderOTSeed, SoftSpokenOTReceiver, SoftSpokenOTSender,
};

use crate::params::{BASE_OT_MSG_BYTES, ELL, L, ROUND1_BYTES, WIDTH};

#[cfg(feature = "libote")]
use crate::params::{BLOCKS_PER_OT, LIBOTE_OTS};

/// Nanoseconds spent inside the extension (Keccak/AES + GF(2^128)), for profiling.
pub static EXT_NS: AtomicU64 = AtomicU64::new(0);

pub fn ext_ns() -> u64 {
    EXT_NS.load(Ordering::Relaxed)
}

/// Which library realises the OT extension.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend {
    /// Vendored `sl-oblivious`, `L = 3*kappa` rows of `2*kappa` bits.
    SlOblivious,
    /// `libOTe`'s `SoftSpokenMalOtExt`, `ELL * 4` 128-bit OTs.
    LibOte,
}

impl Backend {
    pub fn name(self) -> &'static str {
        match self {
            Backend::SlOblivious => "sl-oblivious",
            Backend::LibOte => "libOTe",
        }
    }
}

/// Sender's two pads per OT component: `2 * ELL` entries of 256 bits, laid out as
/// `[ot_0 component_0, ot_0 component_1, ot_1 component_0, ...]`.
pub struct SenderPads {
    pub v0: Vec<[u8; 32]>,
    pub v1: Vec<[u8; 32]>,
}

/// Receiver's pad per OT component, same layout.
pub struct ReceiverPads {
    pub vx: Vec<[u8; 32]>,
}

fn blank_sender() -> SenderPads {
    SenderPads {
        v0: vec![[0u8; 32]; WIDTH * ELL],
        v1: vec![[0u8; 32]; WIDTH * ELL],
    }
}

/// Wire traffic and primitive counts, in bits and operations.
#[derive(Clone, Copy, Debug, Default)]
pub struct Counters {
    pub bits: u64,
    pub ots: u64,
    pub ec_ops: u64,
}

impl Counters {
    /// Average bits per party (the paper's convention for bandwidth).
    pub fn per_party_bits(&self) -> u64 {
        self.bits / 2
    }

    pub fn add(&mut self, other: &Counters) {
        self.bits += other.bits;
        self.ots += other.ots;
        self.ec_ops += other.ec_ops;
    }
}

/// One pair's persistent extension material, produced once during setup.
pub enum OtSetup {
    Sl {
        sender: SenderOTSeed,
        receiver: ReceiverOTSeed,
    },
    /// The whole two-party extension runs inside one call, so the sender's pads produced during
    /// the receiver's half are parked here until the sender asks for them.
    #[cfg(feature = "libote")]
    Libote {
        pair: crate::libote::Pair,
        pending: Mutex<Option<SenderPads>>,
    },
}

impl OtSetup {
    /// Setup for the `sl-oblivious` backend (the historical constructor).
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        let (sender, receiver) = generate_all_but_one_seed_ot(&mut rng);
        Self::Sl { sender, receiver }
    }

    /// Setup for the `libOTe` backend with SoftSpokenOT's default `field_bits = 2`.
    #[cfg(feature = "libote")]
    pub fn libote() -> Option<Self> {
        Self::libote_with_field_bits(2)
    }

    /// Setup for the `libOTe` backend, choosing SoftSpokenOT's computation/communication knob.
    ///
    /// `field_bits` trades wire for CPU: at 2 an extension instance of 2688 OTs costs 22 989 B,
    /// at 4 it costs 11 565 B for the same time, at 8 it costs 5 853 B but roughly triples the
    /// CPU. `field_bits = 4` is what matches Roy's `k = 2` cost model in practice; see the README.
    #[cfg(feature = "libote")]
    pub fn libote_with_field_bits(field_bits: u32) -> Option<Self> {
        crate::libote::Pair::with_field_bits(field_bits).map(|pair| Self::Libote {
            pair,
            pending: Mutex::new(None),
        })
    }

    /// Setup for the requested backend with the backend's default options.
    pub fn with_backend(backend: Backend) -> Option<Self> {
        Self::with_options(backend, 2)
    }

    /// Setup for the requested backend; `field_bits` only affects the `libOTe` backend.
    pub fn with_options(backend: Backend, field_bits: u32) -> Option<Self> {
        match backend {
            Backend::SlOblivious => Some(Self::new()),
            #[cfg(feature = "libote")]
            Backend::LibOte => Self::libote_with_field_bits(field_bits),
            #[cfg(not(feature = "libote"))]
            Backend::LibOte => {
                let _ = field_bits;
                None
            }
        }
    }

    pub fn backend(&self) -> Backend {
        match self {
            OtSetup::Sl { .. } => Backend::SlOblivious,
            #[cfg(feature = "libote")]
            OtSetup::Libote { .. } => Backend::LibOte,
        }
    }
}

impl Default for OtSetup {
    fn default() -> Self {
        Self::new()
    }
}

/// Endemic base OT (MR19): receiver sends `Msg1`, sender replies `Msg2`.
///
/// This is the `MulSetupCost` of the paper, measured rather than quoted.
pub fn base_ot(session: &[u8], counters: &mut Counters) -> Result<(), &'static str> {
    let mut rng = rand::thread_rng();
    let mut msg1 = EndemicOTMsg1::default();
    let mut msg2 = EndemicOTMsg2::default();

    let receiver = EndemicOTReceiver::new(session, &mut msg1, &mut rng);
    counters.bits += (BASE_OT_MSG_BYTES * 8) as u64;
    counters.ec_ops += crate::params::BASE_OT_EC_OPS / 2;

    let _sender_output: SenderOutput = EndemicOTSender::process(session, &msg1, &mut msg2, &mut rng)?;
    counters.bits += (BASE_OT_MSG_BYTES * 8) as u64;
    counters.ec_ops += crate::params::BASE_OT_EC_OPS / 2;

    let _receiver_output: ReceiverOutput = receiver.process(&msg2)?;
    Ok(())
}

/// Spread the `ELL` canonical choice bits so that the four libOTe blocks of one `pi_Mul` OT share
/// the same choice bit.
#[cfg(feature = "libote")]
fn widen_choices(omega: &[u8]) -> Vec<u8> {
    let mut wide = vec![0u8; LIBOTE_OTS / 8];
    for index in 0..LIBOTE_OTS {
        let source = index / BLOCKS_PER_OT;
        let bit = (omega[source / 8] >> (source % 8)) & 1;
        if bit == 1 {
            wide[index / 8] |= 1 << (index % 8);
        }
    }
    wide
}

/// Cut a flat run of 16-byte blocks into `256`-bit pads, two blocks per pad.
#[cfg(feature = "libote")]
fn pack_blocks(blocks: &[u8]) -> Vec<[u8; 32]> {
    let mut out = Vec::with_capacity(WIDTH * ELL);
    for index in 0..(WIDTH * ELL) {
        let mut pad = [0u8; 32];
        pad[..16].copy_from_slice(&blocks[32 * index..32 * index + 16]);
        pad[16..].copy_from_slice(&blocks[32 * index + 16..32 * index + 32]);
        out.push(pad);
    }
    out
}

/// Receiver side of one extension: returns the pads and the wire message it must send.
///
/// `omega` holds the `ELL` choice bits (little-endian within bytes). For the `libOTe` backend the
/// sender's pads are produced in the same call and parked in `setup`.
pub fn extend_receiver(
    session: &[u8],
    setup: &OtSetup,
    omega: &[u8],
    counters: &mut Counters,
) -> Result<(ReceiverPads, Vec<u8>), &'static str> {
    if omega.len() * 8 < ELL {
        return Err("omega shorter than one multiplication");
    }
    match setup {
        OtSetup::Sl { sender, .. } => {
            let mut rng = rand::thread_rng();
            let mut round1 = Round1Output::default();
            let mut out = bytemuck::allocation::zeroed_box::<ReceiverExtendedOutput>();
            let mut choices = vec![0u8; L / 8];
            let used = (ELL + 7) / 8;
            choices[..used].copy_from_slice(&omega[..used]);
            rand::Rng::fill(&mut rng, &mut choices[used..]);
            out.choices.copy_from_slice(&choices);

            let started = Instant::now();
            SoftSpokenOTReceiver::process(session, sender, &mut round1, &mut out, &mut rng);
            EXT_NS.fetch_add(started.elapsed().as_nanos() as u64, Ordering::Relaxed);
            counters.bits += (ROUND1_BYTES * 8) as u64;
            counters.ots += L as u64;

            let mut vx = Vec::with_capacity(WIDTH * ELL);
            for index in 0..ELL {
                for component in 0..WIDTH {
                    vx.push(out.v_x[index][component]);
                }
            }
            Ok((
                ReceiverPads { vx },
                bytemuck::bytes_of(&round1).to_vec(),
            ))
        }
        #[cfg(feature = "libote")]
        OtSetup::Libote { pair, pending } => {
            let wide = widen_choices(omega);
            let started = Instant::now();
            let (v0, v1, vx, stats) = pair
                .extend(&wide, LIBOTE_OTS)
                .ok_or("libOTe extension failed")?;
            EXT_NS.fetch_add(started.elapsed().as_nanos() as u64, Ordering::Relaxed);
            counters.bits += (stats.bytes_sender + stats.bytes_receiver) * 8;
            counters.ots += LIBOTE_OTS as u64;
            *pending.lock().expect("pending pads") = Some(SenderPads {
                v0: pack_blocks(&v0),
                v1: pack_blocks(&v1),
            });
            Ok((ReceiverPads { vx: pack_blocks(&vx) }, Vec::new()))
        }
    }
}

/// Sender side of one extension.
///
/// For the `sl-oblivious` backend this consumes the receiver's wire message; for `libOTe` the pads
/// were already produced by [`extend_receiver`] and this only takes them out of the slot.
pub fn extend_sender(
    session: &[u8],
    setup: &OtSetup,
    message: &[u8],
    counters: &mut Counters,
) -> Result<SenderPads, &'static str> {
    match setup {
        OtSetup::Sl { receiver, .. } => {
            if message.len() != ROUND1_BYTES {
                return Err("malformed extension message");
            }
            let round1: Round1Output =
                bytemuck::pod_read_unaligned::<Round1Output>(&bytemuck::pod_collect_to_vec(message));
            let started = Instant::now();
            let out = SoftSpokenOTSender::process(session, receiver, &round1)
                .map_err(|_| "SoftSpokenOT sender failed")?;
            EXT_NS.fetch_add(started.elapsed().as_nanos() as u64, Ordering::Relaxed);

            let mut pads = blank_sender();
            for index in 0..ELL {
                for component in 0..WIDTH {
                    pads.v0[WIDTH * index + component] = out.v_0[index][component];
                    pads.v1[WIDTH * index + component] = out.v_1[index][component];
                }
            }
            Ok(pads)
        }
        #[cfg(feature = "libote")]
        OtSetup::Libote { pending, .. } => {
            let _ = counters;
            pending
            .lock()
            .expect("pending pads")
                .take()
                .ok_or("libOTe sender pads missing")
        }
    }
}

/// Both halves of one extension, for the single-process [`crate::mul::multiply`] path.
///
/// The `libOTe` backend runs both parties inside [`extend_receiver`], so `sender_setup` is only
/// consulted by the `sl-oblivious` backend.
pub fn extend(
    session: &[u8],
    receiver_setup: &OtSetup,
    sender_setup: &OtSetup,
    omega: &[u8],
    counters: &mut Counters,
) -> Result<(SenderPads, ReceiverPads), &'static str> {
    let (receiver_pads, message) = extend_receiver(session, receiver_setup, omega, counters)?;
    let sender_setup = if receiver_setup.backend() == Backend::LibOte {
        receiver_setup
    } else {
        sender_setup
    };
    let sender_pads = extend_sender(session, sender_setup, &message, counters)?;
    Ok((sender_pads, receiver_pads))
}
