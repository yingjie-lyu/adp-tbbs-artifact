//! Parameters of the DKLST baseline.
//!
//! `kappa` is the bit length of the BLS12-381 group order, `s` the statistical parameter of the
//! DKLs18 multiplier, and one `pi_Mul` consumes `ell = 2*kappa + 2*s = 672` OTs.

/// `|q|` for BLS12-381 (the scalar field we compute in).
pub const KAPPA: usize = 256;

/// Computational security parameter (`lambda`), for the sizes of commitments and hashes.
pub const LAMBDA: usize = 128;

/// Statistical security parameter of the DKLs18 multiplier.
pub const STAT: usize = 80;

/// `ell = 2*kappa + 2*s`: OTs consumed by one multiplication.
pub const ELL: usize = 2 * KAPPA + 2 * STAT;

/// Batch size of one SoftSpokenOT extension instance (vendored copy: `L = 3*kappa`).
pub const L: usize = 3 * KAPPA;

/// Field elements carried by each OT (vendored copy: `OT_WIDTH = L_BATCH + RHO = 2`).
pub const WIDTH: usize = 2;

/// One `pi_Mul` OT carries `WIDTH * KAPPA = 512` bits, i.e. this many 128-bit libOTe blocks.
pub const BLOCKS_PER_OT: usize = (WIDTH * KAPPA) / 128;

/// OTs of one `libOTe` extension instance: `ELL` `pi_Mul` OTs, four blocks each.
pub const LIBOTE_OTS: usize = ELL * BLOCKS_PER_OT;

/// Number of base OTs of the Endemic OT (`LAMBDA_C`).
pub const LAMBDA_C: usize = 256;

/// Bits a party sends per extended OT when derandomising: two field elements.
pub const DERANDOMISE_BITS: usize = WIDTH * KAPPA;

/// Bytes of the receiver's extension message (`Round1Output`).
pub const ROUND1_BYTES: usize = std::mem::size_of::<sl_oblivious::soft_spoken::Round1Output>();

/// Bytes of the sender's extended output.
pub const SENDER_OUT_BYTES: usize =
    std::mem::size_of::<sl_oblivious::soft_spoken::SenderExtendedOutput>();

/// Bytes of one Endemic OT message (256 indices, two compressed secp256k1 points each).
pub const BASE_OT_MSG_BYTES: usize =
    std::mem::size_of::<sl_oblivious::endemic_ot::EndemicOTMsg1>();

/// EC scalar multiplications per party in the base OT.
pub const BASE_OT_EC_OPS: u64 = 2 * LAMBDA_C as u64;
