//! Adaptively secure threshold BBS+ signatures.
//!
//! This crate is the reference implementation of the construction in
//! `sections/2-construction.tex` with the instantiation of `sections/A-instantiation.tex`:
//!
//! * [`params`] — `setup`, i.e. `TS.pp = (pp_bbs, h_2, h_1, hh, crs, hashvrf, hashout, hashu, hashS)`,
//! * [`keygen`] — four Shamir polynomials, `X_i`, `Y_i`, role-A NIM encodings, pairwise seeds,
//! * [`round1`] — the dual-base threshold VRF share `W_i` plus a proof `pi_i` of the
//!   presigning relation,
//! * [`round2`] — cross-term decoding, masks, and the `(u_i, S_i)` share,
//! * [`combine`] — `A = S^{1/u}` and the final BBS+ check,
//! * [`sigma`] — the Σ-protocol behind `pi_i`, with a single integer challenge,
//! * [`wire`] — canonical encodings, so parties exchange bytes and nothing else,
//! * [`transport`] — an in-memory bulletin board used by [`session::run_over_bus`].
//!
//! The pairing group is BLS12-381 and the class group is instantiated with BICYCL through
//! the `bicycl` crate.
//!
//! # Cost accounting
//!
//! Every stage takes a [`Breakdown`], which records wall clock on two axes: per primitive
//! ([`Operation`]) and per protocol step ([`Phase`]), with the primitive counts attributed to
//! the innermost active step. `tests/report.rs` prints the resulting tables; the same API is
//! available to any caller that wants a profile.
//!
//! # Deviations from the paper worth knowing
//!
//! * The setup generators `h_0, h_1, hh, h_2` are derived by hash-to-curve from fixed tags
//!   instead of being sampled; this keeps `setup` reproducible and removes a trusted
//!   sampler for the pairing side.
//! * `g_z` is BICYCL's fixed generator `h` of the hard component rather than a fresh random
//!   element of `CH`. The `crs` distribution is otherwise unchanged.
//! * The Σ-protocol is compiled with Fiat–Shamir, not Fischlin/Kondi–Shelat, so extraction
//!   is only argued heuristically, as the appendix notes.
//! * Class-group forms use the Dobson–Galbraith–Smith compressed representation from
//!   BICYCL (`QFI::compressed_repr`, exposed here as [`bicycl::QFI::compressed`]): about
//!   `3/4 log2|Delta_q|` bits, i.e. 226 bytes per element at the paper's parameters against
//!   the table's 220. The four remaining bytes are framing (a flags byte with the component
//!   signs, plus four one-byte lengths).
//!
//! # Verification
//!
//! `tests/e2e.rs` runs the whole `keygen -> presign -> sign -> combine -> verify` chain,
//! including once at the paper's 1827-bit discriminant and once with every message encoded
//! and decoded through [`wire`]. `tests/report.rs` prints the measured sizes, which now match
//! the paper's table to within the framing, and the class-group operation counts.
//!
//! The previous, partially-wired implementation is kept under `legacy/` for reference; it
//! is not compiled.

pub mod algebra;
pub mod bbs;
pub mod bls381;
pub mod combine;
pub mod error;
pub mod hash;
pub mod keygen;
pub mod nim;
pub mod params;
pub mod round1;
pub mod round2;
pub mod session;
pub mod shamir;
pub mod sigma;
pub mod transport;
pub mod util;
pub mod wire;

pub use algebra::{Breakdown, Operation};
pub use bbs::Signature;
pub use bls381::{Scalar255, G1, G2};
pub use error::{Error, Result};
pub use keygen::{keygen, KeyPackage, KeyShare, PartyView, PublicShare};
pub use params::{PublicParameters, SetupConfig};
