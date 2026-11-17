//! Two-party BBS+ signatures in two passes.
//!
//! Reference implementation of *Two-Party BBS+ Signature in Two Passes* (Wu, Qiu, Tang, Niu,
//! Jiang, Zhou, Xue, Yang), the paper in `refs/`. It is the third implementation in this
//! workspace and shares only the BLS12-381 backend, the transcript machinery and the `bicycl`
//! bindings with the others — the class-group layer here is the plain CL encryption of §2.2,
//! not a threshold KEM.
//!
//! # What is implemented
//!
//! * [`cl`] — `CL-Enc`/`CL-Dec` and the homomorphic addition and scalar multiplication over
//!   BICYCL's `CL_HSMqk` at `k = 1`, so the plaintext space is exactly `Z_q` and no range
//!   proof is needed.
//! * [`vrf`] — ECVRF over `G_1` (`Gamma, c, s`, `beta = Hash(vk, Gamma)`), used by `P_2` only.
//! * [`zkp`] — `R_DL`, `R_CL-DL` and `R_CL-Lin` as Fiat–Shamir Σ-protocols.
//! * [`keygen`] — the three-pass DKG: `h = H_0(X_1)`, `X_2` with `vk_2`, then `X_1`, `ek_1`,
//!   `C_key1` with its proof.
//! * [`sign`] — the two-pass signing protocol of Fig. 1, plus `bbs` verification.
//! * [`session`] — drivers that put every message through the wire format.
//!
//! # Cost shape
//!
//! Two passes and roughly 0.9 KiB per signature, independent of the message count except for
//! the linear cost of `B`. Measured by `tests/report.rs` at the paper's 1827-bit discriminant:
//!
//! ```text
//! pass 1  (P_1 -> P_2)   32 B
//! pass 2  (P_2 -> P_1)   VRF proof 96 B + C 48 B + D 450 B + pi_Lin 321 B = 915 B
//! total                  947 B = 0.925 KiB        (paper's Table 1: 0.85 KB, 2 passes)
//! class-group element    225 B compressed          (paper: 219 B)
//! ```
//!
//! Key generation costs 32 B + 192 B + 958 B, once.
//!
//! One signature is about 11 class-group exponentiations with long exponents, 5 with `Z_q`
//! exponents, 12 compositions, one `CL.Solve` and two pairings; the numbers are per signature,
//! split between the two parties roughly 8/6.
//!
//! # Deviations from the paper
//!
//! * **`R_CL-Lin` (Fig. 4) is realized without a `G_T` commitment.** Fig. 4 commits to the
//!   pairing identity with `T_{alpha_t} = alpha_t G_H in G_T` and hashes it into the
//!   challenge. `bls12_381::Gt` has no canonical encoding, so this implementation instead sends
//!   `W = r(x+e) B` and has the verifier check `e(W, G_2) = e(C, X + e G_2)` as a public
//!   statement check. Soundness and HVZK are preserved (see the module docs of [`zkp`]), and
//!   the proof ends up 16 B smaller because `beta_t` disappears; `W` reveals nothing extra,
//!   since `P_1` recovers `r(x+e)` from `D` anyway.
//! * `D_q = [0, 2^{lambda_s} s_bar)` instead of the paper's `[0, 2^{lambda_s} q s]`. The extra
//!   `q` is not needed for `g_q^rho` to be near-uniform in `<g_q>`, and dropping it shortens
//!   every `rho` response by 256 bits.
//! * The response intervals are `(2^{lambda+lambda_s} + 2^{lambda}) B_q` rather than the
//!   paper's `[0, 2^{lambda+lambda_s} B_q]`: an honest response can exceed the stated bound by
//!   `ch * rho <= 2^{lambda} B_q`, so the paper's interval would reject honest proofs. The
//!   soundness-relevant fact — the response is bounded by `~2^{lambda+lambda_s} B_q` — is
//!   unchanged.
//! * `H_1`, the base of the `R_CL-Lin` commitment, is a dedicated hash-to-curve generator
//!   (`pp.crs_h1` in the paper's role) instead of reusing the message base `H_1` of the
//!   parameters.
//! * The VRF is RFC 9381's shape (hash to curve, `Gamma = sk H`, Chaum–Pedersen proof
//!   compiled with Fiat–Shamir, `beta = Hash(vk, Gamma)`), but the suite identifiers and the
//!   final "proof-to-hash" tweaks of the RFC are not reproduced. `Y = {0,1}^256`.
//! * Signing is **stateful**: both parties refuse to reuse a `sid`, as §3 requires. Reusing one
//!   would replay `P_2`'s VRF output and let a corrupted `P_1` grind `beta_1`.
//! * The `(2, n)` extension (Feldman VSS, Lagrange coefficients) is not implemented; this is
//!   the 2-out-of-2 protocol of §3.
//! * Proofs are Fiat–Shamir, so the NIZK's zero-knowledge is argued in the programmable
//!   random-oracle model. The paper notes that `pi_Vrf` and `pi_Lin` do not need to be proofs
//!   of knowledge, which is what makes FS acceptable there.

pub mod bbs;
pub mod cl;
pub mod error;
pub mod keygen;
pub mod meter;
pub mod params;
pub mod random;
pub mod session;
pub mod sign;
pub mod vrf;
pub mod wire;
pub mod zkp;

pub use bbs::Signature;
pub use cl::{Cipher, ClParameters};
pub use error::{Error, Result};
pub use keygen::{FirstParty, SecondParty};
pub use params::{PublicParameters, SetupConfig};
pub use session::{run_dkg, run_signing, DkgOutcome, SignOutcome};
pub use sign::{SignerOne, SignerTwo};
