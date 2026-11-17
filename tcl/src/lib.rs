//! Threshold CL / threshold ElGamal core.
//!
//! Shared by [`wmc24-bbs`](../wmc24_bbs/index.html) (Wong–Ma–Chow–Yin–Chow, NDSS'24, the
//! *Secure Multiparty Computation of Threshold Signatures Made More Efficient* crate) and
//! [`robot-bbs`](../robot_bbs/index.html) (Tang et al., *Robust Threshold BBS+ in Two Rounds*).
//! Both papers build threshold BBS+ on the same three ingredients, so they live here once:
//!
//! * [`cl`] — the CL framework, its linearly homomorphic operations, and both ciphertext
//!   shapes the papers use (plaintext in `Z_q`, and plaintext a class-group element).
//! * [`share`] — Shamir sharing over `Z_q`, Shamir sharing over the integers (Z-SS, `Delta`),
//!   Lagrange coefficients, and the dual-code consistency check.
//! * [`dkg`] — a concrete PVSS-based realisation of the DKGs both papers invoke for the
//!   BBS+ key (over `G_2`), the ElGamal key (over `G_1`) and the threshold CL key.
//! * [`zkp`] — the Σ-protocols the two signing protocols need, including the cross-group
//!   "same `gamma`" proofs (`R_El-CL` in WMC24, `R_con` in ROBOT).
//!
//! # One t-CL normalisation for both papers
//!
//! WMC24 and ROBOT state t-CL slightly differently. WMC24 uses `ek = g_q^{Delta^3 k}` with a
//! `g_q^{Delta^2}` ciphertext base and combines as `c_1^{Delta^2} / prod cpd^{Delta L}`;
//! ROBOT writes `pk_cl = g_q^k` with a `g_q` base and combines as `c_2^{Delta^3} / prod M^{Delta L}`.
//! Both are the *same* scheme under a different `Delta` bookkeeping: with Z-SS shares
//! (`F(0) = Delta k`, so `sum_i L_i k_i = Delta k`), the publicly computable key is
//! `g_q^{Delta^3 k}` and the reachable decryption combines to `f^{m Delta^2}`. This crate
//! implements the WMC24 normalisation once; `robot-bbs` uses it as-is and says so, rather than
//! carrying a second copy of the same algebra.
//!
//! # What is *not* reproduced
//!
//! WMC24 §IV's rushing-resilient two-round DKG (publicly verifiable linearly homomorphic
//! delivery of base-`q` ciphertext shares, `R_BInt`, complaint elimination) and ROBOT's
//! ideal functionalities `F_cldkg` / `F_egdkg` are replaced by the concrete PVSS DKG in
//! [`dkg`]: commitments to the polynomial are broadcast, shares go over private channels, and
//! a failing check aborts. The *outputs* have exactly the shape both signing protocols
//! consume (`k_i`, `pk_i = g_q^{Delta k_i}`, `g_q^{Delta^3 k}`, `x_i`, `X_i`, `X`), and honest
//! majority suffices, but the papers' own DKG contributions — identifiable abort on the
//! delivery path, and the rushing-resilient set-shrinking — are not implemented here. The
//! robustness that *is* implemented is the signing protocols' own: every round verifies the
//! peers' proofs and shrinks the participant set, aborting only when it falls to the
//! threshold.

pub mod cl;
pub mod dkg;
pub mod eg;
pub mod meter;
pub mod random;
pub mod share;
pub mod util;
pub mod wire;
pub mod zkp;

pub use cl::{ClParameters, Cipher};
pub use dkg::{dkg_cl, dkg_dl, setup, ClKey, DlKey, ThresholdKeys};
pub use error::{Error, Result};
pub use meter::{Meter, Op};
pub use share::Zss;

pub mod error;
