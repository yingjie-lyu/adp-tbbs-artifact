//! Robust threshold BBS+ in two rounds (Tang, Qiu, Jiang, Xue, Yang, Au, Deng, Lam).
//!
//! Reference implementation of the protocol in `refs/`, on top of the shared threshold-CL /
//! ElGamal core in the [`tcl`] crate. Two rounds, robustness against up to `t` malicious
//! parties (the second round only needs decryption-key shares, so the signer set may change
//! between rounds), and a constant-size first-round broadcast per signer.
//!
//! ```text
//! Round 1  Z_i = x̂_i Y,  pi_i (DDH);   gamma_i;  C_{gamma_i}, C_{gamma_i x};
//!          C_{D_0i} = EG(gamma_i H_0),  C_{D_1i} = EG(gamma_i D);  pi_con
//! Round 2  Z = sum_j lambda_j Z_j  ->  e = H1(Z,0),  s = H1(Z,1);
//!          C_{gamma x + gamma e} = C_{gamma x} + e C_{gamma};
//!          C_{s D_0 + D_1} = s C_{D_0} + C_{D_1};
//!          M_i = c_0^{Delta k_i} with tau_i (CL partial decryption);
//!          M'_i = x̂_i A_1 with tau'_i (ElGamal partial decryption)
//! Output   a = CL.Combine(...) = gamma (x+e),   R = EG.Combine(...) = gamma (s H_0 + D),
//!          A = R / a
//! ```
//!
//! The two nonces come from a *threshold VRF*: each `Z_i` is a partial evaluation, and `Z`
//! is the unique VRF output of `H_0(m, sid)`, so `(e, s)` are unbiased even against a rushing
//! adversary, in one pass.
//!
//! # Cost shape
//!
//! Measured by `tests/report.rs` at the paper's 1827-bit discriminant with `n = 4, t = 2`
//! (K = KiB per signer, uploaded):
//!
//! ```text
//! ell   round 1   round 2   per signer   total (4 signers)
//! 1      1550 B     511 B     2.01 K          8.05 K
//! 10     1551 B     511 B     2.01 K          8.06 K
//! ```
//!
//! Both rounds are constant in the number of signers and in `ell`; `ell` only costs the
//! signer-local multiplications that build `D`.
//!
//! # Deviations
//!
//! * The three DKGs are realised by [`tcl::dkg`]'s PVSS construction, not by the abstract
//!   `F_cldkg` / `F_egdkg` functionalities the paper invokes (which it delegates to WMC24).
//! * The `t-CL` ciphertext base and combination follow the WMC24 normalisation
//!   (`g_q^{Delta^2}` base, `c_1^{Delta^2} / prod M^{Delta L}`), which is the same scheme as
//!   the paper's `g_q` base with `Delta^3`, only with a different `Delta` bookkeeping; see the
//!   `tcl` crate docs.
//! * `H = (H_0, ..., H_ell)` is derived by hash-to-curve from `X`, as the paper prescribes,
//!   with our own domain separation.
//! * Signing requires `|P| >= t + 1` valid participants, as the paper's robustness claim
//!   states; the underlying sharing threshold is `t`.

pub mod bbs;
pub mod session;
pub mod sign;

pub use bbs::{big_b, verify, Bases, PublicParameters, Signature};
pub use sign::{Round1Msg, Round2Msg, Signer};
