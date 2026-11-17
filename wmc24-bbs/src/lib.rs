//! Threshold BBS+ from threshold CL encryption (Wong, Ma, Chow, Yin, Chow — NDSS'24).
//!
//! Reference implementation of §VI.C of `refs/`, on top of the shared threshold-CL / ElGamal
//! core in the [`tcl`] crate. Four rounds, robustness against a minority of corrupted signers,
//! constant per-signer communication.
//!
//! ```text
//! Step 1  e_i, s_i encrypted under the threshold CL key, with R_Enc proofs
//! Step 2  aggregate  ebar, sbar,  and  x+e = xbar + ebar
//! Step 3  partial decryptions of ebar and sbar (R_PartDec)
//! Step 4  FinDec -> e, s ;  D = g_1 h_0^s prod h_k^{m_k}
//! Step 5  gamma_i;  C_{gamma_i};  EG ciphertext of gamma_i D;  gamma_i (x+e) with R_El-CL
//! Step 6  aggregate  C_gamma,  EG ciphertexts,  gamma (x+e)
//! Step 7  partial decryptions of D^gamma (ElGamal) and gamma (x+e) (CL)
//! Step 8  FinDec both,  A = D^gamma / (gamma (x+e))
//! ```
//!
//! Two things are worth pointing out because they look redundant but are not:
//!
//! * `x` never leaves its CL encryption. Step 2 adds `ebar` to `xbar`, so the value that is
//!   finally decrypted in step 7 is `gamma (x+e)`, not `x`.
//! * `gamma_i` is drawn fresh by each signer and never opened. It masks `x` in the only place
//!   the protocol would otherwise reveal it, and `R_El-CL` is what stops a signer from using
//!   different `gamma`s in the ElGamal and CL halves.
//!
//! The aggregated `C_gamma` of step 6 has no consumer in the BBS+ flow (it is used by the
//! paper's ECDSA variant); it is still computed and checked here.
//!
//! # Cost shape
//!
//! Measured by `tests/report.rs` at the paper's 1827-bit discriminant with `n = 4, t = 2`
//! (bytes uploaded per signer):
//!
//! ```text
//! ell   step 1   step 3   step 5   step 7   per signer   total (4 signers)
//! 1      1312      823     1142      511      3.70 K          14.8 K
//! 10     1312      822     1142      510      3.70 K          14.8 K
//! ```
//!
//! Step 1 carries two `R_Enc` proofs, step 3 two `R_PartDec` proofs, step 5 one `R_El-CL`, and
//! step 7 one `R_PartDec` plus one DDH proof; the class-group elements dominate everywhere.
//!
//! # Deviations
//!
//! * The DKGs are [`tcl::dkg`]'s PVSS construction rather than the paper's rushing-resilient
//!   two-round DKG-CL / DKG-DL (§IV). See the `tcl` crate docs for exactly what that trades
//!   away: the outputs are identical in shape, but identifiable abort on the delivery path and
//!   the base-`q` encrypted-share machinery are not implemented.
//! * `h_0, ..., h_ell` are hash-derived from fixed tags rather than distributively sampled.
//! * Only BBS+ is implemented (the paper's threshold ECDSA is out of scope, as requested).

pub mod bbs;
pub mod session;
pub mod sign;

pub use bbs::{big_b, verify, PublicParameters, Signature};
pub use sign::{Round1Msg, Round2Msg, Round3Msg, Round4Msg, Signer};
