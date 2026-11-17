//! Online-friendly three-round threshold BBS+ (Tang–Xue, S&P'25).
//!
//! Reference implementation of §5 of `refs/`, on the shared CL core in [`tcl`]. The paper's
//! headline is the split: everything message-independent happens **offline** (two rounds of
//! CL-based multi-party MtA), so signing a message costs a **single** online round.
//!
//! ```text
//! Offline 1  gamma_i;  C_{gamma_i} = CL.Enc(ek_i, gamma_i);  tau_i (R_Enc);
//!            ebar_i = H(e_i), sbar_i = H(s_i)                     [commit the nonces]
//! Offline 2  k* = x_i + e q with e <- D_q;  for each j:
//!            C_{alpha_{j,i}} = (c_{j1}^{k*}, c_{j2}^{k*} f^{-beta_{i,j}}),  B_{i,j} = beta_{i,j} G_2
//!            one aggregated R* proof over all j;  open (e_i, s_i)
//! Offline out  zeta_{i,j} = Dec(dk_i, C_{alpha_{i,j}}) + beta_{i,j};  e = sum e_i, s = sum s_i
//! Online     chi_{i,j} = e gamma_i + zeta_{i,j} + f(j) (f(0) = 0);  R_i = gamma_i D
//! Output     A = (sum_j lambda_j R_j) / (sum_{j,nu} lambda_j lambda_nu chi_{j,nu})
//! ```
//!
//! # Why the double Lagrange sum
//!
//! `zeta_{i,j}` is not a share of `gamma_i x_j` alone — it is `alpha_{i,j} + beta_{i,j}`, which
//! equals `gamma_i x_j + (beta_{i,j} - beta_{j,i})`. Summing with the symmetric weight
//! `lambda_i lambda_j` cancels the antisymmetric `beta` terms, leaving
//! `sum lambda_i lambda_j gamma_i x_j = gamma x`; adding `sum lambda_i e gamma_i = e gamma`
//! gives exactly `gamma (x+e)`, which is what `A = gamma D / gamma (x+e)` needs. The
//! `f(0) = 0` polynomial re-randomises the individual `chi_{i,j}` without changing the sum.
//!
//! # Robustness
//!
//! Both offline rounds and the online round verify what they receive and shrink the signer set;
//! if the assembled signature still fails to verify, the parties run the paper's cheater
//! identification: `T_j = sum_nu lambda_nu (chi_{j,nu} G_2 - B_{j,nu} + B_{nu,j})` and
//! `e(R_j, e G_2 + X) = e(D, T_j)`, dropping every `j` that fails.
//!
//! # Cost shape
//!
//! Measured by `tests/e2e.rs` at 1827-bit `Delta_K` with `n = 3, t = 2, ell = 2`, uploaded per
//! signer:
//!
//! ```text
//! offline round 1   724 B   (C_{gamma_i}, its R_Enc proof, two nonce hashes)
//! offline round 2  2763 B   (|S| alpha ciphertexts, |S| B points, one batched R* proof)
//! online round      178 B   (|S| chi values and R_i)
//! total            ~3.7 KiB per signer
//! ```
//!
//! The offline rounds are the expensive ones by design: they carry the `MtA` traffic. The
//! online round is a single broadcast whose size grows only with `|S|` (the `chi` values), which
//! is the property the paper is built for.
//!
//! # Deviations
//!
//! * The key generation is [`tcl::dkg`]'s Feldman DKG over `G_2` (for `x`) plus a locally
//!   sampled CL key pair per party with an `R_key` proof, instead of the paper's Figure 1
//!   `ShareDist`/`ShareComb` DKG that delivers CL-encrypted shares and proves `R_Dec-DL`.
//!   The outputs are the same shape (`x_i`, `X_i`, `X`, `ek_j`), and `R_key` here is the
//!   straightforward class-group Schnorr proof rather than the five-round Yuen et al. protocol
//!   the paper uses to get online extractability.
//! * `k*` uses `e <- D_q` (the paper's `Af` definition) rather than the `e <- Z_q` written in
//!   the `MPMtA_2` step; the larger range is what makes `k*` statistically hide `k_i mod q`.
//! * `H_1 .. H_{ell+1}` are hash-derived from fixed tags; the paper has them sampled.
//! * The batched `R*` proof is instantiated as described in Appendix A.3 with our own domain
//!   separation; the per-j batching exponents are derived from one statement digest.

pub mod keys;
pub mod mta;
pub mod params;
pub mod session;
pub mod sign;

pub use bbs::{Signature, verify};
pub use keys::{setup, KeyProof, Keys};
pub use mta::{AffProof, Aggregated};
pub use params::PublicParameters;
pub use session::{run_signing, SignOutcome};
pub use sign::{Offline1Msg, Offline2Msg, OnlineMsg, Signer};

/// BBS+ itself: `A = (G_1 + s H_1 + sum m_k H_{k+1}) / (x+e)` and its pairing check.
pub mod bbs {
    use threshold_bbs::algebra::{Group, PairingGroup, Scalar};
    use threshold_bbs::bls381::{Scalar255, G1, G2};

    use tcl::Error;

    /// `D = G_1 + sum_k m_k H_{k+1}` (the `s` part is added separately).
    pub fn base_d(bases: &[G1], message: &[Scalar255]) -> Result<G1, Error> {
        if message.len() + 1 != bases.len() {
            return Err(Error::Protocol("message length does not match the bases"));
        }
        let mut value = threshold_bbs::bls381::generator_g1();
        for (base, scalar) in bases[1..].iter().zip(message) {
            value = value.combine(&base.scale(scalar));
        }
        Ok(value)
    }

    /// `G_1 + s H_1 + sum_k m_k H_{k+1}`.
    pub fn big_b(bases: &[G1], s: &Scalar255, message: &[Scalar255]) -> Result<G1, Error> {
        if message.len() + 1 != bases.len() {
            return Err(Error::Protocol("message length does not match the bases"));
        }
        let mut value = base_d(bases, message)?;
        value = value.combine(&bases[0].scale(s));
        Ok(value)
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct Signature {
        pub a: G1,
        pub e: Scalar255,
        pub s: Scalar255,
    }

    /// `e(A, X + e G_2) = e(G_1 + s H_1 + sum m_k H_{k+1}, G_2)`.
    pub fn verify(
        bases: &[G1],
        x_g2: &G2,
        message: &[Scalar255],
        signature: &Signature,
    ) -> bool {
        if signature.e.is_zero() {
            return false;
        }
        let b = match big_b(bases, &signature.s, message) {
            Ok(value) => value,
            Err(_) => return false,
        };
        let g2 = threshold_bbs::bls381::generator_g2();
        let denominator = x_g2.combine(&g2.scale(&signature.e));
        G1::pairing(&denominator, &signature.a) == G1::pairing(&g2, &b)
    }

    pub fn encode_message(message: &[Scalar255]) -> Vec<u8> {
        let mut out = Vec::with_capacity(message.len() * 32);
        for value in message {
            out.extend_from_slice(&value.to_be_bytes());
        }
        out
    }
}

pub use bbs::encode_message;
pub use tcl::{Error, Result};
