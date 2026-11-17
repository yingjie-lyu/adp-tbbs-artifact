//! A three-round threshold BBS+ signature scheme built from the CL KEM.
//!
//! Reference implementation of *Efficient Construction of Threshold BBS+ Signatures and its
//! Extensions* (Heng, Liu, Lu, Xue, Bao, Au), the paper in `refs/`. It sits next to the
//! adaptive-security construction in the parent crate and shares only its BLS12-381 backend,
//! the transcript machinery and the `bicycl` bindings.
//!
//! # What is implemented
//!
//! * [`cl`] — the CL framework at `k = 1`: `g_q` (BICYCL's `h`), the kernel generator `f` of
//!   order `q`, `CL.Solve`, and the `Encap`/`Dem` view of a CL ciphertext.
//! * [`zkp`] — `R_dlc`, `R_dls` and `R_enc` as Fiat–Shamir Σ-protocols, with the commitment
//!   recomputed by the verifier so a proof is one challenge plus its responses.
//! * [`pvss`] — Braun et al.'s Feldman-style PVSS in the class group, plus `Delta L_i(0)`.
//! * [`keygen`] — Fig. 6 (DKG of the CL KEM) and Fig. 7 (verifying key, encapsulation of the
//!   signing key).
//! * [`sign`] — Fig. 8, the three signing rounds, and the `pd_i` partial decryption that the
//!   modified scaling makes cheap.
//! * [`session`] — round drivers; [`transport`] is the in-memory bulletin board they run on.
//!
//! # Cost shape
//!
//! Per signer, per signature: two class-group elements broadcast, with the re-randomised
//! partial decryption folded into the second one (that is the CL-KEM trick), and `t + 3`
//! class-group exponentiations with long exponents: one to prove `phi_{K^{gamma_i}}`, `t - 1`
//! to verify the peers' proofs, `phi_K^{gamma_i}` and `(x^K)^{gamma_i}`, and
//! `phi_{K^gamma}^{Delta L_i sk_i}`. Measured: 5 long exponentiations at `t = 2` and 6 at
//! `t = 3`, i.e. `t + 3`. The paper's "~2t" counts the prover's and the `t - 1` verifiers'
//! work together.
//!
//! Measured by `tests/report.rs` at the paper's 1827-bit discriminant:
//!
//! ```text
//! class-group element (DGS compressed)   225 B   (paper: 219 B)
//! R_dls / R_dlc proof                    202 B
//! round 1  467 B      round 2  72 B      round 3  281 B
//! total    820 B = 0.801 KiB per signer  (paper's Table 3: 0.78 KiB)
//! ```
//!
//! The total is independent of `t`, which is the point of the construction. The 3% gap to the
//! paper is the compressed-form framing (a flags byte and four one-byte lengths) plus a
//! slightly larger `|Delta_q|` at the same `|Delta_K|`.
//!
//! # Deviations from the paper
//!
//! * `F_COM` is a hash commitment, `H(pp, sid, id, payload)`. The round-4 payload already
//!   contains fresh encapsulation randomness, so no blinding nonce is needed; what
//!   commit-and-release has to buy is unbiasedness, not hiding.
//! * The distributed setup `F_cl` is replaced by local `CL.Gen` from the fixed parameters, as
//!   in the parent crate: the class group is public and nothing in the protocol depends on who
//!   sampled it.
//! * Each party's `H_i` is derived by hash-to-curve from a fresh 32-byte seed rather than
//!   sampled uniformly from `G_1^{ell+1}`. The two distributions are indistinguishable and the
//!   derivation is reproducible.
//! * `R_dls` is proved with the witness `(gamma_i, 0)`, matching the `(prove, ..., (gamma_i,
//!   0))` call in Fig. 8. The `2^{-w_2}` generalisation of §B.3 is what makes extraction work
//!   against a biased encapsulation; it does not change the prover's messages.
//! * Proofs are Fiat–Shamir, so knowledge extraction is argued heuristically (rewinding), as
//!   the paper itself notes in Remark 4.
//! * The protocol is not robust: every signer in `T` must be online for all three rounds.
//!   `pd_i` needs the common encapsulation `phi_{K^gamma}`, which changes with `T`, so shares
//!   are not reusable across signer sets — that is the trade the paper makes for two broadcast
//!   elements per party.
//! * `bicycl::RandGen::new()` is *not* seeded (GMP's default seed is fixed), so every
//!   randomness source here goes through [`random::fresh_rng`]. Reusing a stream would hand
//!   the same `gamma_i` to every party.

pub mod bbs;
pub mod cl;
pub mod error;
pub mod keygen;
pub mod params;
pub mod pvss;
pub mod random;
pub mod session;
pub mod sign;
pub mod stats;
pub mod transport;
pub mod util;
pub mod wire;
pub mod zero;
pub mod zkp;

pub use bbs::Signature;
pub use cl::ClParameters;
pub use error::{Error, Result};
pub use keygen::{KeyPackage, KeyPublic, KeyShare};
pub use params::{Bases, PublicParameters, SetupConfig};
pub use session::{run_keygen, run_signing, KeygenOutcome, SignOutcome};
pub use stats::{Meter, Op, Stage};
