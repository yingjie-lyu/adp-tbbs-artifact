//! The Σ-protocol for the presigning relation.
//!
//! Statement: `(i, sid, msg, Q, Y_i, W_i, pe_{gamma,i}, Gamma_i)`, witness
//! `(v_i, s~_i, gamma_i, rho_i, r_{gamma,i})` with
//!
//! ```text
//! Y_i     = g_1^{v_i} h_1^{s~_i}
//! W_i     = B_1^{v_i} B_2^{s~_i}
//! Gamma_i = g_1^{gamma_i} hh^{rho_i}
//! c0_i    = g_z^{r}
//! c1_i    = f^{gamma_i} g_o^{r}
//! ```
//!
//! Compiled with Fiat–Shamir the proof is `(c, z)` and the verifier rebuilds the five
//! commitments from the responses. That only works if rebuilding is byte-identical to what
//! the prover committed to, so [`FirstMessage`] is exposed and both directions go through
//! [`challenge_from`]; `tests/sigma.rs` asserts the byte identity directly.
//!
//! The single integer challenge `c < 2^{ell_c}` multiplies `r_{gamma,i}` over the integers
//! and every other witness coordinate modulo `q`, exactly as in the paper.

use bicycl::{Mpz, RandGen, QFI};

use crate::algebra::{Group, Operation, Scalar};
use crate::bls381::{Scalar255, G1};
use crate::hash::Transcript;
use crate::params::PublicParameters;
use crate::util::{mpz_lt, mpz_to_scalar, pow2, scalar_to_mpz};

/// The presigning statement.
#[derive(Clone, Debug)]
pub struct Statement {
    pub id: usize,
    pub session: Vec<u8>,
    pub message: Vec<u8>,
    pub quorum: Vec<usize>,
    /// `B_1 = hashvrf(sid, msg, Q).0`
    pub base_1: G1,
    /// `B_2 = hashvrf(sid, msg, Q).1`
    pub base_2: G1,
    /// `Y_i`
    pub vrf_commitment: G1,
    /// `W_i`
    pub vrf_share: G1,
    /// `Gamma_i = g_1^{gamma_i} hh^{rho_i}`
    pub gamma_commitment: G1,
    pub c0: QFI,
    pub c1: QFI,
}

impl Statement {
    fn transcript(&self, pp: &PublicParameters) -> Transcript {
        let mut transcript = Transcript::new(b"threshold-bbs/v03/sigma/statement");
        transcript
            .absorb_u64(b"id", self.id as u64)
            .absorb_bytes(b"sid", &self.session)
            .absorb_bytes(b"msg", &self.message)
            .absorb_quorum(&self.quorum)
            .absorb_g1(b"B1", &self.base_1)
            .absorb_g1(b"B2", &self.base_2)
            .absorb_g1(b"Y", &self.vrf_commitment)
            .absorb_g1(b"W", &self.vrf_share)
            .absorb_g1(b"Gamma", &self.gamma_commitment)
            .absorb_qfi(b"c0", &self.c0)
            .absorb_qfi(b"c1", &self.c1)
            .absorb_g1(b"g1", &pp.g1)
            .absorb_g1(b"h1", &pp.h1)
            .absorb_g1(b"hh", &pp.hh);
        transcript
    }
}

#[derive(Clone, Debug)]
pub struct Witness {
    pub v_i: Scalar255,
    pub s_tilde_i: Scalar255,
    pub gamma_i: Scalar255,
    pub rho_i: Scalar255,
    /// Role-B coins `r_{gamma,i} in [0, N_B)`.
    pub randomness_gamma: Mpz,
}

/// The five commitments of the first message.
///
/// In the Fiat–Shamir compilation this is not transmitted: the verifier recomputes it from
/// `(c, z)` via [`recompute_first`].
#[derive(Clone)]
pub struct FirstMessage {
    pub t_y: G1,
    pub t_w: G1,
    pub t_gamma: G1,
    pub t_0: QFI,
    pub t_1: QFI,
}

#[derive(Clone, Debug)]
pub struct Proof {
    /// Integer challenge in `[0, 2^{ell_c})`.
    pub challenge: Mpz,
    pub z_v: Scalar255,
    pub z_s: Scalar255,
    pub z_gamma: Scalar255,
    pub z_rho: Scalar255,
    /// Integer response `t_r + c * r_{gamma,i}`, kept unreduced.
    pub z_r: Mpz,
}

impl Proof {
    /// `ell_c + 4*256 + (kappa_Z + ell_c + log2 N_B + 1)` bits, the paper's ~296 bytes.
    pub fn encoded_len(&self, pp: &PublicParameters) -> usize {
        let challenge_bytes = (pp.challenge_bits + 7) / 8;
        challenge_bytes + 4 * 32 + crate::util::mpz_bytes(&self.z_r).len()
    }
}

/// Whether the `z_r` exponent counts as a long class-group exponentiation: 1211 bits with
/// full role-B coins, 465 with short ones, so only the full variant is "long".
fn long_exp(pp: &PublicParameters) -> bool {
    !matches!(pp.nim.variant(), crate::nim::NimVariant::SingleBaseShort)
}

/// `N~_B = 2^{kappa_Z} * K * N_B`, the mask interval for `t_r`.
pub fn mask_bound(pp: &PublicParameters) -> Mpz {
    pow2(pp.kappa_stat) * pow2(pp.challenge_bits) * pp.nim.bound_b().clone()
}

/// One class-group exponentiation, counted long when the exponent exceeds ~900 bits.
///
/// Powers of the kernel generator `cgf` are *not* routed through here: they have a closed
/// form and the paper's cost model does not count them.
fn class_exp(
    pp: &PublicParameters,
    base: &QFI,
    exponent: &Mpz,
    long: bool,
    stats: &mut crate::Breakdown,
) -> QFI {
    let op = if long {
        Operation::ClassGroupExponentiationLong
    } else {
        Operation::ClassGroupExponentiationShort
    };
    crate::algebra::measure(stats, op, || base.exp(pp.nim.group(), exponent))
}

/// One two-base multi-exponentiation in `G_1`.
fn measure_g1<T>(stats: &mut crate::Breakdown, f: impl FnOnce() -> T) -> T {
    crate::algebra::measure(stats, Operation::G1Exponentiation, f)
}

pub fn challenge_from(pp: &PublicParameters, statement: &Statement, first: &FirstMessage) -> Mpz {
    let mut transcript = statement.transcript(pp);
    transcript
        .absorb_g1(b"T_Y", &first.t_y)
        .absorb_g1(b"T_W", &first.t_w)
        .absorb_g1(b"T_Gamma", &first.t_gamma)
        .absorb_qfi(b"T_0", &first.t_0)
        .absorb_qfi(b"T_1", &first.t_1);
    pp.challenge_integer(&transcript.digest32())
}

/// Prover's first move. Exposed for the byte-identity regression test.
pub fn commit(
    pp: &PublicParameters,
    statement: &Statement,
    stats: &mut crate::Breakdown,
) -> (FirstMessage, Nonces) {
    let mut rng = rand_core::OsRng;
    let nonces = Nonces {
        t_v: Scalar255::random(&mut rng),
        t_s: Scalar255::random(&mut rng),
        t_gamma: Scalar255::random(&mut rng),
        t_rho: Scalar255::random(&mut rng),
        t_r: RandGen::new().random_mpz(&mask_bound(pp)),
    };

    let group = pp.nim.group();
    let first = FirstMessage {
        t_y: measure_g1(stats, || {
            pp.g1.scale(&nonces.t_v).combine(&pp.h1.scale(&nonces.t_s))
        }),
        t_w: measure_g1(stats, || {
            statement
                .base_1
                .scale(&nonces.t_v)
                .combine(&statement.base_2.scale(&nonces.t_s))
        }),
        t_gamma: measure_g1(stats, || {
            pp.g1
                .scale(&nonces.t_gamma)
                .combine(&pp.hh.scale(&nonces.t_rho))
        }),
        t_0: if pp.nim.variant().is_single_base() {
            // `T_c = f^{lift(t_gamma)} g^{t_r}`: one class-group element, not two.
            pp.nim
                .f()
                .exp(group, &scalar_to_mpz(&nonces.t_gamma))
                .compose(
                    group,
                    &class_exp(pp, pp.nim.g_z(), &nonces.t_r, long_exp(pp), stats),
                )
        } else {
            class_exp(pp, pp.nim.g_z(), &nonces.t_r, true, stats)
        },
        t_1: if pp.nim.variant().is_single_base() {
            pp.nim.identity().clone()
        } else {
            pp.nim
                .f()
                .exp(group, &scalar_to_mpz(&nonces.t_gamma))
                .compose(
                    group,
                    &class_exp(pp, pp.nim.g_o(), &nonces.t_r, true, stats),
                )
        },
    };
    (first, nonces)
}

/// Private prover state between the two moves.
#[derive(Clone)]
pub struct Nonces {
    pub t_v: Scalar255,
    pub t_s: Scalar255,
    pub t_gamma: Scalar255,
    pub t_rho: Scalar255,
    pub t_r: Mpz,
}

/// Prover's second move, given the challenge recomputed from the first move.
pub fn respond(witness: &Witness, nonces: &Nonces, challenge: &Mpz) -> Proof {
    let c = mpz_to_scalar(challenge);
    Proof {
        z_v: nonces.t_v.add(&c.mul(&witness.v_i)),
        z_s: nonces.t_s.add(&c.mul(&witness.s_tilde_i)),
        z_gamma: nonces.t_gamma.add(&c.mul(&witness.gamma_i)),
        z_rho: nonces.t_rho.add(&c.mul(&witness.rho_i)),
        z_r: nonces.t_r.clone() + challenge.clone() * witness.randomness_gamma.clone(),
        challenge: challenge.clone(),
    }
}

pub fn prove(
    pp: &PublicParameters,
    statement: &Statement,
    witness: &Witness,
    stats: &mut crate::Breakdown,
) -> Proof {
    let (first, nonces) = commit(pp, statement, stats);
    let challenge = challenge_from(pp, statement, &first);
    respond(witness, &nonces, &challenge)
}

/// Rebuild the first message from `(c, z)`, as the verifier must.
pub fn recompute_first(
    pp: &PublicParameters,
    statement: &Statement,
    proof: &Proof,
    stats: &mut crate::Breakdown,
) -> FirstMessage {
    let c = mpz_to_scalar(&proof.challenge);
    let minus_c = Scalar255::zero().sub(&c);
    let negative_challenge = Mpz::from(0u64) - proof.challenge.clone();
    let group = pp.nim.group();

    let t_y = measure_g1(stats, || {
        pp.g1
            .scale(&proof.z_v)
            .combine(&pp.h1.scale(&proof.z_s))
            .combine(&statement.vrf_commitment.scale(&minus_c))
    });
    let t_w = measure_g1(stats, || {
        statement
            .base_1
            .scale(&proof.z_v)
            .combine(&statement.base_2.scale(&proof.z_s))
            .combine(&statement.vrf_share.scale(&minus_c))
    });
    let t_gamma = measure_g1(stats, || {
        pp.g1
            .scale(&proof.z_gamma)
            .combine(&pp.hh.scale(&proof.z_rho))
            .combine(&statement.gamma_commitment.scale(&minus_c))
    });
    let (t_0, t_1) = if pp.nim.variant().is_single_base() {
        let t_c = pp
            .nim
            .f()
            .exp(group, &scalar_to_mpz(&proof.z_gamma))
            .compose(
                group,
                &class_exp(pp, pp.nim.g_z(), &proof.z_r, long_exp(pp), stats),
            )
            .compose(
                group,
                &class_exp(pp, &statement.c0, &negative_challenge, false, stats),
            );
        (t_c, pp.nim.identity().clone())
    } else {
        let t_0 = class_exp(pp, pp.nim.g_z(), &proof.z_r, true, stats).compose(
            group,
            &class_exp(pp, &statement.c0, &negative_challenge, false, stats),
        );
        let t_1 = pp
            .nim
            .f()
            .exp(group, &scalar_to_mpz(&proof.z_gamma))
            .compose(group, &class_exp(pp, pp.nim.g_o(), &proof.z_r, true, stats))
            .compose(
                group,
                &class_exp(pp, &statement.c1, &negative_challenge, false, stats),
            );
        (t_0, t_1)
    };

    FirstMessage {
        t_y,
        t_w,
        t_gamma,
        t_0,
        t_1,
    }
}

pub fn verify(
    pp: &PublicParameters,
    statement: &Statement,
    proof: &Proof,
    stats: &mut crate::Breakdown,
) -> bool {
    // Both class-group elements must be forms of the right discriminant before they are
    // handed to the backend, which aborts (rather than returning an error) on garbage.
    if !pp.nim.is_form_of(&statement.c0) {
        return false;
    }
    if !pp.nim.variant().is_single_base() && !pp.nim.is_form_of(&statement.c1) {
        return false;
    }

    let challenge_bound = pow2(pp.challenge_bits);
    if !mpz_lt(&proof.challenge, &challenge_bound) {
        return false;
    }
    // |z_r| < N~_B + K*N_B: the honest response range, widened by the challenge times the
    // largest honest coin so that a cheating prover cannot shift the mask interval.
    let response_bound = mask_bound(pp) + challenge_bound * pp.nim.bound_b().clone();
    if !mpz_lt(&proof.z_r, &response_bound) {
        return false;
    }

    let recomputed = recompute_first(pp, statement, proof, stats);
    challenge_from(pp, statement, &recomputed) == proof.challenge
}
