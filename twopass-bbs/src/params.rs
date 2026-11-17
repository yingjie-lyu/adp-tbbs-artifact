//! Public parameters and the randomness bounds the Σ-protocols need.
//!
//! `params = (G_1, G_2, G_T, q, e, G_1, G_2, H)` with `H = (H_0, ..., H_ell)`; `H_0` is the
//! base of the `s` component and `H_1..H_ell` are the message bases. Unlike the threshold
//! construction in the sibling crate, these bases are *not* contributed by the parties — they
//! are part of the public parameters, so `setup` derives them by hash-to-curve from fixed tags
//! (nothing-up-my-sleeve, and reproducible).
//!
//! `crs_h1` is a dedicated `G_1` generator used only by the `R_CL-Lin` commitment
//! (`M = r(x+e) G_1 + t H_1` in Fig. 4). The paper reuses `H_1` for it; a separate generator
//! costs nothing and keeps the two roles from ever being confused.

use std::sync::Arc;

use bicycl::Mpz;

use threshold_bbs::algebra::Group;
use threshold_bbs::bls381::{
    generator_g1, generator_g2, hash_to_g1, Scalar255, G1, G2, SCALAR_MODULUS_DECIMAL,
};
use threshold_bbs::hash::Transcript;
use threshold_bbs::util::{mpz_from_bytes, pow2};

use crate::cl::ClParameters;

pub const DST_BASE: &[u8] = b"twopass-bbs/v01/setup/H";
pub const DST_CRS: &[u8] = b"twopass-bbs/v01/setup/crs";

#[derive(Clone, Debug)]
pub struct SetupConfig {
    /// Number of signed messages `ell`.
    pub message_len: usize,
    /// Bit length of the CL fundamental discriminant; 1827 gives 128-bit security.
    pub delta_k_bits: usize,
    /// Computational security parameter `lambda` (challenge length).
    pub lambda: usize,
    /// Statistical parameter `lambda_s` (40 in the paper's evaluation).
    pub lambda_s: usize,
    /// Challenge length `ell_c`; the paper uses `lambda`.
    pub challenge_bits: usize,
}

impl SetupConfig {
    pub fn new(message_len: usize, delta_k_bits: usize) -> Self {
        Self {
            message_len,
            delta_k_bits,
            lambda: 128,
            lambda_s: 40,
            challenge_bits: 128,
        }
    }

    /// The paper's parameters: 1827-bit discriminant, `lambda = 128`, `lambda_s = 40`.
    pub fn production(message_len: usize) -> Self {
        Self::new(message_len, 1827)
    }
}

impl Default for SetupConfig {
    fn default() -> Self {
        Self::production(10)
    }
}

#[derive(Clone)]
pub struct PublicParameters {
    pub g1: G1,
    pub g2: G2,
    /// `H_0 .. H_ell`.
    pub bases: Vec<G1>,
    pub crs_h1: G1,
    pub cl: ClParameters,
    pub config: SetupConfig,
}

impl PublicParameters {
    pub fn setup(config: &SetupConfig) -> Arc<Self> {
        assert!(config.message_len > 0, "BBS+ needs at least one message");
        assert!(
            config.challenge_bits <= 128,
            "challenge must fit the 16-byte wire field"
        );
        let modulus = Mpz::from(SCALAR_MODULUS_DECIMAL);
        let cl = ClParameters::setup(&modulus, config.delta_k_bits, config.lambda, config.lambda_s);

        let bases = (0..=config.message_len)
            .map(|index| hash_to_g1(DST_BASE, &(index as u64).to_be_bytes()))
            .collect();
        let crs_h1 = hash_to_g1(DST_CRS, b"R_CL-Lin commitment base");

        Arc::new(Self {
            g1: generator_g1(),
            g2: generator_g2(),
            bases,
            crs_h1,
            cl,
            config: config.clone(),
        })
    }

    pub fn production(message_len: usize) -> Arc<Self> {
        Self::setup(&SetupConfig::production(message_len))
    }

    pub fn message_len(&self) -> usize {
        self.config.message_len
    }

    /// `B = G_1 + s H_0 + sum_{i=1}^{ell} m_i H_i`.
    pub fn big_b(&self, s: &Scalar255, message: &[Scalar255]) -> crate::error::Result<G1> {
        if message.len() != self.config.message_len {
            return Err(crate::error::Error::Protocol(
                "message length does not match the base vector",
            ));
        }
        let mut value = self.g1.combine(&self.bases[0].scale(s));
        for (base, scalar) in self.bases[1..].iter().zip(message) {
            value = value.combine(&base.scale(scalar));
        }
        Ok(value)
    }

    /// `ell_c`-bit challenge from a transcript digest.
    pub fn challenge(&self, transcript: &Transcript) -> Scalar255 {
        let digest = transcript.digest32();
        let bytes = (self.config.challenge_bits + 7) / 8;
        let take = bytes.min(digest.len());
        let mut window = vec![0u8; take];
        window.copy_from_slice(&digest[..take]);
        if self.config.challenge_bits % 8 != 0 && !window.is_empty() {
            let excess = 8 - self.config.challenge_bits % 8;
            window[0] &= 0xffu8 >> excess;
        }
        threshold_bbs::util::mpz_to_scalar(&mpz_from_bytes(&window))
    }

    /// Absorb the parameters into a transcript, first.
    pub fn absorb<'a>(&self, transcript: &'a mut Transcript) -> &'a mut Transcript {
        transcript
            .absorb_u64(b"ell", self.config.message_len as u64)
            .absorb_u64(b"lambda", self.config.lambda as u64)
            .absorb_u64(b"lambda_s", self.config.lambda_s as u64)
            .absorb_u64(b"delta_k_bits", self.config.delta_k_bits as u64)
            .absorb_u64(b"ell_c", self.config.challenge_bits as u64)
    }

    /// `2^{lambda + lambda_s} q`: the interval the `R_CL-Lin` responses `alpha_r`, `alpha_rx`
    /// are masked from.
    pub fn mask_bound_q(&self) -> Mpz {
        pow2(self.config.lambda + self.config.lambda_s) * Mpz::from(SCALAR_MODULUS_DECIMAL)
    }

    /// `2^{lambda + lambda_s} D_q`.
    pub fn mask_bound_dq(&self) -> Mpz {
        pow2(self.config.lambda + self.config.lambda_s) * self.cl.bound_dq().clone()
    }

    /// `(2^{lambda + lambda_s} + 2^{lambda}) q`: the honest response bound.
    ///
    /// The paper's Fig. 4 states the tighter `[0, 2^{lambda+lambda_s} q]`, which an honest
    /// prover can exceed by `ch * r <= 2^{lambda} q`. The gap does not affect soundness — the
    /// response is still bounded by `~2^{lambda+lambda_s} q` — but using the paper's interval
    /// verbatim would reject honest proofs.
    pub fn response_bound_q(&self) -> Mpz {
        (pow2(self.config.lambda + self.config.lambda_s) + pow2(self.config.lambda))
            * Mpz::from(SCALAR_MODULUS_DECIMAL)
    }

    /// `(2^{lambda + lambda_s} + 2^{lambda}) D_q`.
    pub fn response_bound_dq(&self) -> Mpz {
        (pow2(self.config.lambda + self.config.lambda_s) + pow2(self.config.lambda))
            * self.cl.bound_dq().clone()
    }
}
