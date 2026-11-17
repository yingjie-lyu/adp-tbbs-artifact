//! `setup` and the public parameters `TS.pp`.
//!
//! The paper's setup is
//! `(pp_bbs, h_2, h_1, hh, crs, pp_nizk, hashvrf, hashout, hashu, hashS)`.
//! `pp_bbs` is folded into the BBS+ bases here, `crs` is the class-group NIM CRS, and the
//! four random oracles are the domain-separated functions in [`crate::hash`].
//!
//! `h_0, h_1, hh ∈ G_1` and `h_2 ∈ G_2` are derived with hash-to-curve from fixed tags
//! rather than sampled, which is the standard way to get a nothing-up-my-sleeve generator
//! and keeps the setup reproducible.

use bicycl::Mpz;

use crate::algebra::{Group, Scalar};
use crate::bls381::{
    generator_g1, generator_g2, hash_to_g1, hash_to_g2, Scalar255, G1, G2, SCALAR_MODULUS_DECIMAL,
};
use crate::hash::{DST_MESSAGE_BASE, DST_SETUP_H0, DST_SETUP_H1, DST_SETUP_H2, DST_SETUP_HH};
use crate::nim::{NimParameters, NimVariant};

#[derive(Clone, Debug)]
pub struct SetupConfig {
    /// Number of signed messages `k` in BBS+.
    pub message_len: usize,
    /// Bit length of the fundamental discriminant `Delta_K`; 1827 gives 128-bit security.
    pub delta_k_bits: usize,
    /// `log2 B` for the class-number bound; about `delta_k_bits / 2 + 9`.
    pub s_bound_bits: usize,
    /// Statistical security parameter `kappa` (80 in the paper).
    pub kappa_stat: usize,
    /// Challenge length `ell_c` in bits (128 with Fiat–Shamir).
    pub challenge_bits: usize,
    /// Which NIM instantiation the CRS implements (Appendix `sec:sb` variants included).
    pub nim_variant: NimVariant,
}

impl SetupConfig {
    pub fn new(message_len: usize, delta_k_bits: usize) -> Self {
        Self {
            message_len,
            delta_k_bits,
            // log2 B for B = ceil(pi^-1 * log|Delta_K| * |Delta_K|^{1/2}), which is 922 for
            // the paper's 1827-bit discriminant. Raise it by one bit for extra margin: the
            // bound only needs to upper-bound the odd part of the class number.
            s_bound_bits: delta_k_bits / 2 + 9,
            kappa_stat: 80,
            challenge_bits: 128,
            nim_variant: NimVariant::TwoBase,
        }
    }

    /// The same parameters with the single-base NIM of Appendix `sec:sb`.
    pub fn single_base(message_len: usize, short_coins: bool) -> Self {
        let mut config = Self::production(message_len);
        config.nim_variant = if short_coins {
            NimVariant::SingleBaseShort
        } else {
            NimVariant::SingleBase
        };
        config
    }

    /// The paper's parameters: `log2|Delta_K| = 1827`, `kappa = 80`, `ell_c = 128`.
    pub fn production(message_len: usize) -> Self {
        Self::new(message_len, 1827)
    }
}

impl Default for SetupConfig {
    fn default() -> Self {
        Self::production(10)
    }
}

/// `TS.pp`: the public parameters of the scheme.
#[derive(Clone)]
pub struct PublicParameters {
    pub g1: G1,
    pub g2: G2,
    pub h0: G1,
    pub h1: G1,
    pub hh: G1,
    pub h2: G2,
    pub message_bases: Vec<G1>,
    pub nim: NimParameters,
    pub challenge_bits: usize,
    pub kappa_stat: usize,
}

impl PublicParameters {
    pub fn setup(config: &SetupConfig) -> Self {
        Self::setup_with_stats(config, &mut crate::Breakdown::default())
    }

    /// `setup` that records its cost into `stats`.
    pub fn setup_with_stats(config: &SetupConfig, stats: &mut crate::Breakdown) -> Self {
        stats.step(crate::algebra::Phase::Setup, |_| Self::setup_inner(config))
    }

    fn setup_inner(config: &SetupConfig) -> Self {
        assert!(config.message_len > 0, "BBS+ needs at least one message");
        assert!(
            config.challenge_bits <= 128,
            "challenge must stay invertible mod q"
        );

        let g1 = generator_g1();
        let g2 = generator_g2();
        let h0 = hash_to_g1(DST_SETUP_H0, b"h0");
        let h1 = hash_to_g1(DST_SETUP_H1, b"h1");
        let hh = hash_to_g1(DST_SETUP_HH, b"hh");
        let h2 = hash_to_g2(DST_SETUP_H2, b"h2");

        let message_bases = (0..config.message_len)
            .map(|index| hash_to_g1(DST_MESSAGE_BASE, &(index as u64).to_be_bytes()))
            .collect();

        let modulus = Mpz::from(SCALAR_MODULUS_DECIMAL);
        let nim = match config.nim_variant {
            NimVariant::TwoBase => NimParameters::setup(
                modulus,
                config.delta_k_bits,
                config.s_bound_bits,
                config.kappa_stat,
            ),
            variant => NimParameters::setup_single_base(
                modulus,
                config.delta_k_bits,
                config.s_bound_bits,
                config.kappa_stat,
                matches!(variant, NimVariant::SingleBaseShort),
                128,
            ),
        };

        Self {
            g1,
            g2,
            h0,
            h1,
            hh,
            h2,
            message_bases,
            nim,
            challenge_bits: config.challenge_bits,
            kappa_stat: config.kappa_stat,
        }
    }

    /// Convenience: production parameters for a given message length.
    pub fn production(message_len: usize) -> Self {
        Self::setup(&SetupConfig::production(message_len))
    }

    /// Canonical byte encoding of the message vector, used inside every transcript.
    pub fn encode_message(&self, message: &[Scalar255]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(message.len() * 32);
        for value in message {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        bytes
    }

    /// `U = g_1 * h_0^phi * prod_k h_k^{m_k}`.
    pub fn compute_u(&self, phi: &Scalar255, message: &[Scalar255]) -> G1 {
        let mut u = self.g1.combine(&self.h0.scale(phi));
        for (base, value) in self.message_bases.iter().zip(message) {
            u = u.combine(&base.scale(value));
        }
        u
    }

    /// The BBS+ public key lives in `G_2`; this projects a scalar secret for tests.
    pub fn public_key_for(&self, secret: &Scalar255) -> G2 {
        self.g2.scale(secret)
    }

    /// Extract the `k`-bit integer challenge from a digest, as `Z_q` and as an integer.
    pub fn challenge_integer(&self, digest: &[u8]) -> Mpz {
        let bytes = (self.challenge_bits + 7) / 8;
        let take = bytes.min(digest.len());
        let mut window = vec![0u8; take];
        window.copy_from_slice(&digest[..take]);
        if self.challenge_bits % 8 != 0 && !window.is_empty() {
            let excess = 8 - self.challenge_bits % 8;
            window[0] &= 0xffu8 >> excess;
        }
        crate::util::mpz_from_bytes(&window)
    }

    pub fn zero_scalar(&self) -> Scalar255 {
        <Scalar255 as Scalar>::zero()
    }
}
