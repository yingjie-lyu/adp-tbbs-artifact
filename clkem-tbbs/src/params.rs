//! Public parameters and the BBS+ base vector.
//!
//! `pp = (G, lambda, lambda_d, ell, pp_cl)`: the BLS12-381 group, the security parameters,
//! the message length, and the CL framework. The BBS+ bases `H = (H_1, ..., H_{ell+1})` are
//! **not** part of the setup — paper Fig. 7 has every party contribute `H_i` and publishes
//! `H = sum_i H_i` as part of the verifying key, so they live in [`Bases`] and are aggregated
//! during key generation.
//!
//! [`Bases::derive`] exists for the single-signer reference implementation and for negative
//! tests; it hash-derives the vector from a seed instead of sampling it, which is the
//! standard nothing-up-my-sleeve construction and keeps fixtures reproducible.

use std::sync::Arc;

use bicycl::Mpz;

use threshold_bbs::algebra::Group;
use threshold_bbs::bls381::{
    generator_g1, generator_g2, hash_to_g1, Scalar255, G1, G2, SCALAR_MODULUS_DECIMAL,
};
use threshold_bbs::hash::Transcript;
use threshold_bbs::util::mpz_from_bytes;

use crate::cl::ClParameters;
use crate::stats::Meter;

pub const DST_SETUP_H1: &[u8] = b"clkem-tbbs/v01/setup/H1";
pub const DST_SETUP_MESSAGE: &[u8] = b"clkem-tbbs/v01/setup/message-base";
/// Random G_1 bases contributed by one party in key generation.
pub const DST_KEYGEN_BASE: &[u8] = b"clkem-tbbs/v01/keygen/bases";

#[derive(Clone, Debug)]
pub struct SetupConfig {
    /// Number of signed messages `ell`.
    pub message_len: usize,
    /// Bit length of the fundamental discriminant; 1827 gives 128-bit security.
    pub delta_k_bits: usize,
    /// Computational security parameter `lambda`.
    pub lambda: usize,
    /// Statistical security parameter `lambda_d`.
    pub lambda_d: usize,
    /// Challenge length `ell_c`.
    pub challenge_bits: usize,
}

impl SetupConfig {
    pub fn new(message_len: usize, delta_k_bits: usize) -> Self {
        Self {
            message_len,
            delta_k_bits,
            lambda: 128,
            lambda_d: 80,
            challenge_bits: 128,
        }
    }

    /// The paper's parameters: `log2|Delta_K| = 1827`, `lambda = 128`, `lambda_d = 80`.
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
        let cl = ClParameters::setup(
            &modulus,
            config.delta_k_bits,
            config.lambda,
            config.lambda_d,
        );
        Arc::new(Self {
            g1: generator_g1(),
            g2: generator_g2(),
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

    /// `ell_c`-bit challenge drawn from a transcript digest.
    pub fn challenge(&self, transcript: &Transcript) -> Mpz {
        let digest = transcript.digest32();
        let bytes = (self.config.challenge_bits + 7) / 8;
        let take = bytes.min(digest.len());
        let mut window = vec![0u8; take];
        window.copy_from_slice(&digest[..take]);
        if self.config.challenge_bits % 8 != 0 && !window.is_empty() {
            let excess = 8 - self.config.challenge_bits % 8;
            window[0] &= 0xffu8 >> excess;
        }
        mpz_from_bytes(&window)
    }

    /// Canonical encoding of the parameters, absorbed first by every transcript.
    pub fn absorb<'a>(&self, transcript: &'a mut Transcript) -> &'a mut Transcript {
        transcript
            .absorb_u64(b"ell", self.config.message_len as u64)
            .absorb_u64(b"lambda", self.config.lambda as u64)
            .absorb_u64(b"lambda_d", self.config.lambda_d as u64)
            .absorb_u64(b"delta_k_bits", self.config.delta_k_bits as u64)
            .absorb_u64(b"ell_c", self.config.challenge_bits as u64);
        transcript
    }
}

/// The BBS+ base vector `(H_1, H_2, ..., H_{ell+1})`; `h1` is the base of the `s` component.
#[derive(Clone, Debug)]
pub struct Bases {
    pub h1: G1,
    pub message: Vec<G1>,
}

impl Bases {
    /// Hash-derive a full vector from a seed. Used by the reference signer and by tests.
    pub fn derive(pp: &PublicParameters, seed: &[u8]) -> Self {
        let mut h1_seed = seed.to_vec();
        h1_seed.extend_from_slice(&u64::MAX.to_be_bytes());
        let h1 = hash_to_g1(DST_SETUP_H1, &h1_seed);
        let message = (0..pp.config.message_len)
            .map(|index| {
                let mut buffer = seed.to_vec();
                buffer.extend_from_slice(&(index as u64).to_be_bytes());
                hash_to_g1(DST_SETUP_MESSAGE, &buffer)
            })
            .collect();
        Self { h1, message }
    }

    pub fn zero(pp: &PublicParameters) -> Self {
        Self {
            h1: G1::identity(),
            message: vec![G1::identity(); pp.config.message_len],
        }
    }

    pub fn add(&self, other: &Self, _meter: &mut Meter) -> Self {
        assert_eq!(self.message.len(), other.message.len(), "base vector length");
        Self {
            h1: self.h1.combine(&other.h1),
            message: self
                .message
                .iter()
                .zip(&other.message)
                .map(|(lhs, rhs)| lhs.combine(rhs))
                .collect(),
        }
    }

    /// `B = G_1 + s * H_1 + sum_k m_k H_{k+1}`.
    pub fn big_b(&self, pp: &PublicParameters, s: &Scalar255, message: &[Scalar255]) -> G1 {
        assert_eq!(message.len(), self.message.len(), "message length");
        let mut value = pp.g1.combine(&self.h1.scale(s));
        for (base, scalar) in self.message.iter().zip(message) {
            value = value.combine(&base.scale(scalar));
        }
        value
    }

    /// Serialised size of the vector, for the report.
    pub fn encoded_len(&self) -> usize {
        (1 + self.message.len()) * 48
    }
}
