//! BLS12-381 backend.
//!
//! `G1` is the paper's `G_1` and `G2` is `G_2`. Scalar encodings are canonical and
//! big-endian at this boundary (the underlying crate stores little-endian), which keeps
//! transcripts and Fiat–Shamir challenges unambiguous.

use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Gt, Scalar as BlsScalar};
use ff::Field;

use rand_core::OsRng;
use sha2::Sha256;

use crate::algebra::{Encodable, Group, PairingGroup, Scalar};

/// The order `q` of the scalar field, as a decimal string (BLS12-381 `r`).
pub const SCALAR_MODULUS_DECIMAL: &str =
    "52435875175126190479447740508185965837690552500527637822603658699938581184513";

/// The scalar field of BLS12-381, order `q` (255 bits).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Scalar255(pub BlsScalar);

impl Scalar255 {
    pub fn random(rng: &mut impl rand_core::RngCore) -> Self {
        Self(BlsScalar::random(rng))
    }

    pub fn inner(&self) -> BlsScalar {
        self.0
    }

    /// Interpret a big-endian byte string as an integer and reduce it modulo `q`.
    ///
    /// `from_bytes_wide` reads its 64-byte input as **little-endian**, so each big-endian
    /// chunk is reversed into a zeroed buffer before reduction. Getting this backwards is
    /// silent: it only shows up when an input is not exactly 32 bytes long, which is why
    /// the 128-bit Fiat–Shamir challenge is the case that catches it.
    pub fn from_be_bytes_mod_order(bytes: &[u8]) -> Self {
        let mut acc = BlsScalar::ZERO;
        for chunk in bytes.chunks(32) {
            let mut little = [0u8; 64];
            for (index, byte) in chunk.iter().rev().enumerate() {
                little[index] = *byte;
            }
            let value = BlsScalar::from_bytes_wide(&little);

            // acc = acc * 256^chunk.len() + value.
            let mut shift = [0u8; 64];
            shift[chunk.len()] = 1;
            let scale = BlsScalar::from_bytes_wide(&shift);

            acc = acc * scale + value;
        }
        Self(acc)
    }
}

impl Scalar for Scalar255 {
    fn zero() -> Self {
        Self(BlsScalar::ZERO)
    }
    fn one() -> Self {
        Self(BlsScalar::ONE)
    }
    fn add(&self, rhs: &Self) -> Self {
        Self(self.0 + rhs.0)
    }
    fn sub(&self, rhs: &Self) -> Self {
        Self(self.0 - rhs.0)
    }
    fn mul(&self, rhs: &Self) -> Self {
        Self(self.0 * rhs.0)
    }
    fn invert(&self) -> Option<Self> {
        Option::<BlsScalar>::from(self.0.invert()).map(Self)
    }
    fn from_u64(value: u64) -> Self {
        Self(BlsScalar::from(value))
    }
    fn from_be_bytes_mod_order(bytes: &[u8]) -> Self {
        Scalar255::from_be_bytes_mod_order(bytes)
    }
    fn to_be_bytes(&self) -> Vec<u8> {
        let mut bytes = self.0.to_bytes();
        bytes.reverse();
        bytes.to_vec()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct G1(pub G1Projective);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct G2(pub G2Projective);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Target(pub Gt);

impl Group for G1 {
    type Scalar = Scalar255;
    fn identity() -> Self {
        Self(G1Projective::identity())
    }
    fn combine(&self, rhs: &Self) -> Self {
        Self(self.0 + rhs.0)
    }
    fn inverse(&self) -> Self {
        Self(-self.0)
    }
    fn scale(&self, exponent: &Self::Scalar) -> Self {
        Self(self.0 * exponent.0)
    }
}

impl Encodable for G1 {
    fn to_bytes(&self) -> Vec<u8> {
        G1Affine::from(self.0).to_compressed().to_vec()
    }
}

impl Group for G2 {
    type Scalar = Scalar255;
    fn identity() -> Self {
        Self(G2Projective::identity())
    }
    fn combine(&self, rhs: &Self) -> Self {
        Self(self.0 + rhs.0)
    }
    fn inverse(&self) -> Self {
        Self(-self.0)
    }
    fn scale(&self, exponent: &Self::Scalar) -> Self {
        Self(self.0 * exponent.0)
    }
}

impl Encodable for G2 {
    fn to_bytes(&self) -> Vec<u8> {
        G2Affine::from(self.0).to_compressed().to_vec()
    }
}

impl Group for Target {
    type Scalar = Scalar255;
    fn identity() -> Self {
        Self(Gt::identity())
    }
    fn combine(&self, rhs: &Self) -> Self {
        Self(self.0 + rhs.0)
    }
    fn inverse(&self) -> Self {
        Self(-self.0)
    }
    fn scale(&self, exponent: &Self::Scalar) -> Self {
        Self(self.0 * exponent.0)
    }
}

impl PairingGroup for G1 {
    type G2 = G2;
    type Target = Target;
    fn pairing(g2: &G2, g1: &G1) -> Target {
        Target(pairing(&G1Affine::from(g1.0), &G2Affine::from(g2.0)))
    }
}

pub fn generator_g1() -> G1 {
    G1(G1Projective::generator())
}

pub fn generator_g2() -> G2 {
    G2(G2Projective::generator())
}

/// Hash-to-curve into `G_1` with an explicit domain separation tag.
pub fn hash_to_g1(domain: &[u8], message: &[u8]) -> G1 {
    G1(<G1Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(message, domain))
}

/// Hash-to-curve into `G_2`.
pub fn hash_to_g2(domain: &[u8], message: &[u8]) -> G2 {
    G2(<G2Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(message, domain))
}

/// Sample a scalar uniformly at random from the OS RNG.
pub fn random_scalar() -> Scalar255 {
    Scalar255(BlsScalar::random(&mut OsRng))
}
