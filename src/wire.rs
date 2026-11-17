//! Canonical wire format.
//!
//! Everything that crosses a party boundary is encoded here, and decoding is strict: fixed
//! widths where the size is implied by the setup, length-prefixed integers where it is not,
//! trailing bytes rejected. Two design points matter:
//!
//! * **Class-group forms use the Dobson–Galbraith–Smith compressed representation**
//!   (eprint 2020/196, algorithms 2 and 3) through BICYCL's `compressed_repr`. Four small
//!   integers plus a sign bit take about `3/4 log2|Delta|` bits: 222 bytes at the paper's
//!   parameters instead of 438 for the raw `(a, b, c)`.
//! * **Decoding is canonical.** The decoder recompresses the recovered form and requires the
//!   bytes to match what it received, so a second encoding of the same element is rejected
//!   rather than silently accepted into a transcript.
//!
//! Decoding never panics: a malformed point, an out-of-range length, or a bogus form all
//! return [`Error::Wire`].

use bicycl::{Mpz, QFI};
use bls12_381::{G1Affine, G2Affine};

use crate::algebra::{Encodable, Scalar};

use crate::bbs::Signature;
use crate::bls381::{Scalar255, G1, G2};
use crate::error::{Error, Result};
use crate::nim::NimParameters;
use crate::round1::Round1Message;
use crate::round2::Round2Message;
use crate::sigma::Proof;
use crate::util::{mpz_bits, mpz_bytes, mpz_from_bytes, mpz_neg, mpz_sign};

/// A cursor over a received byte string.
pub struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.position)
    }

    /// Reject trailing bytes: a longer message than the schema allows is a protocol error,
    /// not something to ignore.
    pub fn finish(&self) -> Result<()> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(Error::Wire("trailing bytes"))
        }
    }

    pub fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(len)
            .ok_or(Error::Wire("length overflow"))?;
        if end > self.bytes.len() {
            return Err(Error::Wire("truncated message"));
        }
        let slice = &self.bytes[self.position..end];
        self.position = end;
        Ok(slice)
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub fn u16(&mut self) -> Result<usize> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]) as usize)
    }

    pub fn u64(&mut self) -> Result<u64> {
        let bytes = self.take(8)?;
        let mut value = [0u8; 8];
        value.copy_from_slice(bytes);
        Ok(u64::from_be_bytes(value))
    }

    pub fn usize_id(&mut self) -> Result<usize> {
        let value = self.u64()?;
        usize::try_from(value).map_err(|_| Error::Wire("identifier out of range"))
    }

    pub fn bytes_prefixed(&mut self) -> Result<&'a [u8]> {
        let len = self.u16()?;
        self.take(len)
    }

    pub fn scalar(&mut self) -> Result<Scalar255> {
        let bytes = self.take(32)?;
        Ok(Scalar255::from_be_bytes_mod_order(bytes))
    }

    pub fn g1(&mut self) -> Result<G1> {
        let bytes = self.take(48)?;
        let mut compressed = [0u8; 48];
        compressed.copy_from_slice(bytes);
        Option::<G1Affine>::from(G1Affine::from_compressed(&compressed))
            .map(|point| G1(bls12_381::G1Projective::from(point)))
            .ok_or(Error::Wire("invalid G_1 point"))
    }

    pub fn g2(&mut self) -> Result<G2> {
        let bytes = self.take(96)?;
        let mut compressed = [0u8; 96];
        compressed.copy_from_slice(bytes);
        Option::<G2Affine>::from(G2Affine::from_compressed(&compressed))
            .map(|point| G2(bls12_381::G2Projective::from(point)))
            .ok_or(Error::Wire("invalid G_2 point"))
    }

    /// A non-negative integer as `u16` length + big-endian magnitude.
    pub fn mpz(&mut self) -> Result<Mpz> {
        Ok(mpz_from_bytes(self.bytes_prefixed()?))
    }

    /// A class-group form in DGS compressed form.
    pub fn qfi(&mut self, nim: &NimParameters) -> Result<QFI> {
        let start = self.position;
        let flags = self.u8()?;
        if flags >= 32 {
            return Err(Error::Wire("invalid compressed-form flags"));
        }
        let signed = |magnitude: Mpz, bit: u8| {
            if flags & bit == 0 {
                magnitude
            } else {
                mpz_neg(&magnitude)
            }
        };
        let ap = signed(self.short_mpz()?, 1);
        let g = signed(self.short_mpz()?, 2);
        let tp = signed(self.short_mpz()?, 4);
        let b0 = signed(self.short_mpz()?, 8);
        let is_neg = flags & 16 != 0;

        // Guard the backend: decompression divides by these, and BICYCL's C++ aborts (SIGSEGV
        // rather than a Rust panic) on degenerate input. The special cases mirror
        // `compressed_repr`: the principal form has `(a, 0, 0, 0)` and the `a == b` form has
        // `(1, a, 0, 0)`; everything else needs `ap`, `g` non-zero.
        if mpz_bits(&ap) == 0 || mpz_sign(&ap) < 0 || mpz_sign(&g) < 0 || mpz_sign(&b0) < 0 {
            return Err(Error::Wire("compressed form has an out-of-range component"));
        }
        let degenerate = mpz_bits(&g) == 0 || mpz_bits(&tp) == 0;
        if degenerate && !(mpz_bits(&tp) == 0 && mpz_bits(&b0) == 0 && !is_neg) {
            return Err(Error::Wire(
                "compressed form has an inconsistent zero component",
            ));
        }

        let form = QFI::from_compressed(
            &bicycl::CompressedForm {
                ap,
                g,
                tp,
                b0,
                is_neg,
            },
            &nim.group().discriminant(),
        );
        // Decompressing arbitrary integers does not throw; it just yields a non-form.
        if !nim.is_form_of(&form) {
            return Err(Error::Wire("compressed form is not a form of Delta_q"));
        }
        // Reject a second encoding of the same element: recompress and compare bytes.
        let received = &self.bytes[start..self.position];
        let mut canonical = Vec::with_capacity(received.len());
        encode_qfi(&mut canonical, &form);
        if canonical != received {
            return Err(Error::Wire("non-canonical form encoding"));
        }
        Ok(form)
    }

    /// A `u8`-length-prefixed integer, used by the compressed form components.
    pub fn short_mpz(&mut self) -> Result<Mpz> {
        let len = self.u8()? as usize;
        Ok(mpz_from_bytes(self.take(len)?))
    }
}

pub fn encode_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

pub fn encode_scalar(out: &mut Vec<u8>, value: &Scalar255) {
    out.extend_from_slice(&value.to_be_bytes());
}

pub fn encode_g1(out: &mut Vec<u8>, point: &G1) {
    out.extend_from_slice(&point.to_bytes());
}

pub fn encode_g2(out: &mut Vec<u8>, point: &G2) {
    out.extend_from_slice(&point.to_bytes());
}

pub fn encode_mpz(out: &mut Vec<u8>, value: &Mpz) {
    let bytes = mpz_bytes(value);
    debug_assert!(
        bytes.len() <= u16::MAX as usize,
        "integer too large for the wire format"
    );
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(&bytes);
}

/// Encode a form in DGS compressed form: a flags byte, then four `u8`-length-prefixed
/// integers.
///
/// The compressed components are shorter than `sqrt(|Delta|)`, so a one-byte length is
/// enough; this keeps the framing at five bytes on top of the ~218 bytes of payload at the
/// paper's parameters.
///
/// The flags byte carries one sign bit per component plus the `b` sign. `Mpz::to_bytes` is
/// magnitude-only and `tp` really is negative in general (`t/g` from the extended Euclidean
/// step), so dropping the signs silently maps a form to a different one.
pub fn encode_qfi(out: &mut Vec<u8>, form: &QFI) {
    let compressed = form.compressed();
    let parts = [
        &compressed.ap,
        &compressed.g,
        &compressed.tp,
        &compressed.b0,
    ];
    let mut flags = if compressed.is_neg { 16u8 } else { 0 };
    for (index, part) in parts.iter().enumerate() {
        if mpz_sign(part) < 0 {
            flags |= 1 << index;
        }
    }
    out.push(flags);
    for part in parts {
        let bytes = mpz_bytes(part);
        debug_assert!(
            bytes.len() <= u8::MAX as usize,
            "compressed component too large"
        );
        let len = u8::try_from(bytes.len()).unwrap_or(u8::MAX);
        out.push(len);
        out.extend_from_slice(&bytes[..len as usize]);
    }
}

pub fn encode_proof(out: &mut Vec<u8>, proof: &Proof) {
    // The challenge is `ell_c` bits; 16 bytes covers the 128-bit instantiation.
    let mut challenge = vec![0u8; 16];
    let bytes = mpz_bytes(&proof.challenge);
    if bytes.len() <= 16 {
        challenge[16 - bytes.len()..].copy_from_slice(&bytes);
    }
    out.extend_from_slice(&challenge);
    encode_scalar(out, &proof.z_v);
    encode_scalar(out, &proof.z_s);
    encode_scalar(out, &proof.z_gamma);
    encode_scalar(out, &proof.z_rho);
    encode_mpz(out, &proof.z_r);
}

pub fn decode_proof(reader: &mut Reader<'_>) -> Result<Proof> {
    let challenge = mpz_from_bytes(reader.take(16)?);
    Ok(Proof {
        z_v: reader.scalar()?,
        z_s: reader.scalar()?,
        z_gamma: reader.scalar()?,
        z_rho: reader.scalar()?,
        z_r: reader.mpz()?,
        challenge,
    })
}

pub fn encode_round1(out: &mut Vec<u8>, message: &Round1Message, nim: &NimParameters) {
    encode_u64(out, message.id as u64);
    encode_g1(out, &message.vrf_share);
    encode_g1(out, &message.gamma_commitment);
    encode_qfi(out, &message.c0);
    // The single-base role-B encoding is one element; `c1` is the principal form there and is
    // not sent, which is where the ~220-byte saving comes from.
    if !nim.variant().is_single_base() {
        encode_qfi(out, &message.c1);
    }
    encode_proof(out, &message.proof);
}

pub fn decode_round1(bytes: &[u8], nim: &NimParameters) -> Result<Round1Message> {
    let mut reader = Reader::new(bytes);
    let id = reader.usize_id()?;
    let message = Round1Message {
        id,
        vrf_share: reader.g1()?,
        gamma_commitment: reader.g1()?,
        c0: reader.qfi(nim)?,
        c1: if nim.variant().is_single_base() {
            nim.identity().clone()
        } else {
            reader.qfi(nim)?
        },
        proof: decode_proof(&mut reader)?,
    };
    reader.finish()?;
    Ok(message)
}

pub fn encode_round2(out: &mut Vec<u8>, message: &Round2Message) {
    encode_u64(out, message.id as u64);
    encode_scalar(out, &message.u);
    encode_g1(out, &message.s);
}

pub fn decode_round2(bytes: &[u8]) -> Result<Round2Message> {
    let mut reader = Reader::new(bytes);
    let id = reader.usize_id()?;
    let u = reader.scalar()?;
    let s = reader.g1()?;
    reader.finish()?;
    Ok(Round2Message { id, u, s })
}

pub fn encode_signature(out: &mut Vec<u8>, signature: &Signature<G1>) {
    encode_g1(out, &signature.a);
    encode_scalar(out, &signature.e);
    encode_scalar(out, &signature.phi);
}

pub fn decode_signature(bytes: &[u8]) -> Result<Signature<G1>> {
    let mut reader = Reader::new(bytes);
    let signature = Signature {
        a: reader.g1()?,
        e: reader.scalar()?,
        phi: reader.scalar()?,
    };
    reader.finish()?;
    Ok(signature)
}

/// Encode a message vector as `32 * k` bytes.
pub fn encode_messages(out: &mut Vec<u8>, messages: &[Scalar255]) {
    for value in messages {
        encode_scalar(out, value);
    }
}

pub fn decode_messages(bytes: &[u8]) -> Result<Vec<Scalar255>> {
    if bytes.len() % 32 != 0 {
        return Err(Error::Wire("message vector length is not a multiple of 32"));
    }
    let mut reader = Reader::new(bytes);
    let mut messages = Vec::with_capacity(bytes.len() / 32);
    while reader.remaining() > 0 {
        messages.push(reader.scalar()?);
    }
    Ok(messages)
}
