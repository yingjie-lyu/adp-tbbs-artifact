//! Canonical wire format.
//!
//! Same discipline as the sibling crates: fixed widths where the setup fixes the size,
//! length prefixes where it does not, trailing bytes rejected, and class-group forms checked
//! against `b^2 - 4ac = Delta_q` *and* re-encoded, so a second encoding of the same element is
//! refused. Decoding never panics.
//!
//! Class-group forms use BICYCL's Dobson–Galbraith–Smith compressed representation: 225 bytes
//! at the paper's 1827-bit discriminant, which is what the 0.85 KB per-signature figure is
//! built from.

use bicycl::{Mpz, QFI};
use bls12_381::{G1Affine, G2Affine};

use threshold_bbs::algebra::{Encodable, Scalar};
use threshold_bbs::bls381::{Scalar255, G1, G2};
use threshold_bbs::util::{mpz_bits, mpz_bytes, mpz_from_bytes, mpz_neg, mpz_sign};

use crate::cl::ClParameters;
use crate::error::{Error, Result};

/// Challenges are `ell_c <= 128` bits.
pub const CHALLENGE_BYTES: usize = 16;

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

    pub fn position(&self) -> usize {
        self.position
    }

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
        usize::try_from(self.u64()?).map_err(|_| Error::Wire("identifier out of range"))
    }

    pub fn scalar(&mut self) -> Result<Scalar255> {
        Ok(Scalar255::from_be_bytes_mod_order(self.take(32)?))
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

    pub fn hash(&mut self) -> Result<[u8; 32]> {
        let mut value = [0u8; 32];
        value.copy_from_slice(self.take(32)?);
        Ok(value)
    }

    pub fn challenge(&mut self) -> Result<Scalar255> {
        Ok(Scalar255::from_be_bytes_mod_order(self.take(CHALLENGE_BYTES)?))
    }

    /// A signed integer as `sign byte + u16 length + magnitude`.
    pub fn mpz(&mut self) -> Result<Mpz> {
        let negative = match self.u8()? {
            0 => false,
            1 => true,
            _ => return Err(Error::Wire("invalid integer sign")),
        };
        let len = self.u16()?;
        let magnitude = mpz_from_bytes(self.take(len)?);
        Ok(if negative { mpz_neg(&magnitude) } else { magnitude })
    }

    pub fn short_mpz(&mut self) -> Result<Mpz> {
        let len = self.u8()? as usize;
        Ok(mpz_from_bytes(self.take(len)?))
    }

    /// A class-group form in DGS compressed form.
    pub fn qfi(&mut self, cl: &ClParameters) -> Result<QFI> {
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

        // BICYCL divides by these while decompressing and aborts the process on garbage.
        if mpz_bits(&ap) == 0 || mpz_sign(&ap) < 0 || mpz_sign(&g) < 0 || mpz_sign(&b0) < 0 {
            return Err(Error::Wire("compressed form has an out-of-range component"));
        }
        let degenerate = mpz_bits(&g) == 0 || mpz_bits(&tp) == 0;
        if degenerate && !(mpz_bits(&tp) == 0 && mpz_bits(&b0) == 0 && !is_neg) {
            return Err(Error::Wire("compressed form has an inconsistent zero component"));
        }

        let form = QFI::from_compressed(
            &bicycl::CompressedForm {
                ap,
                g,
                tp,
                b0,
                is_neg,
            },
            &cl.group().discriminant(),
        );
        if !cl.is_form(&form) {
            return Err(Error::Wire("compressed form is not a form of Delta_q"));
        }
        let received = &self.bytes[start..self.position];
        let mut canonical = Vec::with_capacity(received.len());
        put_qfi(&mut canonical, &form);
        if canonical != received {
            return Err(Error::Wire("non-canonical form encoding"));
        }
        Ok(form)
    }
}

pub fn put_u16(out: &mut Vec<u8>, value: usize) {
    debug_assert!(value <= u16::MAX as usize, "count too large for the wire");
    out.extend_from_slice(&(value as u16).to_be_bytes());
}

pub fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

pub fn put_scalar(out: &mut Vec<u8>, value: &Scalar255) {
    out.extend_from_slice(&value.to_be_bytes());
}

pub fn put_g1(out: &mut Vec<u8>, point: &G1) {
    out.extend_from_slice(&point.to_bytes());
}

pub fn put_g2(out: &mut Vec<u8>, point: &G2) {
    out.extend_from_slice(&point.to_bytes());
}

pub fn put_hash(out: &mut Vec<u8>, value: &[u8; 32]) {
    out.extend_from_slice(value);
}

pub fn put_mpz(out: &mut Vec<u8>, value: &Mpz) {
    out.push(if mpz_sign(value) < 0 { 1 } else { 0 });
    let bytes = mpz_bytes(value);
    debug_assert!(bytes.len() <= u16::MAX as usize, "integer too large for the wire");
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(&bytes);
}

pub fn put_challenge(out: &mut Vec<u8>, value: &Scalar255) {
    let bytes = mpz_bytes(&Mpz::from_bytes(&value.to_be_bytes()));
    let mut field = vec![0u8; CHALLENGE_BYTES];
    if bytes.len() <= CHALLENGE_BYTES {
        field[CHALLENGE_BYTES - bytes.len()..].copy_from_slice(&bytes);
    }
    out.extend_from_slice(&field);
}

/// Encode a form in DGS compressed form: a flags byte with five sign bits, then four
/// `u8`-length-prefixed integers. `tp` is generally negative and `Mpz::to_bytes` is
/// magnitude-only, so the sign bits are not optional.
pub fn put_qfi(out: &mut Vec<u8>, form: &QFI) {
    let compressed = form.compressed();
    let parts = [&compressed.ap, &compressed.g, &compressed.tp, &compressed.b0];
    let mut flags = if compressed.is_neg { 16u8 } else { 0 };
    for (index, part) in parts.iter().enumerate() {
        if mpz_sign(part) < 0 {
            flags |= 1 << index;
        }
    }
    out.push(flags);
    for part in parts {
        let bytes = mpz_bytes(part);
        debug_assert!(bytes.len() <= u8::MAX as usize, "compressed component too large");
        let len = u8::try_from(bytes.len()).unwrap_or(u8::MAX);
        out.push(len);
        out.extend_from_slice(&bytes[..len as usize]);
    }
}

/// Serialised size of a form, for the report.
pub fn qfi_len(form: &QFI) -> usize {
    let mut buffer = Vec::new();
    put_qfi(&mut buffer, form);
    buffer.len()
}
