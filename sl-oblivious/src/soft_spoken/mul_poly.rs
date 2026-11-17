// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.
//
// Locally modified: multiplication dispatches to PCLMULQDQ on x86-64 and keeps the original
// software routine as the fallback (see MODIFICATIONS.md).

///     Multiplies `a` and `b` in the finite field of order 2^128
///     modulo the irreducible polynomial f(x) = 1 + x + x^2 + x^7 + x^128
///
///     https://link.springer.com/book/10.1007/b97644
///     multiplication part: Algorithm 2.34, "Right-to-left comb method for polynomial multiplication"
///     reduction part: variant of the idea of Figure 2.9
pub fn binary_field_multiply_gf_2_128(a: &[u8; 16], b_data: &[u8; 16]) -> [u8; 16] {
    #[cfg(target_arch = "x86_64")]
    {
        if std::is_x86_feature_detected!("pclmulqdq") && std::is_x86_feature_detected!("sse2") {
            // SAFETY: both target features were just checked at runtime.
            return unsafe { clmul_multiply(a, b_data) };
        }
    }
    software_multiply(a, b_data)
}

/// Carry-less multiply plus a two-fold reduction modulo `x^128 + x^7 + x^2 + x + 1`.
///
/// Bytes are little-endian field elements, matching [`software_multiply`].
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn clmul_multiply(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    use core::arch::x86_64::{
        __m128i, _mm_clmulepi64_si128, _mm_loadu_si128, _mm_slli_si128, _mm_srli_si128,
        _mm_storeu_si128, _mm_xor_si128,
    };

    let x = _mm_loadu_si128(a.as_ptr() as *const __m128i);
    let y = _mm_loadu_si128(b.as_ptr() as *const __m128i);

    // Schoolbook over 64-bit halves: a = a0 + a1 x^64, b = b0 + b1 x^64.
    let p00 = _mm_clmulepi64_si128(x, y, 0x00);
    let p11 = _mm_clmulepi64_si128(x, y, 0x11);
    let p01 = _mm_clmulepi64_si128(x, y, 0x01);
    let p10 = _mm_clmulepi64_si128(x, y, 0x10);
    let middle = _mm_xor_si128(p01, p10);

    let low = _mm_xor_si128(p00, _mm_slli_si128(middle, 8));
    let high = _mm_xor_si128(p11, _mm_srli_si128(middle, 8));

    let mut low_bytes = [0u8; 16];
    let mut high_bytes = [0u8; 16];
    _mm_storeu_si128(low_bytes.as_mut_ptr() as *mut __m128i, low);
    _mm_storeu_si128(high_bytes.as_mut_ptr() as *mut __m128i, high);

    let lo = u128::from_le_bytes(low_bytes);
    let hi = u128::from_le_bytes(high_bytes);
    reduce(lo, hi).to_le_bytes()
}

/// `x^128 = x^7 + x^2 + x + 1`, folded twice: the first fold handles the high half, the second
/// the at-most-seven overflow bits it produces.
#[cfg(target_arch = "x86_64")]
fn reduce(lo: u128, hi: u128) -> u128 {
    let mut carry: u128 = 0;
    carry ^= hi >> 127;
    carry ^= hi >> 126;
    carry ^= hi >> 121;
    let folded = hi ^ (hi << 1) ^ (hi << 2) ^ (hi << 7);
    let low = lo ^ folded;

    let again = carry ^ (carry << 1) ^ (carry << 2) ^ (carry << 7);
    low ^ again
}

/// Original software routine, kept as the fallback when PCLMULQDQ is unavailable.
pub fn software_multiply(a: &[u8; 16], b_data: &[u8; 16]) -> [u8; 16] {
    const W: usize = 8;
    const T: usize = 16;

    let mut c = [0u8; T * 2];
    let mut b = [0u8; T + 1];

    b[..16].copy_from_slice(b_data);

    for k in 0..W {
        for j in 0..T {
            let mask = -((a[j] >> k & 0x01) as i8) as u8;
            for i in 0..T + 1 {
                c[j + i] ^= b[i] & mask;
            }
        }
        for i in (1..=T).rev() {
            b[i] = (b[i] << 1) | (b[i - 1] >> 7);
        }
        b[0] <<= 1
    }
    for i in (T..=2 * T - 1).rev() {
        c[i - 16] ^= c[i];
        c[i - 16] ^= c[i] << 1;
        c[i - 15] ^= c[i] >> 7;
        c[i - 16] ^= c[i] << 2;
        c[i - 15] ^= c[i] >> 6;
        c[i - 16] ^= c[i] << 7;
        c[i - 15] ^= c[i] >> 1;
    }

    c[..16].try_into().unwrap()
}

#[cfg(test)]
mod tests {
    // Test based on fermat's little theorem
    #[test]
    fn test_mul_128() {
        for _ in 0..10 {
            let rand_num = rand::random::<[u8; 16]>();
            let mut temp = rand_num;

            for _ in 0..128 {
                temp = super::binary_field_multiply_gf_2_128(&temp, &temp);
            }

            assert_eq!(temp, rand_num);
        }
    }

    /// The accelerated path must agree with the software one on random inputs.
    #[test]
    fn clmul_matches_software() {
        for _ in 0..256 {
            let a = rand::random::<[u8; 16]>();
            let b = rand::random::<[u8; 16]>();
            assert_eq!(
                super::binary_field_multiply_gf_2_128(&a, &b),
                super::software_multiply(&a, &b)
            );
        }
    }
}
