//! The accelerated GF(2^128) multiplication must agree with the software fallback.

use sl_oblivious::soft_spoken::mul_poly::{binary_field_multiply_gf_2_128, software_multiply};

#[test]
fn clmul_matches_software() {
    let mut state: u64 = 0x9e3779b97f4a7c15;
    let mut next = || {
        let mut bytes = [0u8; 16];
        for chunk in bytes.chunks_mut(8) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            chunk.copy_from_slice(&state.to_le_bytes());
        }
        bytes
    };
    for _ in 0..1000 {
        let a = next();
        let b = next();
        assert_eq!(
            binary_field_multiply_gf_2_128(&a, &b),
            software_multiply(&a, &b),
            "a = {a:02x?}, b = {b:02x?}"
        );
    }
    // Squaring 128 times is the identity (Fermat), which the accelerated path must satisfy too.
    for _ in 0..10 {
        let a = next();
        let mut acc = a;
        for _ in 0..128 {
            acc = binary_field_multiply_gf_2_128(&acc, &acc);
        }
        assert_eq!(acc, a);
    }
}
