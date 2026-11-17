//! RNG plumbing.
//!
//! `bicycl::RandGen::new()` wraps GMP's `gmp_randinit_default`, which is not seeded: two
//! instances produce the same stream. Every long-lived randomness source goes through
//! [`fresh_rng`], which seeds from the OS RNG. A repeated stream here would hand the same CL
//! randomness `rho` to every encryption, which breaks the hiding of `x_1` outright.

use bicycl::{Mpz, RandGen};
use rand_core::{OsRng, RngCore};

pub fn fresh_rng() -> RandGen {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let mut rng = RandGen::new();
    rng.set_seed(&Mpz::from_bytes(&seed));
    rng
}

/// A 32-byte value from the OS RNG.
pub fn seed32() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}
