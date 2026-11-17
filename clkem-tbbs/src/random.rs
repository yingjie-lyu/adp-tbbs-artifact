//! RNG plumbing.
//!
//! `bicycl::RandGen::new()` wraps GMP's `gmp_randinit_default`, which is *not* seeded: two
//! `RandGen::new()` instances produce the same stream. Every long-lived randomness source in
//! this crate therefore goes through [`fresh_rng`], which seeds from the OS RNG. Nonces,
//! scaling factors `gamma_i` and DKG contributions all come from here; reusing a stream
//! across parties would hand the same `gamma_i` to everyone.

use bicycl::{Mpz, RandGen};
use rand_core::{OsRng, RngCore};

/// A `RandGen` seeded from the operating system.
pub fn fresh_rng() -> RandGen {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let mut rng = RandGen::new();
    rng.set_seed(&Mpz::from_bytes(&seed));
    rng
}

/// Uniform in `[0, bound)`.
pub fn below(rng: &mut RandGen, bound: &Mpz) -> Mpz {
    rng.random_mpz(bound)
}

/// A 32-byte seed / nonce from the OS RNG.
pub fn seed32() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}
