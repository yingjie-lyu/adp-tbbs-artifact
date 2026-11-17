//! RNG plumbing. `bicycl::RandGen::new()` is not seeded (GMP's default seed is fixed), so
//! every long-lived stream goes through [`fresh_rng`].

use bicycl::{Mpz, RandGen};
use rand_core::{OsRng, RngCore};

pub fn fresh_rng() -> RandGen {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let mut rng = RandGen::new();
    rng.set_seed(&Mpz::from_bytes(&seed));
    rng
}

pub fn seed32() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}
