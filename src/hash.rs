//! Canonical transcripts and the random oracles of the construction.
//!
//! Every challenge in this crate goes through [`Transcript`], which length-prefixes every
//! absorbed item. This matters for two reasons the previous implementation got wrong:
//! group elements are hashed through their canonical compressed encoding (never through
//! `Debug` output), and class-group forms are hashed component-wise with explicit lengths
//! (`QFI::to_bytes` concatenates three integers without separators).

use std::sync::OnceLock;

use bicycl::{Mpz, QFI};
use sha2::{Digest, Sha256, Sha512};

use crate::algebra::{Encodable, Scalar};
use crate::bls381::{hash_to_g1, Scalar255, G1};
use crate::util::{mpz_bytes, mpz_from_bytes, mpz_lt, mpz_sign, pow2, scalar_to_mpz};

pub const DST_VRF_BASE_1: &[u8] = b"threshold-bbs/v03/hashvrf/B1";
pub const DST_VRF_BASE_2: &[u8] = b"threshold-bbs/v03/hashvrf/B2";
pub const DST_GROUP_MASK: &[u8] = b"threshold-bbs/v03/hashS";
pub const DST_SCALAR_MASK: &[u8] = b"threshold-bbs/v03/hashu";
pub const DST_SETUP_H0: &[u8] = b"threshold-bbs/v03/setup/h0";
pub const DST_SETUP_H1: &[u8] = b"threshold-bbs/v03/setup/h1";
pub const DST_SETUP_HH: &[u8] = b"threshold-bbs/v03/setup/hh";
pub const DST_SETUP_H2: &[u8] = b"threshold-bbs/v03/setup/h2";
pub const DST_MESSAGE_BASE: &[u8] = b"threshold-bbs/v03/setup/message-base";

/// An unambiguous, domain-separated byte transcript.
#[derive(Clone, Debug, Default)]
pub struct Transcript {
    buffer: Vec<u8>,
}

impl Transcript {
    pub fn new(domain: &[u8]) -> Self {
        let mut buffer = Vec::new();
        push_item(&mut buffer, domain);
        Self { buffer }
    }

    pub fn absorb_bytes(&mut self, label: &[u8], value: &[u8]) -> &mut Self {
        push_item(&mut self.buffer, label);
        push_item(&mut self.buffer, value);
        self
    }

    pub fn absorb_u64(&mut self, label: &[u8], value: u64) -> &mut Self {
        self.absorb_bytes(label, &value.to_be_bytes())
    }

    pub fn absorb_scalar(&mut self, label: &[u8], value: &Scalar255) -> &mut Self {
        self.absorb_bytes(label, &value.to_be_bytes())
    }

    pub fn absorb_g1(&mut self, label: &[u8], point: &G1) -> &mut Self {
        self.absorb_bytes(label, &point.to_bytes())
    }

    pub fn absorb_g2(&mut self, label: &[u8], point: &crate::bls381::G2) -> &mut Self {
        self.absorb_bytes(label, &point.to_bytes())
    }

    /// Absorb a class-group form as its three signed integers.
    ///
    /// `mpz_bytes` is magnitude-only, so the sign of each coefficient is included
    /// explicitly; without it `(a, b, c)` and `(a, -b, c)` would hash identically.
    pub fn absorb_qfi(&mut self, label: &[u8], form: &QFI) -> &mut Self {
        push_item(&mut self.buffer, label);
        for coefficient in [form.a(), form.b(), form.c()] {
            push_item(&mut self.buffer, &[mpz_sign(&coefficient) as u8]);
            push_item(&mut self.buffer, &mpz_bytes(&coefficient));
        }
        self
    }

    pub fn absorb_quorum(&mut self, quorum: &[usize]) -> &mut Self {
        let mut encoded = Vec::with_capacity(quorum.len() * 8);
        for id in quorum {
            encoded.extend_from_slice(&(*id as u64).to_be_bytes());
        }
        self.absorb_bytes(b"quorum", &encoded)
    }

    /// 64-byte digest used to derive challenges and oracle outputs.
    pub fn digest(&self) -> [u8; 64] {
        let mut hasher = Sha512::new();
        hasher.update(&self.buffer);
        let out = hasher.finalize();
        let mut digest = [0u8; 64];
        digest.copy_from_slice(&out);
        digest
    }

    pub fn digest32(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.buffer);
        let out = hasher.finalize();
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&out);
        digest
    }
}

fn push_item(buffer: &mut Vec<u8>, item: &[u8]) {
    buffer.extend_from_slice(&(item.len() as u32).to_be_bytes());
    buffer.extend_from_slice(item);
}

/// The dual-base threshold VRF input of Round 1: `(B_1, B_2) = hashvrf(sid, msg, Q)`.
pub fn hashvrf(session: &[u8], message: &[u8], quorum: &[usize]) -> (G1, G1) {
    let mut transcript = Transcript::new(b"threshold-bbs/v03/hashvrf");
    transcript
        .absorb_bytes(b"sid", session)
        .absorb_bytes(b"msg", message)
        .absorb_quorum(quorum);
    let seed = transcript.digest32();
    (
        hash_to_g1(DST_VRF_BASE_1, &seed),
        hash_to_g1(DST_VRF_BASE_2, &seed),
    )
}

/// Domain tags that separate the two field elements `hashout` returns, so `e` and `phi` are
/// independent hash evaluations rather than two halves of one digest.
const DST_HASHOUT_E: &[u8] = b"threshold-bbs/v03/hashout/e";
const DST_HASHOUT_PHI: &[u8] = b"threshold-bbs/v03/hashout/phi";

/// Rejection rounds attempted before falling back to a direct reduction. A round is accepted
/// with probability `1 - (2^512 mod q)/2^512 > 1 - 2^-257`, so reaching the fallback is a
/// `2^-1000` event; it exists only so the function is total.
const HASHOUT_ATTEMPTS: u32 = 4;

/// One random oracle on the TVRF output, returning both BBS+ scalars `(e, phi)`.
///
/// Each scalar is drawn from its own 512-bit window and rejection-sampled, so the output is
/// *exactly* uniform in `Z_q` for every party that evaluates it. Deriving a scalar from a
/// single 256-bit integer reduced modulo `q` would not be: with
/// `q = 0.452847·2^256` and `r = 2^256 - 2q`, a 256-bit draw lands in `[0, r)` with
/// probability `3r/2^256` instead of `r/q`, a statistical distance of
/// `(r/2^256)(1 - r/q) = 0.0747` — a constant, so it does not vanish in the number of
/// queries and the ROM argument of Theorem 4.1 would not apply to the code.
pub fn hashout(
    session: &[u8],
    message: &[u8],
    quorum: &[usize],
    vrf_output: &G1,
) -> (Scalar255, Scalar255) {
    (
        field_element(session, message, quorum, vrf_output, DST_HASHOUT_E),
        field_element(session, message, quorum, vrf_output, DST_HASHOUT_PHI),
    )
}

/// `2^512 - (2^512 mod q)`: the largest multiple of `q` not exceeding `2^512`.
///
/// `2^512 mod q` is evaluated inside `Z_q` as `(2^256 mod q)^2`, so the constant needs no
/// big-integer division and cannot drift away from the field modulus.
pub fn window_threshold() -> &'static Mpz {
    static CACHE: OnceLock<Mpz> = OnceLock::new();
    CACHE.get_or_init(|| {
        let mut two_256 = [0u8; 33];
        two_256[0] = 1;
        let half = Scalar255::from_be_bytes_mod_order(&two_256);
        let square = half.mul(&half);
        pow2(512) - scalar_to_mpz(&square)
    })
}

/// `value` lies in the unbiased window `[0, 2^512 - (2^512 mod q))`.
pub fn in_unbiased_window(value: &Mpz) -> bool {
    mpz_lt(value, window_threshold())
}

fn field_element(
    session: &[u8],
    message: &[u8],
    quorum: &[usize],
    vrf_output: &G1,
    tag: &[u8],
) -> Scalar255 {
    let mut digest = [0u8; 64];
    for attempt in 0..=HASHOUT_ATTEMPTS {
        let mut transcript = Transcript::new(b"threshold-bbs/v03/hashout");
        transcript
            .absorb_bytes(b"sid", session)
            .absorb_bytes(b"msg", message)
            .absorb_quorum(quorum)
            .absorb_g1(b"W", vrf_output)
            .absorb_bytes(b"tag", tag)
            .absorb_bytes(b"attempt", &attempt.to_be_bytes());
        digest = transcript.digest();
        if attempt == HASHOUT_ATTEMPTS || in_unbiased_window(&mpz_from_bytes(&digest)) {
            break;
        }
    }
    Scalar255::from_be_bytes_mod_order(&digest)
}

/// `hashu(seed, tr)`: the pairwise mask in `Z_q`, full width.
pub fn mask_scalar(seed: &[u8; 32], transcript: &[u8; 32]) -> Scalar255 {
    let mut hasher = Sha512::new();
    hasher.update(b"threshold-bbs/v03/hashu");
    hasher.update(seed);
    hasher.update(transcript);
    Scalar255::from_be_bytes_mod_order(&hasher.finalize())
}

/// `hashS(seed, tr)`: the pairwise mask in `G_1`.
pub fn mask_group(seed: &[u8; 32], transcript: &[u8; 32]) -> G1 {
    let mut hasher = Sha256::new();
    hasher.update(b"threshold-bbs/v03/hashS");
    hasher.update(seed);
    hasher.update(transcript);
    hash_to_g1(DST_GROUP_MASK, &hasher.finalize())
}

/// Sign of the pairwise mask contribution, the paper's `sgn(i - j)`: negative when the
/// caller's index is the smaller one.
///
/// The construction only uses the product `hashu(seed_{i,j}, tr) * sgn(i-j)` summed over
/// `j != i`, so a global flip of all signs would cancel just as well; the convention is kept
/// equal to the paper's so that the security proof can be followed line by line.
pub fn mask_sign(id: usize, peer: usize) -> i8 {
    if id < peer {
        -1
    } else {
        1
    }
}

/// Absorb a scalar into a transcript (label-prefixed), exposed for statement encoding.
pub fn absorb_scalar_repr(transcript: &mut Transcript, label: &[u8], value: &Scalar255) {
    transcript.absorb_bytes(label, &value.to_be_bytes());
}

/// Absorb a non-negative class-group integer.
pub fn absorb_mpz_repr(transcript: &mut Transcript, label: &[u8], value: &bicycl::Mpz) {
    transcript.absorb_bytes(label, &mpz_bytes(value));
}

/// Convenience: embed a scalar for exponentiation by the class-group backend.
pub fn exponent_of(value: &Scalar255) -> bicycl::Mpz {
    scalar_to_mpz(value)
}
