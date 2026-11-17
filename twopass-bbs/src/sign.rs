//! The two-pass signing protocol (Fig. 1).
//!
//! ```text
//! Pass 1  P_1 -> P_2 :  beta_1                                    (one random string)
//! Pass 2  P_2 -> P_1 :  pi_Vrf, C = r B, D, pi_Lin
//! Output  P_1        :  beta_2 = VRF-Verify(...),  (e,s) = H_2(beta_1 || beta_2),
//!                       d = CL-Dec(dk_1, D),  A = C / d,  sigma = (A, e, s)
//! ```
//!
//! Three details carry the protocol:
//!
//! * `(e, s)` is derived from `beta_1 || beta_2` where `beta_2` is `P_2`'s VRF output on
//!   `H_1(m || sid)`. `P_1` must pick `beta_1` before seeing `beta_2`, and cannot predict it, so
//!   the pair is unbiased. Only `P_2` needs a VRF: `P_1` moves first and has nothing to react
//!   to.
//! * `r` is `P_2`'s alone. It never has to be shared, because it only masks the intermediate
//!   values — `P_1` recovers `r(x+e)` from `D` and divides it out. That is why the whole
//!   non-linear part fits in one pass.
//! * `D = C_key1^r * CL-Enc(ek_1, r(x_2 + e))` decrypts to `r(x_1 + x_2 + e) = r(x+e)`, because
//!   `C_key1^r` supplies `r x_1` homomorphically. `pi_Lin` proves that the `r` in `D` is the
//!   same `r` as in `C = r B` and that the plaintext really is `r(x_2+e)` — without it, `P_2`
//!   could hand `P_1` a ciphertext of anything and read one bit of `x_1` off whether the
//!   signature came out valid.
//!
//! Both parties keep the set of used `sid`s and refuse to sign twice under the same one. That
//! is the statefulness the paper notes: reusing a `sid` on the same message replays the same
//! VRF output, which would let a corrupted `P_1` search `beta_1` for a favourable `(e, s)`.

use std::collections::BTreeSet;
use std::sync::Arc;

use bicycl::{Mpz, QFI, RandGen};

use threshold_bbs::algebra::{Group, Scalar};
use threshold_bbs::bls381::{Scalar255, G1};
use threshold_bbs::hash::Transcript;

use crate::bbs::{self, Signature};
use crate::cl::{self, Cipher};
use crate::error::{Error, Result};
use crate::keygen::{FirstParty, SecondParty};
use crate::meter::{Meter, Op, Stage};
use crate::params::PublicParameters;
use crate::random::{fresh_rng, seed32};
use crate::vrf::{self, VrfOutput, VrfProof};
use crate::wire::{self, Reader};
use crate::zkp::{self, LinProof, LinStatement, LinWitness};

pub const DOMAIN_H2: &[u8] = b"twopass-bbs/v01/sign/nonces";
pub const DOMAIN_SIGN_CTX: &[u8] = b"twopass-bbs/v01/sign/ctx";

/// `H_2(beta_1 || beta_2) -> (e, s) in Z_q^2`.
pub fn hash_nonces(
    pp: &PublicParameters,
    beta1: &[u8; 32],
    beta2: &VrfOutput,
) -> (Scalar255, Scalar255) {
    let mut transcript = Transcript::new(DOMAIN_H2);
    pp.absorb(&mut transcript);
    transcript
        .absorb_bytes(b"beta1", beta1)
        .absorb_bytes(b"beta2", beta2);
    let digest = transcript.digest();
    (
        Scalar255::from_be_bytes_mod_order(&digest[..32]),
        Scalar255::from_be_bytes_mod_order(&digest[32..]),
    )
}

/// Canonical encoding of the message vector, used for the VRF input and the proof context.
pub fn encode_message(message: &[Scalar255]) -> Vec<u8> {
    let mut out = Vec::with_capacity(message.len() * 32);
    for value in message {
        wire::put_scalar(&mut out, value);
    }
    out
}

fn message_digest(message: &[Scalar255]) -> [u8; 32] {
    let mut transcript = Transcript::new(DOMAIN_SIGN_CTX);
    transcript.absorb_bytes(b"msg", &encode_message(message));
    transcript.digest32()
}

// ---------------------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Pass1 {
    pub beta1: [u8; 32],
}

impl Pass1 {
    pub fn encode(&self) -> Vec<u8> {
        self.beta1.to_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        let beta1 = reader.hash()?;
        reader.finish()?;
        Ok(Self { beta1 })
    }
}

#[derive(Clone, Debug)]
pub struct Pass2 {
    pub vrf_proof: VrfProof,
    pub c: G1,
    pub d: Cipher,
    pub lin_proof: LinProof,
}

impl Pass2 {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        wire::put_g1(&mut out, &self.vrf_proof.gamma);
        wire::put_challenge(&mut out, &self.vrf_proof.challenge);
        wire::put_scalar(&mut out, &self.vrf_proof.response);
        wire::put_g1(&mut out, &self.c);
        self.d.encode(&mut out);
        self.lin_proof.encode(&mut out);
        out
    }

    pub fn decode(bytes: &[u8], pp: &PublicParameters) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        let message = Self {
            vrf_proof: VrfProof {
                gamma: reader.g1()?,
                challenge: reader.challenge()?,
                response: reader.scalar()?,
            },
            c: reader.g1()?,
            d: Cipher::decode(&mut reader, &pp.cl)?,
            lin_proof: LinProof::decode(&mut reader)?,
        };
        reader.finish()?;
        Ok(message)
    }
}

// ---------------------------------------------------------------------------------------
// Signers
// ---------------------------------------------------------------------------------------

struct Pending {
    beta1: [u8; 32],
    session: Vec<u8>,
    message: [u8; 32],
}

/// `P_1`: moves first with `beta_1`, then finishes the signature.
pub struct SignerOne {
    pub party: FirstParty,
    pending: Option<Pending>,
    used: BTreeSet<Vec<u8>>,
}

impl SignerOne {
    pub fn new(party: FirstParty) -> Self {
        Self {
            party,
            pending: None,
            used: BTreeSet::new(),
        }
    }

    pub fn params(&self) -> &Arc<PublicParameters> {
        &self.party.params
    }

    /// Pass 1.
    pub fn pass1(
        &mut self,
        message: &[Scalar255],
        session: &[u8],
        meter: &mut Meter,
    ) -> Result<Pass1> {
        meter.step(Stage::SignOne, |_| {
            if self.used.contains(session) {
                return Err(Error::Protocol("sid already used for signing"));
            }
            if message.len() != self.party.params.config.message_len {
                return Err(Error::Protocol("message length"));
            }
            if self.pending.is_some() {
                return Err(Error::Protocol("a signing session is already in flight"));
            }
            let beta1 = seed32();
            self.pending = Some(Pending {
                beta1,
                session: session.to_vec(),
                message: message_digest(message),
            });
            Ok(Pass1 { beta1 })
        })
    }

    /// Output: verify, decrypt, divide.
    pub fn output(
        &mut self,
        pass2: &Pass2,
        message: &[Scalar255],
        session: &[u8],
        meter: &mut Meter,
    ) -> Result<Signature> {
        meter.step(Stage::SignOutput, |meter| {
            let pending = self
                .pending
                .take()
                .ok_or(Error::Protocol("no signing session in flight"))?;
            if pending.session != session || pending.message != message_digest(message) {
                return Err(Error::Protocol("pass 2 answers a different session"));
            }
            self.used.insert(session.to_vec());

            let pp = self.party.params.clone();
            let class = &pp.cl;

            // (1) beta_2 from the VRF proof.
            let alpha = vrf::input(&pp, &encode_message(message), session);
            let beta2 = vrf::verify(&pp, &self.party.peer_vk, &alpha, &pass2.vrf_proof, meter)
                .ok_or(Error::Verify("VRF proof"))?;

            // (2) nonces and base.
            let (e, s) = hash_nonces(&pp, &pending.beta1, &beta2);
            let base = pp.big_b(&s, message)?;

            // (3) pi_Lin.
            let statement = LinStatement {
                ek: &self.party.ek,
                base: &base,
                scaled: &pass2.c,
                x_g2: &self.party.peer_share,
                ct_a: &self.party.c_key,
                ct_b: &pass2.d,
                e: &e,
            };
            let ctx = zkp::context(session, b"sign/lin", &[1, 2]);
            if !zkp::verify_cl_lin(&pp, &ctx, &statement, &pass2.lin_proof, meter) {
                return Err(Error::Verify("R_CL-Lin"));
            }

            // (4) d = CL-Dec(dk_1, D) = r(x+e), then A = C / d.
            let d = cl::decrypt(class, &self.party.dk, &pass2.d, meter)?;
            zkp::require_invertible(&d)?;
            let inverse = d
                .invert()
                .ok_or(Error::Arithmetic("r(x + e) is not invertible"))?;
            meter.add(Op::G1Exp);
            let a = pass2.c.scale(&inverse);

            let signature = Signature { a, e, s };
            let valid = bbs::verify(&pp, &self.party.public_key, message, &signature);
            if !valid {
                return Err(Error::Verify("two-party signature"));
            }
            Ok(signature)
        })
    }
}

/// `P_2`: answers with the VRF output, `C`, `D` and `pi_Lin`.
pub struct SignerTwo {
    pub party: SecondParty,
    used: BTreeSet<Vec<u8>>,
    rng: RandGen,
}

impl SignerTwo {
    pub fn new(party: SecondParty) -> Self {
        Self {
            party,
            used: BTreeSet::new(),
            rng: fresh_rng(),
        }
    }

    pub fn params(&self) -> &Arc<PublicParameters> {
        &self.party.params
    }

    /// Pass 2.
    pub fn pass2(
        &mut self,
        pass1: &Pass1,
        message: &[Scalar255],
        session: &[u8],
        meter: &mut Meter,
    ) -> Result<Pass2> {
        meter.step(Stage::SignTwo, |meter| {
            if self.used.contains(session) {
                return Err(Error::Protocol("sid already used for signing"));
            }
            if message.len() != self.party.params.config.message_len {
                return Err(Error::Protocol("message length"));
            }
            // `beta_1 in Y` is the length check the decoder already enforced.
            self.used.insert(session.to_vec());

            let pp = self.party.params.clone();
            let class = &pp.cl;

            // (1) VRF on H_1(m || sid).
            let alpha = vrf::input(&pp, &encode_message(message), session);
            let (beta2, vrf_proof) =
                vrf::eval(&pp, &self.party.vrf, &alpha, &mut rand_core::OsRng, meter);

            // (2) nonces and base.
            let (e, s) = hash_nonces(&pp, &pass1.beta1, &beta2);
            let base = pp.big_b(&s, message)?;

            // (3) C = r B.
            let r = Scalar255::random(&mut rand_core::OsRng);
            meter.add(Op::G1Exp);
            let c = base.scale(&r);

            // (4) D = C_key1^r * CL-Enc(ek_1, r(x_2 + e); rho_2).
            let rho2 = class.sample_dq(&mut self.rng);
            let plaintext = r.mul(&self.party.own_share.add(&e));
            let scaled = cl::scale(class, &self.party.c_key, &r, meter);
            let fresh = cl::encrypt(class, &self.party.ek, &plaintext, &rho2, meter);
            let d = cl::add(class, &scaled, &fresh, meter);

            // (5) pi_Lin.
            let statement = LinStatement {
                ek: &self.party.ek,
                base: &base,
                scaled: &c,
                x_g2: &self.party.own_share_g2,
                ct_a: &self.party.c_key,
                ct_b: &d,
                e: &e,
            };
            let witness = LinWitness {
                r: &r,
                x: &self.party.own_share,
                rho: &rho2,
            };
            let ctx = zkp::context(session, b"sign/lin", &[1, 2]);
            let lin_proof =
                zkp::prove_cl_lin(&pp, &ctx, &statement, &witness, &mut self.rng, meter);

            Ok(Pass2 {
                vrf_proof,
                c,
                d,
                lin_proof,
            })
        })
    }
}

/// `P_2`'s own share, exposed for tests that want to reconstruct `X` independently.
pub fn share_of_second(party: &SecondParty) -> Scalar255 {
    party.own_share.clone()
}

/// `ek_1` and `C_key1` are public material `P_2` must keep; exposed for the report.
pub fn key_cipher_len(ek: &QFI, c_key: &Cipher) -> usize {
    wire::qfi_len(ek) + c_key.encoded_len()
}

/// `rho` is `D_q`-bounded; the report prints its width.
pub fn randomness_bits(rho: &Mpz) -> usize {
    threshold_bbs::util::mpz_bits(rho)
}
