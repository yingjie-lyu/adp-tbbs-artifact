//! The three-round signing protocol (Fig. 8).
//!
//! ```text
//! Round 1  commit (e_i, s_i);  gamma_i <- D;  phi_{K^{gamma_i}} = phi_K^{gamma_i};
//!          gamma_i x^K = (x^K)^{gamma_i};  broadcast phi_{K^{gamma_i}} with an R_dls proof
//! Round 2  open (e_i, s_i);  e = sum e_j,  s = sum s_j
//! Round 3  B = G_1 + s H_1 + sum m_k H_{k+1};  R_i = gamma_i B;
//!          pd_i = (gamma_i (x+e)^K)^{Delta^2} / (phi_{K^gamma}^{Delta L_i sk_i} * f^{alpha_i})
//! Combine  u = Delta^{-2} CL.Solve(prod pd_j);  A = (sum R_j) / u;  check the pairing
//! ```
//!
//! Three things make this work and are easy to get wrong:
//!
//! * `phi_{K^{gamma_i}}` is broadcast *without* the symmetric half, so the encapsulation hides
//!   `gamma_i mod q` because `gamma_i` is drawn from `D` and `gcd(s', q) = 1`.
//! * `e` is only known in round 3, but `phi_{K^{gamma_i}}` — and therefore the encapsulation
//!   of the partial decryption — was already fixed in round 1. The `f^{gamma_i e}` correction
//!   is added in the exponent of the *symmetric* component, which needs no proof.
//! * The `Delta^2` in `pd_i` cancels the `Delta^{-2}` in the Lagrange reconstruction of `sk`,
//!   leaving `prod pd_j = f^{Delta^2 gamma (x+e)}` in the kernel, where `CL.Solve` is easy.
//!
//! `pd_i` carries no proof: as the paper argues, the `{pd_j}` already determine the MAC key
//! `gamma mod q` (or yield a value that fails the final pairing check), so misbehaviour is
//! detected by the signature verification itself.

use std::collections::BTreeMap;

use bicycl::{Mpz, RandGen, QFI};

use threshold_bbs::algebra::{Group, Scalar};
use threshold_bbs::bls381::{Scalar255, G1};
use threshold_bbs::util::mpz_to_scalar;

use crate::bbs::Signature;
use crate::error::{Error, Result};
use crate::keygen::{commit_hash, KeyPackage};
use crate::random::fresh_rng;
use crate::stats::{Meter, Stage};
use crate::util::{mul, square};
use crate::wire::{self, Reader};
use crate::zkp::{self, DlProof};

pub const DOMAIN_SIGN_COMMIT: &[u8] = b"clkem-tbbs/v01/sign/commit";

#[derive(Clone, Debug)]
pub struct SignCommitMsg {
    pub id: usize,
    pub commitment: [u8; 32],
    pub phi_gamma: QFI,
    pub proof: DlProof,
}

impl SignCommitMsg {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        wire::put_u64(&mut out, self.id as u64);
        wire::put_hash(&mut out, &self.commitment);
        wire::put_qfi(&mut out, &self.phi_gamma);
        self.proof.encode(&mut out);
        out
    }

    pub fn decode(bytes: &[u8], cl: &crate::cl::ClParameters) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        let message = Self {
            id: reader.usize_id()?,
            commitment: reader.hash()?,
            phi_gamma: reader.qfi(cl)?,
            proof: DlProof::decode(&mut reader)?,
        };
        reader.finish()?;
        Ok(message)
    }
}

#[derive(Clone, Debug)]
pub struct SignOpenMsg {
    pub id: usize,
    pub e_i: Scalar255,
    pub s_i: Scalar255,
}

impl SignOpenMsg {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        wire::put_u64(&mut out, self.id as u64);
        wire::put_scalar(&mut out, &self.e_i);
        wire::put_scalar(&mut out, &self.s_i);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        let message = Self {
            id: reader.usize_id()?,
            e_i: reader.scalar()?,
            s_i: reader.scalar()?,
        };
        reader.finish()?;
        Ok(message)
    }
}

#[derive(Clone, Debug)]
pub struct SignShareMsg {
    pub id: usize,
    pub r_i: G1,
    pub pd_i: QFI,
}

impl SignShareMsg {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        wire::put_u64(&mut out, self.id as u64);
        wire::put_g1(&mut out, &self.r_i);
        wire::put_qfi(&mut out, &self.pd_i);
        out
    }

    pub fn decode(bytes: &[u8], cl: &crate::cl::ClParameters) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        let message = Self {
            id: reader.usize_id()?,
            r_i: reader.g1()?,
            pd_i: reader.qfi(cl)?,
        };
        reader.finish()?;
        Ok(message)
    }
}

/// One signer's state machine.
pub struct SignParty {
    pub id: usize,
    pub quorum: Vec<usize>,
    pub session: Vec<u8>,
    pub package: KeyPackage,
    pub message: Vec<Scalar255>,
    rng: RandGen,
    e_i: Scalar255,
    s_i: Scalar255,
    gamma_i: Mpz,
    phi_gamma: QFI,
    scaled: QFI,
    e: Scalar255,
    s: Scalar255,
    counter: u64,
    commits: BTreeMap<usize, SignCommitMsg>,
    phi_gamma_all: Option<QFI>,
}

impl SignParty {
    pub fn new(
        package: KeyPackage,
        quorum: &[usize],
        message: &[Scalar255],
        session: &[u8],
    ) -> Result<Self> {
        let public = &package.public;
        if quorum.len() < public.t {
            return Err(Error::Protocol("quorum below the threshold"));
        }
        if !quorum.contains(&package.share.id) {
            return Err(Error::Protocol("this party is not in the quorum"));
        }
        if message.len() != public.bases.message.len() {
            return Err(Error::Protocol("message length does not match the base vector"));
        }
        let identity = public.pp.cl.identity().clone();
        Ok(Self {
            id: package.share.id,
            quorum: quorum.to_vec(),
            session: session.to_vec(),
            package,
            message: message.to_vec(),
            rng: fresh_rng(),
            e_i: Scalar255::from_u64(0),
            s_i: Scalar255::from_u64(0),
            gamma_i: Mpz::from(0u64),
            phi_gamma: identity.clone(),
            scaled: identity,
            e: Scalar255::from_u64(0),
            s: Scalar255::from_u64(0),
            counter: 0,
            commits: BTreeMap::new(),
            phi_gamma_all: None,
        })
    }

    fn ctx(&self, tag: &[u8], id: usize) -> Vec<u8> {
        zkp::context(&self.session, tag, id)
    }

    /// Round 1.
    pub fn commit(&mut self, meter: &mut Meter) -> SignCommitMsg {
        meter.step(Stage::SignCommit, |meter| {
            let public = &self.package.public;
            let pp = public.pp.clone();
            let class = &pp.cl;

            self.e_i = Scalar255::random(&mut rand_core::OsRng);
            self.s_i = Scalar255::random(&mut rand_core::OsRng);
            self.gamma_i = class.sample_d(&mut self.rng);

            // phi_{K^{gamma_i}} and gamma_i x^K, both long exponentiations.
            self.phi_gamma = class.exp(&public.phi_k, &self.gamma_i, meter);
            self.scaled = class.exp(&public.x_bar, &self.gamma_i, meter);

            let ctx = self.ctx(b"gamma", self.id);
            let proof = zkp::prove_dl(
                &pp,
                zkp::DOMAIN_DLS,
                &ctx,
                &public.phi_k,
                &self.phi_gamma,
                &self.gamma_i,
                class.bound_b(),
                &mut self.rng,
                meter,
            );

            let mut payload = Vec::with_capacity(64);
            wire::put_scalar(&mut payload, &self.e_i);
            wire::put_scalar(&mut payload, &self.s_i);
            let commitment = commit_hash(
                &pp,
                &self.session,
                self.id,
                DOMAIN_SIGN_COMMIT,
                &payload,
            );

            SignCommitMsg {
                id: self.id,
                commitment,
                phi_gamma: self.phi_gamma.clone(),
                proof,
            }
        })
    }

    /// Round 2: verify the encapsulation shares and aggregate `phi_{K^gamma}`.
    ///
    /// The `R_dls` proofs travel in round 1 and could be checked the moment they arrive; they
    /// are verified here because that is where this state machine first sees an inbox, which
    /// is why the round-2 line of the report carries the `(t-1)`-scaling verification cost.
    pub fn open(&mut self, inbox: &[SignCommitMsg], meter: &mut Meter) -> Result<SignOpenMsg> {
        meter.step(Stage::SignOpen, |meter| {
            let public = &self.package.public;
            let pp = public.pp.clone();
            let class = &pp.cl;
            let mut aggregate = class.identity().clone();

            for message in inbox {
                if !self.quorum.contains(&message.id) {
                    return Err(Error::Protocol("message from outside the quorum"));
                }
                // A party does not re-verify its own proof — it built it. A corrupted party
                // lying about its own encapsulation is caught by the other `t - 1` verifiers,
                // so skipping self is sound and saves one long exponentiation per signer.
                if message.id != self.id {
                    let ctx = self.ctx(b"gamma", message.id);
                    if !zkp::verify_dl(
                        &pp,
                        zkp::DOMAIN_DLS,
                        &ctx,
                        &public.phi_k,
                        &message.phi_gamma,
                        &message.proof,
                        class.bound_b(),
                        meter,
                    ) {
                        return Err(Error::Verify("gamma proof"));
                    }
                }
                aggregate = class.compose(&aggregate, &message.phi_gamma, meter);
                self.commits.insert(message.id, message.clone());
            }
            if self.commits.len() != self.quorum.len() {
                return Err(Error::Missing("round-1 messages incomplete"));
            }
            self.phi_gamma_all = Some(aggregate);

            Ok(SignOpenMsg {
                id: self.id,
                e_i: self.e_i.clone(),
                s_i: self.s_i.clone(),
            })
        })
    }

    /// Round 3.
    pub fn share(&mut self, inbox: &[SignOpenMsg], meter: &mut Meter) -> Result<SignShareMsg> {
        meter.step(Stage::SignShare, |meter| {
            let public = &self.package.public;
            let pp = public.pp.clone();
            let class = &pp.cl;

            let mut e = Scalar255::from_u64(0);
            let mut s = Scalar255::from_u64(0);
            for message in inbox {
                let commit = self
                    .commits
                    .get(&message.id)
                    .ok_or(Error::Missing("round-1 commitment missing"))?;
                let mut payload = Vec::with_capacity(64);
                wire::put_scalar(&mut payload, &message.e_i);
                wire::put_scalar(&mut payload, &message.s_i);
                let recomputed = commit_hash(
                    &pp,
                    &self.session,
                    message.id,
                    DOMAIN_SIGN_COMMIT,
                    &payload,
                );
                if recomputed != commit.commitment {
                    return Err(Error::Verify("nonce commitment does not open"));
                }
                e = e.add(&message.e_i);
                s = s.add(&message.s_i);
            }
            if inbox.len() != self.quorum.len() {
                return Err(Error::Missing("round-2 messages incomplete"));
            }
            self.e = e.clone();
            self.s = s.clone();

            let base = public.bases.big_b(&pp, &s, &self.message);
            let gamma = mpz_to_scalar(&self.gamma_i);
            let r_i = base.scale(&gamma);

            // gamma_i(x+e)^K = (gamma_i x^K) * f^{gamma_i e}
            let correction = class.f_exp(&gamma.mul(&e));
            let payload = class.compose(&self.scaled, &correction, meter);
            let numerator = class.exp(&payload, &square(&public.delta), meter);

            let alpha = self
                .package
                .seeds
                .sample(self.id, &self.quorum, &self.session, self.counter)?;
            self.counter += 1;

            let weight = public.lagrange(self.id, &self.quorum);
            let exponent = mul(&weight, &self.package.share.sk_share);
            let denominator = class.exp(
                self.phi_gamma_all
                    .as_ref()
                    .ok_or(Error::Protocol("common encapsulation missing"))?,
                &exponent,
                meter,
            );
            let masked = class.compose(&denominator, &class.f_exp(&alpha), meter);
            let inverse = class.invert(&masked, meter);
            let pd_i = class.compose(&numerator, &inverse, meter);

            Ok(SignShareMsg {
                id: self.id,
                r_i,
                pd_i,
            })
        })
    }

    /// Combine: `u = Delta^{-2} CL.Solve(prod pd_j)`, `A = (sum R_j) / u`.
    pub fn combine(
        &mut self,
        inbox: &[SignShareMsg],
        meter: &mut Meter,
    ) -> Result<Signature> {
        meter.step(Stage::SignCombine, |meter| {
            let public = &self.package.public;
            let pp = public.pp.clone();
            let class = &pp.cl;
            if inbox.len() != self.quorum.len() {
                return Err(Error::Missing("round-3 messages incomplete"));
            }

            let identity = class.identity().clone();
            let mut product = identity.clone();
            let mut r_sum = G1::identity();
            for message in inbox {
                if !self.quorum.contains(&message.id) {
                    return Err(Error::Protocol("message from outside the quorum"));
                }
                product = class.compose(&product, &message.pd_i, meter);
                r_sum = r_sum.combine(&message.r_i);
            }

            let u_prime = class.solve(&product, meter);
            let u = u_prime.mul(&public.inverse_delta_squared()?);
            let inverse = u
                .invert()
                .ok_or(Error::Arithmetic("u = gamma (x + e) is zero"))?;
            let a = r_sum.scale(&inverse);

            let signature = Signature {
                a,
                e: self.e.clone(),
                s: self.s.clone(),
            };
            let valid = meter.step(Stage::SignVerify, |_| {
                crate::bbs::verify(&pp, &public.bases, &public.x_g2, &self.message, &signature)
            });
            if !valid {
                return Err(Error::Verify("threshold signature"));
            }
            Ok(signature)
        })
    }
}
