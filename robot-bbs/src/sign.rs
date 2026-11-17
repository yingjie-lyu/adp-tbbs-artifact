//! The two-round signing protocol.

use std::collections::BTreeSet;
use std::sync::Arc;

use bicycl::{QFI, RandGen};

use tcl::cl::Cipher;
use tcl::eg::{self, EgCipher};
use tcl::meter::{Meter, Op};
use tcl::random::fresh_rng;
use tcl::share::lagrange_scalar;
use tcl::zkp::{self, ConProof, ConStatement, DdhProof, PartDecProof};
use tcl::{Error, Result, ThresholdKeys};

use threshold_bbs::algebra::{Group, Scalar};
use threshold_bbs::bls381::{Scalar255, G1};
use threshold_bbs::hash::Transcript;

use crate::bbs::{self, Bases, Signature};
use tcl::wire;

const DDH: &[u8] = b"r1/ddh";
const CON: &[u8] = b"r1/con";
const CL_PART: &[u8] = b"r2/cl";
const EG_PART: &[u8] = b"r2/eg";
const SIGN_CTX: &[u8] = b"robot-bbs/v01/sign/ctx";

#[derive(Clone, Debug)]
pub struct Round1Msg {
    pub id: usize,
    pub z_i: G1,
    pub ddh_proof: DdhProof,
    pub c_gamma: Cipher,
    pub c_gamma_x: Cipher,
    pub c_d0: EgCipher,
    pub c_d1: EgCipher,
    pub con_proof: ConProof,
}

impl Round1Msg {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        wire::put_u64(&mut out, self.id as u64);
        wire::put_g1(&mut out, &self.z_i);
        self.ddh_proof.encode(&mut out);
        self.c_gamma.encode(&mut out);
        self.c_gamma_x.encode(&mut out);
        self.c_d0.encode(&mut out);
        self.c_d1.encode(&mut out);
        self.con_proof.encode(&mut out);
        out
    }

    pub fn decode(bytes: &[u8], cl: &tcl::cl::ClParameters) -> Result<Self> {
        let mut reader = wire::Reader::new(bytes);
        let message = Self {
            id: reader.usize_id()?,
            z_i: reader.g1()?,
            ddh_proof: DdhProof::decode(&mut reader)?,
            c_gamma: Cipher::decode(&mut reader, cl)?,
            c_gamma_x: Cipher::decode(&mut reader, cl)?,
            c_d0: EgCipher::decode(&mut reader)?,
            c_d1: EgCipher::decode(&mut reader)?,
            con_proof: ConProof::decode(&mut reader)?,
        };
        reader.finish()?;
        Ok(message)
    }

    pub fn encoded_len(&self) -> usize {
        self.encode().len()
    }
}

#[derive(Clone, Debug)]
pub struct Round2Msg {
    pub id: usize,
    /// `M_i = c_0^{Delta k_i}`.
    pub cl_partial: QFI,
    pub cl_proof: PartDecProof,
    /// `M'_i = x̂_i A_1`.
    pub eg_partial: G1,
    pub eg_proof: DdhProof,
}

impl Round2Msg {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        wire::put_u64(&mut out, self.id as u64);
        wire::put_qfi(&mut out, &self.cl_partial);
        self.cl_proof.encode(&mut out);
        wire::put_g1(&mut out, &self.eg_partial);
        self.eg_proof.encode(&mut out);
        out
    }

    pub fn decode(bytes: &[u8], cl: &tcl::cl::ClParameters) -> Result<Self> {
        let mut reader = wire::Reader::new(bytes);
        let message = Self {
            id: reader.usize_id()?,
            cl_partial: reader.qfi(cl)?,
            cl_proof: PartDecProof::decode(&mut reader)?,
            eg_partial: reader.g1()?,
            eg_proof: DdhProof::decode(&mut reader)?,
        };
        reader.finish()?;
        Ok(message)
    }

    pub fn encoded_len(&self) -> usize {
        self.encode().len()
    }
}

struct Pending {
    session: Vec<u8>,
    message: [u8; 32],
    /// The signer set that passed the `pi_con` check.
    quorum: Vec<usize>,
    cipher_cl: Cipher,
    cipher_eg: EgCipher,
    e: Scalar255,
    s: Scalar255,
}

/// One signer.
pub struct Signer {
    pub keys: ThresholdKeys,
    pub bases: Bases,
    pub params: Arc<crate::bbs::PublicParameters>,
    rng: RandGen,
    pending: Option<Pending>,
    used: BTreeSet<Vec<u8>>,
}

fn message_digest(message: &[Scalar255]) -> [u8; 32] {
    let mut transcript = Transcript::new(SIGN_CTX);
    transcript.absorb_bytes(b"msg", &bbs::encode_message(message));
    transcript.digest32()
}

impl Signer {
    pub fn new(
        keys: ThresholdKeys,
        bases: Bases,
        params: Arc<crate::bbs::PublicParameters>,
    ) -> Self {
        Self {
            keys,
            bases,
            params,
            rng: fresh_rng(),
            pending: None,
            used: BTreeSet::new(),
        }
    }

    /// Round 1: VRF share, `gamma_i`, the four ciphertexts and `pi_con`.
    pub fn round1(
        &mut self,
        message: &[Scalar255],
        session: &[u8],
        meter: &mut Meter,
    ) -> Result<Round1Msg> {
        meter.step("sign r1", |meter| {
            if self.used.contains(session) {
                return Err(Error::Protocol("sid already used"));
            }
            if self.pending.is_some() {
                return Err(Error::Protocol("a signing round is in flight"));
            }
            self.used.insert(session.to_vec());

            let tc = &self.keys.tc;
            let cl = &tc.cl;
            let g1 = threshold_bbs::bls381::generator_g1();
            let id = self.keys.party;
            let shared = bbs::encode_message(message);

            // (a) VRF share and its DDH proof.
            let y = bbs::vrf_input(&shared, session);
            meter.add(Op::G1Exp);
            let z_i = y.scale(&self.keys.eg_share);
            let ctx = zkp::context(session, DDH, &[id]);
            let ddh_proof = zkp::prove_ddh(
                &ctx,
                &g1,
                &self.keys.eg_public_share,
                &y,
                &z_i,
                &self.keys.eg_share,
                &mut rand_core::OsRng,
                meter,
            );

            // (b) gamma_i, the group elements, and the four ciphertexts.
            let gamma = Scalar255::random(&mut rand_core::OsRng);
            let d = bbs::message_part(&self.bases, &self.keys.x_public, message)?;
            meter.add_n(Op::G1Exp, 2);
            let d0 = self.bases.h[0].scale(&gamma);
            let d1 = d.scale(&gamma);

            let rho = cl.sample_dq(&mut self.rng);
            let c_gamma = tc.enc(&self.keys.cl_public, &gamma, &rho, meter);
            let c_gamma_x = tc.smul_star(&gamma, &self.keys.c_x, meter);

            let r0 = Scalar255::random(&mut rand_core::OsRng);
            let r1 = Scalar255::random(&mut rand_core::OsRng);
            let c_d0 = eg::encrypt_with(&g1, &self.keys.eg_public, &d0, &r0, meter);
            let c_d1 = eg::encrypt_with(&g1, &self.keys.eg_public, &d1, &r1, meter);

            // (c) pi_con.
            let statement = ConStatement {
                ek: &self.keys.cl_public,
                c_x: &self.keys.c_x,
                c_gamma: &c_gamma,
                c_gamma_x: &c_gamma_x,
                eg_public: &self.keys.eg_public,
                h0: &self.bases.h[0],
                d: &d,
                c_d0: &c_d0,
                c_d1: &c_d1,
            };
            let ctx = zkp::context(session, CON, &[id]);
            let con_proof = zkp::prove_con(
                tc,
                &ctx,
                &statement,
                &gamma,
                &rho,
                &r0,
                &r1,
                &mut self.rng,
                meter,
            );

            Ok(Round1Msg {
                id,
                z_i,
                ddh_proof,
                c_gamma,
                c_gamma_x,
                c_d0,
                c_d1,
                con_proof,
            })
        })
    }

    /// Round 2: derive `(e, s)`, aggregate, and produce both partial decryptions.
    pub fn round2(
        &mut self,
        message: &[Scalar255],
        session: &[u8],
        quorum: &mut Vec<usize>,
        inbox: &[Round1Msg],
        meter: &mut Meter,
    ) -> Result<Round2Msg> {
        meter.step("sign r2", |meter| {
            let tc = &self.keys.tc;
            let g1 = threshold_bbs::bls381::generator_g1();
            let id = self.keys.party;

            // Nonce phase 2: verify the VRF shares and combine.
            let mut messages: Vec<&Round1Msg> = Vec::new();
            let mut valid = Vec::new();
            for candidate in inbox {
                if !quorum.contains(&candidate.id) {
                    continue;
                }
                let ctx = zkp::context(session, DDH, &[candidate.id]);
                let y = bbs::vrf_input(&bbs::encode_message(message), session);
                let public_share = self
                    .keys
                    .eg_public_shares
                    .get(&candidate.id)
                    .ok_or(Error::Missing("eg public share"))?;
                if zkp::verify_ddh(
                    &ctx,
                    &g1,
                    public_share,
                    &y,
                    &candidate.z_i,
                    &candidate.ddh_proof,
                    meter,
                ) {
                    valid.push(candidate.id);
                    messages.push(candidate);
                }
            }
            *quorum = valid.clone();
            if quorum.len() <= self.keys.t {
                return Err(Error::Verify("not enough valid VRF shares"));
            }
            meter.add_n(Op::G1Exp, quorum.len() as u64);
            let mut z = G1::identity();
            for candidate in &messages {
                z = z.combine(&candidate.z_i.scale(&lagrange_scalar(candidate.id, quorum)));
            }
            let (e, s) = bbs::nonces(&z);

            // Partially decrypting phase: verify pi_con, aggregate, build the two ciphertexts.
            let mut accepted = Vec::new();
            for candidate in &messages {
                let statement = ConStatement {
                    ek: &self.keys.cl_public,
                    c_x: &self.keys.c_x,
                    c_gamma: &candidate.c_gamma,
                    c_gamma_x: &candidate.c_gamma_x,
                    eg_public: &self.keys.eg_public,
                    h0: &self.bases.h[0],
                    d: &bbs::message_part(&self.bases, &self.keys.x_public, message)?,
                    c_d0: &candidate.c_d0,
                    c_d1: &candidate.c_d1,
                };
                let ctx = zkp::context(session, CON, &[candidate.id]);
                if zkp::verify_con(tc, &ctx, &statement, &candidate.con_proof, meter) {
                    accepted.push(*candidate);
                }
            }
            if accepted.len() <= self.keys.t {
                return Err(Error::Verify("not enough consistent ciphertexts"));
            }
            *quorum = accepted.iter().map(|message| message.id).collect();

            let c_gamma = tc.add_many(
                &accepted.iter().map(|m| m.c_gamma.clone()).collect::<Vec<_>>(),
                meter,
            );
            let c_gamma_x = tc.add_many(
                &accepted.iter().map(|m| m.c_gamma_x.clone()).collect::<Vec<_>>(),
                meter,
            );
            let c_d0 = eg::add_many(&accepted.iter().map(|m| m.c_d0.clone()).collect::<Vec<_>>());
            let c_d1 = eg::add_many(&accepted.iter().map(|m| m.c_d1.clone()).collect::<Vec<_>>());

            // C_{gamma x + gamma e} and C_{s D_0 + D_1}.
            let scaled_e = tc.smul_star(&e, &c_gamma, meter);
            let cipher_cl = tc.add(&c_gamma_x, &scaled_e, meter);
            let scaled_s = eg::smul_star(&s, &c_d0, meter);
            let cipher_eg = eg::add(&scaled_s, &c_d1);

            // Partial decryptions.
            let cl_partial = tc.part_dec(&cipher_cl, &self.keys.cl_share, meter);
            let ctx = zkp::context(session, CL_PART, &[id]);
            let cl_proof = zkp::prove_part_dec(
                tc,
                &ctx,
                &self.keys.cl_public_share,
                &cipher_cl.c0,
                &cl_partial,
                &self.keys.cl_share,
                &mut self.rng,
                meter,
            );
            let eg_partial = eg::part_dec(&self.keys.eg_share, &cipher_eg, meter);
            let ctx = zkp::context(session, EG_PART, &[id]);
            let eg_proof = zkp::prove_ddh(
                &ctx,
                &g1,
                &self.keys.eg_public_share,
                &cipher_eg.a1,
                &eg_partial,
                &self.keys.eg_share,
                &mut rand_core::OsRng,
                meter,
            );

            self.pending = Some(Pending {
                session: session.to_vec(),
                message: message_digest(message),
                quorum: quorum.clone(),
                cipher_cl,
                cipher_eg,
                e: e.clone(),
                s: s.clone(),
            });

            Ok(Round2Msg {
                id,
                cl_partial,
                cl_proof,
                eg_partial,
                eg_proof,
            })
        })
    }

    /// Output: combine both partial decryptions and divide.
    pub fn output(
        &mut self,
        message: &[Scalar255],
        session: &[u8],
        inbox: &[Round2Msg],
        meter: &mut Meter,
    ) -> Result<Signature> {
        meter.step("sign output", |meter| {
            let pending = self
                .pending
                .take()
                .ok_or(Error::Protocol("no signing round in flight"))?;
            if pending.session != session || pending.message != message_digest(message) {
                return Err(Error::Protocol("round 2 answers a different session"));
            }
            let tc = &self.keys.tc;
            let g1 = threshold_bbs::bls381::generator_g1();

            let mut valid = Vec::new();
            let mut cl_partials = Vec::new();
            let mut eg_partials = std::collections::BTreeMap::new();
            for candidate in inbox {
                if !pending.quorum.contains(&candidate.id) {
                    continue;
                }
                let public_share = self
                    .keys
                    .cl_public_shares
                    .get(&candidate.id)
                    .ok_or(Error::Missing("cl public share"))?;
                let ctx = zkp::context(session, CL_PART, &[candidate.id]);
                let cl_ok = zkp::verify_part_dec(
                    tc,
                    &ctx,
                    public_share,
                    &pending.cipher_cl.c0,
                    &candidate.cl_partial,
                    &candidate.cl_proof,
                    meter,
                );
                let eg_share = self
                    .keys
                    .eg_public_shares
                    .get(&candidate.id)
                    .ok_or(Error::Missing("eg public share"))?;
                let ctx = zkp::context(session, EG_PART, &[candidate.id]);
                let eg_ok = zkp::verify_ddh(
                    &ctx,
                    &g1,
                    eg_share,
                    &pending.cipher_eg.a1,
                    &candidate.eg_partial,
                    &candidate.eg_proof,
                    meter,
                );
                if cl_ok && eg_ok {
                    valid.push(candidate.id);
                    cl_partials.push((candidate.id, candidate.cl_partial.clone()));
                    eg_partials.insert(candidate.id, candidate.eg_partial.clone());
                }
            }
            if valid.len() <= self.keys.t {
                return Err(Error::Verify("not enough valid partial decryptions"));
            }

            let a = tc.combine(&pending.cipher_cl, &cl_partials, &valid, meter)?;
            let inverse = a
                .invert()
                .ok_or(Error::Arithmetic("gamma (x + e) = 0"))?;
            let r = eg::combine(&pending.cipher_eg, &eg_partials, &valid, meter);
            meter.add(Op::G1Exp);
            let signature = Signature {
                a: r.scale(&inverse),
                e: pending.e,
                s: pending.s,
            };
            if !bbs::verify(&self.bases, &self.keys.x_public, message, &signature) {
                return Err(Error::Verify("threshold signature"));
            }
            Ok(signature)
        })
    }
}

/// `encode_message` is used by the tests to bind the transcript.
pub fn encode_message(message: &[Scalar255]) -> Vec<u8> {
    bbs::encode_message(message)
}
