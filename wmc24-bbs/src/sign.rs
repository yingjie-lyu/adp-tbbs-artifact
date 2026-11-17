//! The four-round threshold BBS+ signing protocol.
//!
//! Round `k` here is the paper's `Step 2k-1` broadcast; the `Step 2k` aggregation is what the
//! next call does before it produces its own message.

use std::collections::BTreeSet;
use std::sync::Arc;

use bicycl::{QFI, RandGen};

use tcl::cl::Cipher;
use tcl::eg::{self, EgCipher};
use tcl::meter::{Meter, Op};
use tcl::random::fresh_rng;
use tcl::zkp::{self, DdhProof, ElClProof, ElClStatement, EncProof, EncStatement, PartDecProof};
use tcl::{Error, Result, ThresholdKeys};

use threshold_bbs::algebra::{Group, Scalar};
use threshold_bbs::bls381::{Scalar255, G1};
use threshold_bbs::hash::Transcript;

use crate::bbs::{self, PublicParameters, Signature};
use tcl::wire::{self, Reader};

const ENC_E: &[u8] = b"r1/enc-e";
const ENC_S: &[u8] = b"r1/enc-s";
const PART_E: &[u8] = b"r2/part-e";
const PART_S: &[u8] = b"r2/part-s";
const ELCL: &[u8] = b"r3/el-cl";
const PART_GX: &[u8] = b"r4/cl";
const PART_DG: &[u8] = b"r4/eg";
const SIGN_CTX: &[u8] = b"wmc24-bbs/v01/sign/ctx";

#[derive(Clone, Debug)]
pub struct Round1Msg {
    pub id: usize,
    pub c_e: Cipher,
    pub c_s: Cipher,
    pub proof_e: EncProof,
    pub proof_s: EncProof,
}

impl Round1Msg {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        wire::put_u64(&mut out, self.id as u64);
        self.c_e.encode(&mut out);
        self.c_s.encode(&mut out);
        self.proof_e.encode(&mut out);
        self.proof_s.encode(&mut out);
        out
    }

    pub fn decode(bytes: &[u8], cl: &tcl::cl::ClParameters) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        let message = Self {
            id: reader.usize_id()?,
            c_e: Cipher::decode(&mut reader, cl)?,
            c_s: Cipher::decode(&mut reader, cl)?,
            proof_e: EncProof::decode(&mut reader)?,
            proof_s: EncProof::decode(&mut reader)?,
        };
        reader.finish()?;
        Ok(message)
    }
}

#[derive(Clone, Debug)]
pub struct Round2Msg {
    pub id: usize,
    pub partial_e: QFI,
    pub proof_e: PartDecProof,
    pub partial_s: QFI,
    pub proof_s: PartDecProof,
}

impl Round2Msg {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        wire::put_u64(&mut out, self.id as u64);
        wire::put_qfi(&mut out, &self.partial_e);
        self.proof_e.encode(&mut out);
        wire::put_qfi(&mut out, &self.partial_s);
        self.proof_s.encode(&mut out);
        out
    }

    pub fn decode(bytes: &[u8], cl: &tcl::cl::ClParameters) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        let message = Self {
            id: reader.usize_id()?,
            partial_e: reader.qfi(cl)?,
            proof_e: PartDecProof::decode(&mut reader)?,
            partial_s: reader.qfi(cl)?,
            proof_s: PartDecProof::decode(&mut reader)?,
        };
        reader.finish()?;
        Ok(message)
    }
}

#[derive(Clone, Debug)]
pub struct Round3Msg {
    pub id: usize,
    pub c_gamma: Cipher,
    pub c_dgamma: EgCipher,
    pub c_gamma_x: Cipher,
    pub proof: ElClProof,
}

impl Round3Msg {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        wire::put_u64(&mut out, self.id as u64);
        self.c_gamma.encode(&mut out);
        self.c_dgamma.encode(&mut out);
        self.c_gamma_x.encode(&mut out);
        self.proof.encode(&mut out);
        out
    }

    pub fn decode(bytes: &[u8], cl: &tcl::cl::ClParameters) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        let message = Self {
            id: reader.usize_id()?,
            c_gamma: Cipher::decode(&mut reader, cl)?,
            c_dgamma: EgCipher::decode(&mut reader)?,
            c_gamma_x: Cipher::decode(&mut reader, cl)?,
            proof: ElClProof::decode(&mut reader)?,
        };
        reader.finish()?;
        Ok(message)
    }
}

#[derive(Clone, Debug)]
pub struct Round4Msg {
    pub id: usize,
    pub partial_dgamma: G1,
    pub proof_eg: DdhProof,
    pub partial_gamma_x: QFI,
    pub proof_cl: PartDecProof,
}

impl Round4Msg {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        wire::put_u64(&mut out, self.id as u64);
        wire::put_g1(&mut out, &self.partial_dgamma);
        self.proof_eg.encode(&mut out);
        wire::put_qfi(&mut out, &self.partial_gamma_x);
        self.proof_cl.encode(&mut out);
        out
    }

    pub fn decode(bytes: &[u8], cl: &tcl::cl::ClParameters) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        let message = Self {
            id: reader.usize_id()?,
            partial_dgamma: reader.g1()?,
            proof_eg: DdhProof::decode(&mut reader)?,
            partial_gamma_x: reader.qfi(cl)?,
            proof_cl: PartDecProof::decode(&mut reader)?,
        };
        reader.finish()?;
        Ok(message)
    }
}

struct State {
    session: Vec<u8>,
    message: [u8; 32],
    quorum: Vec<usize>,
    agg_e: Cipher,
    agg_s: Cipher,
    x_plus_e: Cipher,
    e: Scalar255,
    s: Scalar255,
    /// `D = g_1 h_0^s prod h_k^{m_k}`, fixed once `s` is known.
    d: G1,
    agg_gamma_x: Cipher,
    agg_dgamma: EgCipher,
}

fn message_digest(message: &[Scalar255]) -> [u8; 32] {
    let mut transcript = Transcript::new(SIGN_CTX);
    transcript.absorb_bytes(b"msg", &bbs::encode_message(message));
    transcript.digest32()
}

/// One signer.
pub struct Signer {
    pub keys: ThresholdKeys,
    pub params: Arc<PublicParameters>,
    rng: RandGen,
    used: BTreeSet<Vec<u8>>,
    state: Option<State>,
}

impl Signer {
    pub fn new(keys: ThresholdKeys, params: Arc<PublicParameters>) -> Self {
        Self {
            keys,
            params,
            rng: fresh_rng(),
            used: BTreeSet::new(),
            state: None,
        }
    }

    fn empty_cipher(&self) -> Cipher {
        Cipher {
            c0: self.keys.tc.cl.identity().clone(),
            c1: self.keys.tc.cl.identity().clone(),
        }
    }

    /// Step 1: encrypt `e_i` and `s_i` under the threshold CL key.
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
            if self.state.is_some() {
                return Err(Error::Protocol("a signing session is in flight"));
            }
            if message.len() != self.params.message_len {
                return Err(Error::Protocol("message length"));
            }
            self.used.insert(session.to_vec());

            let tc = &self.keys.tc;
            let cl = &tc.cl;
            let id = self.keys.party;

            let e_share = Scalar255::random(&mut rand_core::OsRng);
            let s_share = Scalar255::random(&mut rand_core::OsRng);
            let rho_e = cl.sample_dq(&mut self.rng);
            let rho_s = cl.sample_dq(&mut self.rng);
            let c_e = tc.enc(&self.keys.cl_public, &e_share, &rho_e, meter);
            let c_s = tc.enc(&self.keys.cl_public, &s_share, &rho_s, meter);

            let ctx = zkp::context(session, ENC_E, &[id]);
            let proof_e = zkp::prove_enc(
                tc,
                &ctx,
                &EncStatement {
                    ek: &self.keys.cl_public,
                    cipher: &c_e,
                    point: None,
                },
                &e_share,
                &rho_e,
                &mut self.rng,
                meter,
            );
            let ctx = zkp::context(session, ENC_S, &[id]);
            let proof_s = zkp::prove_enc(
                tc,
                &ctx,
                &EncStatement {
                    ek: &self.keys.cl_public,
                    cipher: &c_s,
                    point: None,
                },
                &s_share,
                &rho_s,
                &mut self.rng,
                meter,
            );

            let empty = self.empty_cipher();
            self.state = Some(State {
                session: session.to_vec(),
                message: message_digest(message),
                quorum: Vec::new(),
                agg_e: empty.clone(),
                agg_s: empty.clone(),
                x_plus_e: empty,
                e: Scalar255::from_u64(0),
                s: Scalar255::from_u64(0),
                d: G1::identity(),
                agg_gamma_x: self.empty_cipher(),
                agg_dgamma: EgCipher {
                    a1: G1::identity(),
                    a2: G1::identity(),
                },
            });

            Ok(Round1Msg {
                id,
                c_e,
                c_s,
                proof_e,
                proof_s,
            })
        })
    }

    /// Steps 2 and 3: aggregate, form `x+e`, and partially decrypt `ebar` and `sbar`.
    pub fn round2(
        &mut self,
        session: &[u8],
        quorum: &mut Vec<usize>,
        inbox: &[Round1Msg],
        meter: &mut Meter,
    ) -> Result<Round2Msg> {
        meter.step("sign r2", |meter| {
            let tc = &self.keys.tc;
            let id = self.keys.party;

            let mut valid = Vec::new();
            let mut e_ciphers = Vec::new();
            let mut s_ciphers = Vec::new();
            for candidate in inbox {
                if !quorum.contains(&candidate.id) {
                    continue;
                }
                let ctx = zkp::context(session, ENC_E, &[candidate.id]);
                let e_ok = zkp::verify_enc(
                    tc,
                    &ctx,
                    &EncStatement {
                        ek: &self.keys.cl_public,
                        cipher: &candidate.c_e,
                        point: None,
                    },
                    &candidate.proof_e,
                    meter,
                );
                let ctx = zkp::context(session, ENC_S, &[candidate.id]);
                let s_ok = zkp::verify_enc(
                    tc,
                    &ctx,
                    &EncStatement {
                        ek: &self.keys.cl_public,
                        cipher: &candidate.c_s,
                        point: None,
                    },
                    &candidate.proof_s,
                    meter,
                );
                if e_ok && s_ok {
                    valid.push(candidate.id);
                    e_ciphers.push(candidate.c_e.clone());
                    s_ciphers.push(candidate.c_s.clone());
                }
            }
            if valid.len() < self.keys.t {
                return Err(Error::Verify("not enough valid nonce ciphertexts"));
            }
            *quorum = valid.clone();

            let agg_e = tc.add_many(&e_ciphers, meter);
            let agg_s = tc.add_many(&s_ciphers, meter);
            let x_plus_e = tc.add(&self.keys.c_x, &agg_e, meter);

            let partial_e = tc.part_dec(&agg_e, &self.keys.cl_share, meter);
            let ctx = zkp::context(session, PART_E, &[id]);
            let proof_e = zkp::prove_part_dec(
                tc,
                &ctx,
                &self.keys.cl_public_share,
                &agg_e.c0,
                &partial_e,
                &self.keys.cl_share,
                &mut self.rng,
                meter,
            );
            let partial_s = tc.part_dec(&agg_s, &self.keys.cl_share, meter);
            let ctx = zkp::context(session, PART_S, &[id]);
            let proof_s = zkp::prove_part_dec(
                tc,
                &ctx,
                &self.keys.cl_public_share,
                &agg_s.c0,
                &partial_s,
                &self.keys.cl_share,
                &mut self.rng,
                meter,
            );

            let state = self
                .state
                .as_mut()
                .ok_or(Error::Protocol("no signing session in flight"))?;
            state.agg_e = agg_e;
            state.agg_s = agg_s;
            state.x_plus_e = x_plus_e;
            state.quorum = valid;

            Ok(Round2Msg {
                id,
                partial_e,
                proof_e,
                partial_s,
                proof_s,
            })
        })
    }

    /// Steps 4 and 5: extract `e, s`, build `D`, and publish the three `gamma_i` ciphertexts.
    pub fn round3(
        &mut self,
        message: &[Scalar255],
        session: &[u8],
        quorum: &mut Vec<usize>,
        inbox: &[Round2Msg],
        meter: &mut Meter,
    ) -> Result<Round3Msg> {
        meter.step("sign r3", |meter| {
            let mut state = self
                .state
                .take()
                .ok_or(Error::Protocol("no signing session in flight"))?;
            if state.session != session || state.message != message_digest(message) {
                self.state = Some(state);
                return Err(Error::Protocol("round 2 answers a different session"));
            }

            let tc = &self.keys.tc;
            let cl = &tc.cl;
            let id = self.keys.party;
            let g1 = threshold_bbs::bls381::generator_g1();

            let mut valid = Vec::new();
            let mut e_partials = Vec::new();
            let mut s_partials = Vec::new();
            for candidate in inbox {
                if !quorum.contains(&candidate.id) {
                    continue;
                }
                let public_share = self
                    .keys
                    .cl_public_shares
                    .get(&candidate.id)
                    .ok_or(Error::Missing("cl public share"))?;
                let ctx = zkp::context(session, PART_E, &[candidate.id]);
                let e_ok = zkp::verify_part_dec(
                    tc,
                    &ctx,
                    public_share,
                    &state.agg_e.c0,
                    &candidate.partial_e,
                    &candidate.proof_e,
                    meter,
                );
                let ctx = zkp::context(session, PART_S, &[candidate.id]);
                let s_ok = zkp::verify_part_dec(
                    tc,
                    &ctx,
                    public_share,
                    &state.agg_s.c0,
                    &candidate.partial_s,
                    &candidate.proof_s,
                    meter,
                );
                if e_ok && s_ok {
                    valid.push(candidate.id);
                    e_partials.push((candidate.id, candidate.partial_e.clone()));
                    s_partials.push((candidate.id, candidate.partial_s.clone()));
                }
            }
            if valid.len() < self.keys.t {
                self.state = Some(state);
                return Err(Error::Verify("not enough valid partial decryptions"));
            }
            *quorum = valid.clone();

            let e = tc.combine(&state.agg_e, &e_partials, &valid, meter)?;
            let s = tc.combine(&state.agg_s, &s_partials, &valid, meter)?;
            let d = self.params.big_d(&s, message)?;

            // gamma_i and the three ciphertexts.
            let gamma = Scalar255::random(&mut rand_core::OsRng);
            let rho = cl.sample_dq(&mut self.rng);
            let c_gamma = tc.enc(&self.keys.cl_public, &gamma, &rho, meter);
            meter.add(Op::G1Exp);
            let gamma_d = d.scale(&gamma);
            let r0 = Scalar255::random(&mut rand_core::OsRng);
            let c_dgamma = eg::encrypt_with(&g1, &self.keys.eg_public, &gamma_d, &r0, meter);
            let c_gamma_x = tc.smul_star(&gamma, &state.x_plus_e, meter);

            let statement = ElClStatement {
                elek: &self.keys.eg_public,
                d: &d,
                eg: &c_dgamma,
                c_k: &state.x_plus_e,
                c_gk: &c_gamma_x,
            };
            let ctx = zkp::context(session, ELCL, &[id]);
            let proof = zkp::prove_el_cl(tc, &ctx, &statement, &gamma, &r0, &mut self.rng, meter);

            state.e = e;
            state.s = s;
            state.d = d;
            state.quorum = valid;
            self.state = Some(state);

            Ok(Round3Msg {
                id,
                c_gamma,
                c_dgamma,
                c_gamma_x,
                proof,
            })
        })
    }

    /// Steps 6 and 7: aggregate and partially decrypt `D^gamma` and `gamma(x+e)`.
    pub fn round4(
        &mut self,
        session: &[u8],
        quorum: &mut Vec<usize>,
        inbox: &[Round3Msg],
        meter: &mut Meter,
    ) -> Result<Round4Msg> {
        meter.step("sign r4", |meter| {
            let mut state = self
                .state
                .take()
                .ok_or(Error::Protocol("no signing session in flight"))?;
            let tc = &self.keys.tc;
            let id = self.keys.party;
            let g1 = threshold_bbs::bls381::generator_g1();

            let mut valid = Vec::new();
            let mut gamma_ciphers = Vec::new();
            let mut dgamma_ciphers = Vec::new();
            let mut gamma_x_ciphers = Vec::new();
            for candidate in inbox {
                if !quorum.contains(&candidate.id) {
                    continue;
                }
                let statement = ElClStatement {
                    elek: &self.keys.eg_public,
                    d: &state.d,
                    eg: &candidate.c_dgamma,
                    c_k: &state.x_plus_e,
                    c_gk: &candidate.c_gamma_x,
                };
                let ctx = zkp::context(session, ELCL, &[candidate.id]);
                if zkp::verify_el_cl(tc, &ctx, &statement, &candidate.proof, meter) {
                    valid.push(candidate.id);
                    gamma_ciphers.push(candidate.c_gamma.clone());
                    dgamma_ciphers.push(candidate.c_dgamma.clone());
                    gamma_x_ciphers.push(candidate.c_gamma_x.clone());
                }
            }
            if valid.len() < self.keys.t {
                self.state = Some(state);
                return Err(Error::Verify("not enough valid gamma ciphertexts"));
            }
            *quorum = valid.clone();

            // `C_gamma` has no consumer in the BBS+ flow; it is aggregated because step 6 of
            // the paper does.
            let _c_gamma = tc.add_many(&gamma_ciphers, meter);
            let agg_dgamma = eg::add_many(&dgamma_ciphers);
            let agg_gamma_x = tc.add_many(&gamma_x_ciphers, meter);

            let partial_gamma_x = tc.part_dec(&agg_gamma_x, &self.keys.cl_share, meter);
            let ctx = zkp::context(session, PART_GX, &[id]);
            let proof_cl = zkp::prove_part_dec(
                tc,
                &ctx,
                &self.keys.cl_public_share,
                &agg_gamma_x.c0,
                &partial_gamma_x,
                &self.keys.cl_share,
                &mut self.rng,
                meter,
            );
            let partial_dgamma = eg::part_dec(&self.keys.eg_share, &agg_dgamma, meter);
            let ctx = zkp::context(session, PART_DG, &[id]);
            let proof_eg = zkp::prove_ddh(
                &ctx,
                &g1,
                &self.keys.eg_public_share,
                &agg_dgamma.a1,
                &partial_dgamma,
                &self.keys.eg_share,
                &mut rand_core::OsRng,
                meter,
            );

            state.agg_gamma_x = agg_gamma_x;
            state.agg_dgamma = agg_dgamma;
            state.quorum = valid;
            self.state = Some(state);

            Ok(Round4Msg {
                id,
                partial_dgamma,
                proof_eg,
                partial_gamma_x,
                proof_cl,
            })
        })
    }

    /// Step 8: combine both decryptions and output `A = D^gamma / (gamma(x+e))`.
    pub fn output(
        &mut self,
        session: &[u8],
        inbox: &[Round4Msg],
        meter: &mut Meter,
    ) -> Result<Signature> {
        meter.step("sign output", |meter| {
            let state = self
                .state
                .take()
                .ok_or(Error::Protocol("no signing round in flight"))?;
            if state.session != session {
                return Err(Error::Protocol("round 4 answers a different session"));
            }
            let tc = &self.keys.tc;
            let g1 = threshold_bbs::bls381::generator_g1();

            let mut valid = Vec::new();
            let mut cl_partials = Vec::new();
            let mut eg_partials = std::collections::BTreeMap::new();
            for candidate in inbox {
                if !state.quorum.contains(&candidate.id) {
                    continue;
                }
                let cl_share = self
                    .keys
                    .cl_public_shares
                    .get(&candidate.id)
                    .ok_or(Error::Missing("cl public share"))?;
                let ctx = zkp::context(session, PART_GX, &[candidate.id]);
                let cl_ok = zkp::verify_part_dec(
                    tc,
                    &ctx,
                    cl_share,
                    &state.agg_gamma_x.c0,
                    &candidate.partial_gamma_x,
                    &candidate.proof_cl,
                    meter,
                );
                let eg_share = self
                    .keys
                    .eg_public_shares
                    .get(&candidate.id)
                    .ok_or(Error::Missing("eg public share"))?;
                let ctx = zkp::context(session, PART_DG, &[candidate.id]);
                let eg_ok = zkp::verify_ddh(
                    &ctx,
                    &g1,
                    eg_share,
                    &state.agg_dgamma.a1,
                    &candidate.partial_dgamma,
                    &candidate.proof_eg,
                    meter,
                );
                if cl_ok && eg_ok {
                    valid.push(candidate.id);
                    cl_partials.push((candidate.id, candidate.partial_gamma_x.clone()));
                    eg_partials.insert(candidate.id, candidate.partial_dgamma.clone());
                }
            }
            if valid.len() < self.keys.t {
                return Err(Error::Verify("not enough valid partial decryptions"));
            }

            let numerator = eg::combine(&state.agg_dgamma, &eg_partials, &valid, meter);
            let denominator = tc.combine(&state.agg_gamma_x, &cl_partials, &valid, meter)?;
            let inverse = denominator
                .invert()
                .ok_or(Error::Arithmetic("gamma (x + e) = 0"))?;
            meter.add(Op::G1Exp);
            Ok(Signature {
                a: numerator.scale(&inverse),
                e: state.e,
                s: state.s,
            })
        })
    }
}
