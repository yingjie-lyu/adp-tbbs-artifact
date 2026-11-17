//! Three-round threshold BBS+: two offline rounds and one online round.

use std::collections::{BTreeMap, BTreeSet};

use bicycl::{Mpz, RandGen};

use tcl::cl::{self, Cipher, ClParameters};
use tcl::meter::{Meter, Op};
use tcl::random::fresh_rng;
use tcl::share::lagrange_scalar;
use tcl::wire::{self, Reader};
use tcl::zkp::{self, EncProof, EncStatement};
use tcl::{Error, Result};

use threshold_bbs::algebra::{Group, PairingGroup, Scalar};
use threshold_bbs::bls381::{Scalar255, G1, G2};
use threshold_bbs::hash::Transcript;
use threshold_bbs::util::mpz_to_scalar;

use crate::bbs::{self, Signature};
use crate::keys::Keys;
use crate::mta::{self, AffProof};

const ENC: &[u8] = b"offline1/enc";
const AFF: &[u8] = b"offline2/aff";

#[derive(Clone, Debug)]
pub struct Offline1Msg {
    pub id: usize,
    pub c_gamma: Cipher,
    pub enc_proof: EncProof,
    pub e_hash: [u8; 32],
    pub s_hash: [u8; 32],
}

impl Offline1Msg {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        wire::put_u64(&mut out, self.id as u64);
        self.c_gamma.encode(&mut out);
        self.enc_proof.encode(&mut out);
        wire::put_hash(&mut out, &self.e_hash);
        wire::put_hash(&mut out, &self.s_hash);
        out
    }

    pub fn decode(bytes: &[u8], cl: &ClParameters) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        let message = Self {
            id: reader.usize_id()?,
            c_gamma: Cipher::decode(&mut reader, cl)?,
            enc_proof: EncProof::decode(&mut reader)?,
            e_hash: reader.hash()?,
            s_hash: reader.hash()?,
        };
        reader.finish()?;
        Ok(message)
    }
}

#[derive(Clone, Debug)]
pub struct Offline2Msg {
    pub id: usize,
    /// `C_{alpha_{j,i}}`, keyed by the recipient `j` (encrypted under `ek_j`).
    pub c_alphas: BTreeMap<usize, Cipher>,
    /// `B_{i,j} = beta_{i,j} G_2`.
    pub b_points: BTreeMap<usize, G2>,
    /// `x_i G_2`, the relation's `R`.
    pub x_point: G2,
    pub aff_proof: AffProof,
    pub e_i: Scalar255,
    pub s_i: Scalar255,
}

impl Offline2Msg {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        wire::put_u64(&mut out, self.id as u64);
        wire::put_u16(&mut out, self.c_alphas.len());
        for (id, cipher) in &self.c_alphas {
            wire::put_u64(&mut out, *id as u64);
            cipher.encode(&mut out);
        }
        wire::put_u16(&mut out, self.b_points.len());
        for (id, point) in &self.b_points {
            wire::put_u64(&mut out, *id as u64);
            wire::put_g2(&mut out, point);
        }
        wire::put_g2(&mut out, &self.x_point);
        self.aff_proof.encode(&mut out);
        wire::put_scalar(&mut out, &self.e_i);
        wire::put_scalar(&mut out, &self.s_i);
        out
    }

    pub fn decode(bytes: &[u8], cl: &ClParameters) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        let id = reader.usize_id()?;
        let count = reader.u16()?;
        let mut c_alphas = BTreeMap::new();
        for _ in 0..count {
            let recipient = reader.usize_id()?;
            c_alphas.insert(recipient, Cipher::decode(&mut reader, cl)?);
        }
        let count = reader.u16()?;
        let mut b_points = BTreeMap::new();
        for _ in 0..count {
            let peer = reader.usize_id()?;
            b_points.insert(peer, reader.g2()?);
        }
        let message = Self {
            id,
            c_alphas,
            b_points,
            x_point: reader.g2()?,
            aff_proof: AffProof::decode(&mut reader, cl)?,
            e_i: reader.scalar()?,
            s_i: reader.scalar()?,
        };
        reader.finish()?;
        Ok(message)
    }
}

#[derive(Clone, Debug)]
pub struct OnlineMsg {
    pub id: usize,
    /// `chi_{i,j}`, keyed by `j`.
    pub chis: BTreeMap<usize, Scalar255>,
    /// `R_i = gamma_i D`.
    pub r_share: G1,
}

impl OnlineMsg {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        wire::put_u64(&mut out, self.id as u64);
        wire::put_u16(&mut out, self.chis.len());
        for (id, value) in &self.chis {
            wire::put_u64(&mut out, *id as u64);
            wire::put_scalar(&mut out, value);
        }
        wire::put_g1(&mut out, &self.r_share);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        let id = reader.usize_id()?;
        let count = reader.u16()?;
        let mut chis = BTreeMap::new();
        for _ in 0..count {
            let peer = reader.usize_id()?;
            chis.insert(peer, reader.scalar()?);
        }
        let message = Self {
            id,
            chis,
            r_share: reader.g1()?,
        };
        reader.finish()?;
        Ok(message)
    }
}

fn nonce_commit(session: &[u8], tag: &[u8], id: usize, value: &Scalar255) -> [u8; 32] {
    let mut transcript = Transcript::new(b"tx25-bbs/v01/offline1/nonce");
    transcript
        .absorb_bytes(b"sid", session)
        .absorb_bytes(b"tag", tag)
        .absorb_u64(b"id", id as u64)
        .absorb_scalar(b"value", value);
    transcript.digest32()
}

struct State {
    session: Vec<u8>,
    gamma: Scalar255,
    e_i: Scalar255,
    s_i: Scalar255,
    betas: BTreeMap<usize, Scalar255>,
    zetas: BTreeMap<usize, Scalar255>,
    e: Scalar255,
    s: Scalar255,
    quorum: Vec<usize>,
    /// `B_{i,j}` for the cheater-identification check.
    own_b_points: BTreeMap<usize, G2>,
}

/// One signer.
pub struct Signer {
    pub keys: Keys,
    rng: RandGen,
    used: BTreeSet<Vec<u8>>,
    state: Option<State>,
}

impl Signer {
    pub fn new(keys: Keys) -> Self {
        Self {
            keys,
            rng: fresh_rng(),
            used: BTreeSet::new(),
            state: None,
        }
    }

    /// Offline round 1: `C_{gamma_i}` with its `R_Enc` proof, plus the nonce commitments.
    pub fn offline1(&mut self, session: &[u8], meter: &mut Meter) -> Result<Offline1Msg> {
        meter.step("offline r1", |meter| {
            if self.used.contains(session) {
                return Err(Error::Protocol("sid already used"));
            }
            if self.state.is_some() {
                return Err(Error::Protocol("a signing session is in flight"));
            }
            self.used.insert(session.to_vec());

            let cl = &self.keys.params.cl;
            let id = self.keys.party;
            let gamma = Scalar255::random(&mut rand_core::OsRng);
            let rho = cl.sample_dq(&mut self.rng);
            let c_gamma = cl::enc_plain(cl, &self.keys.ek, &gamma, &rho, meter);

            let ctx = zkp::context(session, ENC, &[id]);
            let enc_proof = zkp::prove_enc_with_base(
                cl,
                &ctx,
                cl.gq(),
                &EncStatement {
                    ek: &self.keys.ek,
                    cipher: &c_gamma,
                    point: None,
                },
                &gamma,
                &rho,
                &mut self.rng,
                meter,
            );

            let e_i = Scalar255::random(&mut rand_core::OsRng);
            let s_i = Scalar255::random(&mut rand_core::OsRng);
            let e_hash = nonce_commit(session, b"e", id, &e_i);
            let s_hash = nonce_commit(session, b"s", id, &s_i);

            self.state = Some(State {
                session: session.to_vec(),
                gamma,
                e_i: e_i.clone(),
                s_i: s_i.clone(),
                betas: BTreeMap::new(),
                zetas: BTreeMap::new(),
                e: Scalar255::from_u64(0),
                s: Scalar255::from_u64(0),
                quorum: Vec::new(),
                own_b_points: BTreeMap::new(),
            });

            Ok(Offline1Msg {
                id,
                c_gamma,
                enc_proof,
                e_hash,
                s_hash,
            })
        })
    }

    /// Offline round 2: the affine MtA against every `C_{gamma_j}`, aggregated into one proof.
    pub fn offline2(
        &mut self,
        session: &[u8],
        quorum: &mut Vec<usize>,
        inbox: &[Offline1Msg],
        meter: &mut Meter,
    ) -> Result<Offline2Msg> {
        meter.step("offline r2", |meter| {
            let cl = &self.keys.params.cl;
            let id = self.keys.party;

            let mut valid = Vec::new();
            let mut c_gammas = BTreeMap::new();
            for candidate in inbox {
                if !quorum.contains(&candidate.id) {
                    continue;
                }
                let ctx = zkp::context(session, ENC, &[candidate.id]);
                if zkp::verify_enc_with_base(
                    cl,
                    &ctx,
                    cl.gq(),
                    &EncStatement {
                        ek: &self.keys.all_ek[&candidate.id],
                        cipher: &candidate.c_gamma,
                        point: None,
                    },
                    &candidate.enc_proof,
                    meter,
                ) {
                    valid.push(candidate.id);
                    c_gammas.insert(candidate.id, candidate.c_gamma.clone());
                }
            }
            if valid.len() < self.keys.t {
                return Err(Error::Verify("not enough valid gamma ciphertexts"));
            }
            *quorum = valid.clone();

            let k_star = mta::shift(&self.keys.x_share, cl, &mut self.rng);
            let mut c_alphas = BTreeMap::new();
            let mut b_points = BTreeMap::new();
            let mut betas = BTreeMap::new();
            for j in &valid {
                let beta = Scalar255::random(&mut rand_core::OsRng);
                let cipher = mta::aff_map(cl, &c_gammas[j], &k_star, &beta, meter);
                meter.add(Op::G2Exp);
                let point = threshold_bbs::bls381::generator_g2().scale(&beta);
                c_alphas.insert(*j, cipher);
                b_points.insert(*j, point);
                betas.insert(*j, beta);
            }

            let x_point = self.keys.x_public_share.clone();
            let ctx = zkp::context(session, AFF, &[id]);
            let (aggregated, exponents) = mta::aggregate(
                cl,
                &ctx,
                &c_gammas,
                &c_alphas,
                &b_points,
                &x_point,
                meter,
            )?;
            let beta_star = mta::weighted_beta(&betas, &exponents)?;
            let aff_proof =
                mta::prove_aff(cl, &ctx, &aggregated, &k_star, &beta_star, &mut self.rng, meter);

            let state = self
                .state
                .as_mut()
                .ok_or(Error::Protocol("no session in flight"))?;
            state.betas = betas;
            state.quorum = valid;

            let (e_i, s_i) = (state.e_i.clone(), state.s_i.clone());
            Ok(Offline2Msg {
                id,
                c_alphas,
                b_points: b_points.clone(),
                x_point,
                aff_proof,
                e_i,
                s_i,
            })
        })
    }

    /// Offline output: verify the peers, decrypt the `alpha` shares, fix `(e, s)`.
    pub fn offline_output(
        &mut self,
        session: &[u8],
        quorum: &mut Vec<usize>,
        inbox: &[Offline2Msg],
        first_round: &[Offline1Msg],
        meter: &mut Meter,
    ) -> Result<()> {
        meter.step("offline output", |meter| {
            let cl = &self.keys.params.cl;
            let id = self.keys.party;
            let t = self.keys.t;

            let mut valid = Vec::new();
            let mut e = Scalar255::from_u64(0);
            let mut s = Scalar255::from_u64(0);
            let mut zetas = BTreeMap::new();
            let mut own_b = BTreeMap::new();
            let mut c_gammas = BTreeMap::new();
            for candidate in first_round {
                c_gammas.insert(candidate.id, candidate.c_gamma.clone());
            }

            for candidate in inbox {
                if !quorum.contains(&candidate.id) {
                    continue;
                }
                // The nonce commitments must open.
                let commitment = first_round
                    .iter()
                    .find(|message| message.id == candidate.id)
                    .ok_or(Error::Missing("round-1 message"))?;
                if commitment.e_hash != nonce_commit(session, b"e", candidate.id, &candidate.e_i)
                    || commitment.s_hash
                        != nonce_commit(session, b"s", candidate.id, &candidate.s_i)
                {
                    continue;
                }
                // The batched R* proof must verify against this party's aggregated statement.
                let ctx = zkp::context(session, AFF, &[candidate.id]);
                let statement_gammas: BTreeMap<usize, Cipher> = quorum
                    .iter()
                    .filter_map(|peer| c_gammas.get(peer).map(|c| (*peer, c.clone())))
                    .collect();
                let statement_alphas: BTreeMap<usize, Cipher> = quorum
                    .iter()
                    .filter_map(|peer| {
                        candidate.c_alphas.get(peer).map(|c| (*peer, c.clone()))
                    })
                    .collect();
                let statement_bs: BTreeMap<usize, G2> = quorum
                    .iter()
                    .filter_map(|peer| candidate.b_points.get(peer).map(|b| (*peer, b.clone())))
                    .collect();
                if statement_alphas.len() != quorum.len() || statement_bs.len() != quorum.len() {
                    continue;
                }
                let (aggregated, _) = match mta::aggregate(
                    cl,
                    &ctx,
                    &statement_gammas,
                    &statement_alphas,
                    &statement_bs,
                    &candidate.x_point,
                    meter,
                ) {
                    Ok(value) => value,
                    Err(_) => continue,
                };
                if aggregated.x_point != self.keys.all_x_public[&candidate.id] {
                    continue;
                }
                if !mta::verify_aff(cl, &ctx, &aggregated, &candidate.aff_proof, meter) {
                    continue;
                }

                // zeta_{i,j} = Dec(dk_i, C_{alpha_{i,j}}) + beta_{i,j}
                let cipher = candidate
                    .c_alphas
                    .get(&id)
                    .ok_or(Error::Missing("alpha ciphertext for this party"))?;
                let alpha = cl::dec_plain(cl, &self.keys.dk, cipher, meter)?;
                let state = self
                    .state
                    .as_ref()
                    .ok_or(Error::Protocol("no session in flight"))?;
                let beta = state.betas.get(&candidate.id).copied().unwrap_or_else(|| {
                    Scalar255::from_u64(0)
                });
                zetas.insert(candidate.id, alpha.add(&beta));
                if let Some(point) = candidate.b_points.get(&id) {
                    own_b.insert(candidate.id, point.clone());
                }
                e = e.add(&candidate.e_i);
                s = s.add(&candidate.s_i);
                valid.push(candidate.id);
            }
            if valid.len() < t {
                return Err(Error::Verify("not enough valid MtA responses"));
            }
            *quorum = valid;

            let state = self
                .state
                .as_mut()
                .ok_or(Error::Protocol("no session in flight"))?;
            state.zetas = zetas;
            state.e = e;
            state.s = s;
            state.quorum = quorum.clone();
            state.own_b_points = own_b;
            Ok(())
        })
    }

    /// The single online round: `chi_{i,j}` and `R_i = gamma_i D`.
    pub fn online(
        &mut self,
        message: &[Scalar255],
        session: &[u8],
        meter: &mut Meter,
    ) -> Result<OnlineMsg> {
        meter.step("online", |meter| {
            let state = self
                .state
                .take()
                .ok_or(Error::Protocol("no session in flight"))?;
            if state.session != session {
                return Err(Error::Protocol("wrong session"));
            }
            let params = self.keys.params.clone();
            let d = bbs::big_b(&params.bases, &state.s, message)?;
            meter.add(Op::G1Exp);
            let r_share = d.scale(&state.gamma);

            // `f(0) = 0` polynomial of degree `t - 1` over the quorum.
            let coefficients: Vec<Scalar255> =
                (1..self.keys.t).map(|_| Scalar255::random(&mut rand_core::OsRng)).collect();
            let mut chis = BTreeMap::new();
            for peer in &state.quorum {
                let mut value = state.e.mul(&state.gamma);
                value = value.add(&state.zetas[peer]);
                let point = Scalar255::from_u64(*peer as u64);
                let mut power = point.clone();
                for coefficient in &coefficients {
                    value = value.add(&power.mul(coefficient));
                    power = power.mul(&point);
                }
                chis.insert(*peer, value);
            }

            self.state = Some(state);
            Ok(OnlineMsg {
                id: self.keys.party,
                chis,
                r_share,
            })
        })
    }

    /// Assemble `A`, verify, and identify cheaters if the signature does not check out.
    pub fn output(
        &mut self,
        message: &[Scalar255],
        session: &[u8],
        quorum: &mut Vec<usize>,
        inbox: &[OnlineMsg],
        meter: &mut Meter,
    ) -> Result<Signature> {
        meter.step("output", |meter| {
            let state = self
                .state
                .take()
                .ok_or(Error::Protocol("no session in flight"))?;
            if state.session != session {
                return Err(Error::Protocol("wrong session"));
            }
            let params = self.keys.params.clone();
            let d = bbs::big_b(&params.bases, &state.s, message)?;
            let mut active: Vec<usize> = quorum
                .iter()
                .copied()
                .filter(|id| inbox.iter().any(|m| m.id == *id))
                .collect();
            if active.len() < self.keys.t {
                self.state = Some(state);
                return Err(Error::Verify("not enough online shares"));
            }

            for _attempt in 0..2 {
                let signature = assemble(&active, inbox, &state.e, &state.s);
                let Some(signature) = signature else { break };
                if bbs::verify(&params.bases, &self.keys.x_public, message, &signature) {
                    *quorum = active.clone();
                    self.state = Some(state);
                    return Ok(signature);
                }
                // Cheater identification: drop every j whose T_j does not match.
                let mut kept = Vec::new();
                for j in &active {
                    let Some(message_j) = inbox.iter().find(|m| m.id == *j) else {
                        continue;
                    };
                    let mut t_point = G2::identity();
                    for nu in &active {
                        let chi = message_j.chis[nu];
                        let b_jn = state.own_b_points.get(nu).cloned().unwrap_or_else(G2::identity);
                        let b_nj = state.own_b_points.get(j).cloned().unwrap_or_else(G2::identity);
                        let value = threshold_bbs::bls381::generator_g2()
                            .scale(&chi)
                            .combine(&b_jn.inverse())
                            .combine(&b_nj);
                        meter.add(Op::G2Exp);
                        t_point = t_point.combine(&value.scale(&lagrange_scalar(*nu, &active)));
                    }
                    let g2 = threshold_bbs::bls381::generator_g2();
                    let expected = self
                        .keys
                        .x_public
                        .combine(&g2.scale(&state.e));
                    meter.add_n(Op::Pairing, 2);
                    if G1::pairing(&expected, &message_j.r_share) == G1::pairing(&t_point, &d) {
                        kept.push(*j);
                    }
                }
                if kept.len() == active.len() {
                    break;
                }
                active = kept;
                if active.len() < self.keys.t {
                    break;
                }
            }

            self.state = Some(state);
            Err(Error::Verify("threshold signature"))
        })
    }
}

fn assemble(active: &[usize], inbox: &[OnlineMsg], e: &Scalar255, s: &Scalar255) -> Option<Signature> {
    if active.len() < 2 {
        return None;
    }
    let mut numerator = G1::identity();
    let mut denominator = Scalar255::from_u64(0);
    for j in active {
        let message = inbox.iter().find(|m| m.id == *j)?;
        let weight = lagrange_scalar(*j, active);
        numerator = numerator.combine(&message.r_share.scale(&weight));
        let mut inner = Scalar255::from_u64(0);
        for nu in active {
            inner = inner.add(&message.chis.get(nu)?.mul(&lagrange_scalar(*nu, active)));
        }
        denominator = denominator.add(&weight.mul(&inner));
    }
    let inverse = denominator.invert()?;
    Some(Signature {
        a: numerator.scale(&inverse),
        e: e.clone(),
        s: s.clone(),
    })
}

/// `mpz_to_scalar` re-export for the driver's size report.
pub fn scalar_of(value: &Mpz) -> Scalar255 {
    mpz_to_scalar(value)
}
