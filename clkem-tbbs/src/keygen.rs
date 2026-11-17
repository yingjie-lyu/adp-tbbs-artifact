//! Key generation: the CL-KEM DKG (Fig. 6) and the BBS+ verifying key (Fig. 7).
//!
//! Round layout, with the paper's numbering in brackets:
//!
//! 1. seed commit — `H(beta_i)` for the pairwise zero-sharing seeds;
//! 2. seed open — `beta_i`, so every pair can derive `beta_{i,j}`;
//! 3. PVSS — `v_i <- D_q`, `C_{i,0..t-1}` broadcast with `R_dlc` proofs, shares `y_{i,j}`
//!    sent privately and checked with `SScheck_j`   [paper round 3];
//! 4. `D_i`, encapsulation, commit to `(phi_{K_i}, x_i^K, H_i, X_i)`   [paper round 4];
//! 5. open the commitment and prove `R_enc`   [paper round 5].
//!
//! The CL secret key `sk = sum_i v_i` only ever exists as the shares `sk_i = sum_j y_{j,i}`;
//! the BBS+ signing key `x = sum_i x_i` only ever exists inside `x^K = prod_i x_i^{K_i}`.
//! Neither is recoverable from any single party's state.
//!
//! The commitments are `H(payload)` with no blinding nonce. That is enough here: the round-4
//! payload already contains `g_q^{r_i}` and `pk^{r_i} f^{x_i}` with fresh `r_i`, so it hides
//! `x_i` on its own, and what commit-and-release has to buy is *unbiasedness* — the ability
//! to fix your contribution before seeing everyone else's — not hiding.

use std::collections::BTreeMap;
use std::sync::Arc;

use bicycl::{Mpz, QFI, RandGen};

use threshold_bbs::algebra::{Group, Scalar};
use threshold_bbs::bls381::{Scalar255, G2};
use threshold_bbs::hash::Transcript;

use crate::cl::{self, ClParameters};
use crate::error::{Error, Result};
use crate::params::{Bases, PublicParameters};
use crate::pvss::{self, Deal};
use crate::random::{fresh_rng, seed32};
use crate::stats::{Meter, Stage};
use crate::util::{add, factorial, index_pow, mul, pow, square};
use crate::wire::{self, Reader};
use crate::zero::Seeds;
use crate::zkp::{self, DlProof, EncProof};

pub const DOMAIN_SEED_COMMIT: &[u8] = b"clkem-tbbs/v01/keygen/seed-commit";
pub const DOMAIN_KEY_COMMIT: &[u8] = b"clkem-tbbs/v01/keygen/commit";
pub const DOMAIN_KEY_D: &[u8] = b"clkem-tbbs/v01/keygen/d-share";
pub const DOMAIN_KEY_ENC: &[u8] = b"clkem-tbbs/v01/keygen/enc";

/// The verifying key `(X, H)` plus the public CL-KEM material.
#[derive(Clone)]
pub struct KeyPublic {
    pub pp: Arc<PublicParameters>,
    /// `pk = prod_i C_{i,0} = g_q^{sk}`.
    pub pk: QFI,
    /// `phi_K = prod_i phi_{K_i}`.
    pub phi_k: QFI,
    /// `x^K = prod_i x_i^{K_i}`, the signing key under `K = Decap(sk, phi_K)`.
    pub x_bar: QFI,
    /// `X = sum_i X_i`.
    pub x_g2: G2,
    /// `H = sum_i H_i`.
    pub bases: Bases,
    pub n: usize,
    pub t: usize,
    /// `Delta = n!`.
    pub delta: Mpz,
}

impl KeyPublic {
    /// `Delta L_i^T(0)`, the signature-share weight of party `id`.
    pub fn lagrange(&self, id: usize, quorum: &[usize]) -> Mpz {
        pvss::delta_lagrange(&self.delta, id, quorum)
    }

    /// `Delta^{-2} mod q`.
    pub fn inverse_delta_squared(&self) -> Result<Scalar255> {
        let delta = threshold_bbs::util::mpz_to_scalar(&self.delta);
        let inverse = delta
            .invert()
            .ok_or(Error::Arithmetic("Delta is not invertible mod q"))?;
        Ok(inverse.mul(&inverse))
    }
}

/// A party's share of the CL secret key.
#[derive(Clone)]
pub struct KeyShare {
    pub id: usize,
    /// `sk_i = sum_j y_{j,i}`, an integer share of `sk`.
    pub sk_share: Mpz,
    /// `D_i = g_qDelta^{sk_i}`, published so the share is checkable and extractable.
    pub d_i: QFI,
}

/// Everything a party needs to sign.
#[derive(Clone)]
pub struct KeyPackage {
    pub public: Arc<KeyPublic>,
    pub share: KeyShare,
    pub seeds: Seeds,
}

// ---------------------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct SeedCommitMsg {
    pub id: usize,
    pub commitment: [u8; 32],
}

impl SeedCommitMsg {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(40);
        wire::put_u64(&mut out, self.id as u64);
        wire::put_hash(&mut out, &self.commitment);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        let message = Self {
            id: reader.usize_id()?,
            commitment: reader.hash()?,
        };
        reader.finish()?;
        Ok(message)
    }
}

#[derive(Clone, Debug)]
pub struct SeedOpenMsg {
    pub id: usize,
    pub contribution: [u8; 32],
}

impl SeedOpenMsg {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(40);
        wire::put_u64(&mut out, self.id as u64);
        wire::put_hash(&mut out, &self.contribution);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        let message = Self {
            id: reader.usize_id()?,
            contribution: reader.hash()?,
        };
        reader.finish()?;
        Ok(message)
    }
}

/// Round 3 broadcast: `C_{i,0..t-1}` with their `R_dlc` proofs.
#[derive(Clone, Debug)]
pub struct PvssMsg {
    pub id: usize,
    pub commitments: Vec<QFI>,
    pub proofs: Vec<DlProof>,
}

impl PvssMsg {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        wire::put_u64(&mut out, self.id as u64);
        wire::put_u16(&mut out, self.commitments.len());
        for commitment in &self.commitments {
            wire::put_qfi(&mut out, commitment);
        }
        for proof in &self.proofs {
            proof.encode(&mut out);
        }
        out
    }

    pub fn decode(bytes: &[u8], cl: &ClParameters) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        let id = reader.usize_id()?;
        let count = reader.u16()?;
        if count == 0 || count > 1024 {
            return Err(Error::Wire("implausible PVSS commitment count"));
        }
        let mut commitments = Vec::with_capacity(count);
        for _ in 0..count {
            commitments.push(reader.qfi(cl)?);
        }
        let mut proofs = Vec::with_capacity(count);
        for _ in 0..count {
            proofs.push(DlProof::decode(&mut reader)?);
        }
        reader.finish()?;
        Ok(Self {
            id,
            commitments,
            proofs,
        })
    }
}

/// Round 3 private channel: dealer `from`'s share for the recipient.
#[derive(Clone, Debug)]
pub struct ShareMsg {
    pub from: usize,
    pub share: Mpz,
}

impl ShareMsg {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        wire::put_u64(&mut out, self.from as u64);
        wire::put_mpz(&mut out, &self.share);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        let message = Self {
            from: reader.usize_id()?,
            share: reader.mpz()?,
        };
        reader.finish()?;
        Ok(message)
    }
}

/// Round 4: `D_i` with its proof, plus a commitment to the BBS+ contribution.
#[derive(Clone, Debug)]
pub struct KeygenCommitMsg {
    pub id: usize,
    pub d_i: QFI,
    pub d_proof: DlProof,
    pub commitment: [u8; 32],
}

impl KeygenCommitMsg {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        wire::put_u64(&mut out, self.id as u64);
        wire::put_qfi(&mut out, &self.d_i);
        self.d_proof.encode(&mut out);
        wire::put_hash(&mut out, &self.commitment);
        out
    }

    pub fn decode(bytes: &[u8], cl: &ClParameters) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        let message = Self {
            id: reader.usize_id()?,
            d_i: reader.qfi(cl)?,
            d_proof: DlProof::decode(&mut reader)?,
            commitment: reader.hash()?,
        };
        reader.finish()?;
        Ok(message)
    }
}

/// Round 5: the opened BBS+ contribution and its `R_enc` proof.
#[derive(Clone, Debug)]
pub struct KeygenOpenMsg {
    pub id: usize,
    pub phi_i: QFI,
    pub x_bar_i: QFI,
    pub x_g2_i: G2,
    pub bases_i: Bases,
    pub enc_proof: EncProof,
}

impl KeygenOpenMsg {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        wire::put_u64(&mut out, self.id as u64);
        out.extend_from_slice(&self.payload());
        self.enc_proof.encode(&mut out);
        out
    }

    pub fn decode(bytes: &[u8], cl: &ClParameters) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        let id = reader.usize_id()?;
        let message = Self {
            id,
            phi_i: reader.qfi(cl)?,
            x_bar_i: reader.qfi(cl)?,
            x_g2_i: reader.g2()?,
            bases_i: get_bases(&mut reader)?,
            enc_proof: EncProof::decode(&mut reader)?,
        };
        reader.finish()?;
        Ok(message)
    }

    /// The committed payload `(phi_{K_i}, x_i^K, X_i, H_i)`.
    pub fn payload(&self) -> Vec<u8> {
        let mut out = Vec::new();
        wire::put_qfi(&mut out, &self.phi_i);
        wire::put_qfi(&mut out, &self.x_bar_i);
        wire::put_g2(&mut out, &self.x_g2_i);
        put_bases(&mut out, &self.bases_i);
        out
    }
}

fn put_bases(out: &mut Vec<u8>, bases: &Bases) {
    wire::put_g1(out, &bases.h1);
    wire::put_u16(out, bases.message.len());
    for base in &bases.message {
        wire::put_g1(out, base);
    }
}

fn get_bases(reader: &mut Reader<'_>) -> Result<Bases> {
    let h1 = reader.g1()?;
    let count = reader.u16()?;
    if count > 4096 {
        return Err(Error::Wire("implausible base vector"));
    }
    let mut message = Vec::with_capacity(count);
    for _ in 0..count {
        message.push(reader.g1()?);
    }
    Ok(Bases { h1, message })
}

// ---------------------------------------------------------------------------------------
// Party
// ---------------------------------------------------------------------------------------

/// One party's key-generation state machine.
pub struct KeygenParty {
    pub id: usize,
    pub n: usize,
    pub t: usize,
    pub delta: Mpz,
    pub session: Vec<u8>,
    pp: Arc<PublicParameters>,
    rng: RandGen,

    seed_contribution: [u8; 32],
    seed_commits: BTreeMap<usize, [u8; 32]>,
    contributions: BTreeMap<usize, [u8; 32]>,
    seeds: Option<Seeds>,

    value: Mpz,
    _deal: Option<Deal>,
    deals: BTreeMap<usize, PvssMsg>,
    _received: BTreeMap<usize, Mpz>,
    sk_share: Mpz,

    randomness: Mpz,
    secret: Scalar255,
    phi_i: QFI,
    x_bar_i: QFI,
    bases_i: Bases,
    x_g2_i: G2,
    d_i: Option<QFI>,
    commits: BTreeMap<usize, KeygenCommitMsg>,
}

impl KeygenParty {
    pub fn new(pp: Arc<PublicParameters>, id: usize, n: usize, t: usize, session: Vec<u8>) -> Self {
        assert!(id >= 1 && id <= n, "party index out of range");
        assert!(t >= 1 && t <= n, "threshold out of range");
        let mut rng = fresh_rng();
        let value = pp.cl.sample_dq(&mut rng);
        let identity = pp.cl.identity().clone();
        let bases_i = Bases::zero(&pp);
        Self {
            id,
            n,
            t,
            delta: factorial(n),
            session,
            pp,
            rng,
            seed_contribution: seed32(),
            seed_commits: BTreeMap::new(),
            contributions: BTreeMap::new(),
            seeds: None,
            value,
            _deal: None,
            deals: BTreeMap::new(),
            _received: BTreeMap::new(),
            sk_share: Mpz::from(0u64),
            randomness: Mpz::from(0u64),
            secret: Scalar255::from_u64(0),
            phi_i: identity.clone(),
            x_bar_i: identity,
            bases_i,
            x_g2_i: G2::identity(),
            d_i: None,
            commits: BTreeMap::new(),
        }
    }

    fn ctx(&self, tag: &[u8], id: usize) -> Vec<u8> {
        zkp::context(&self.session, tag, id)
    }

    /// Round 1: commit to this party's zero-sharing seed contribution.
    pub fn seed_commit(&mut self, meter: &mut Meter) -> SeedCommitMsg {
        meter.step(Stage::SeedCommit, |_| {
            let commitment = commit_hash(
                &self.pp,
                &self.session,
                self.id,
                DOMAIN_SEED_COMMIT,
                &self.seed_contribution,
            );
            SeedCommitMsg {
                id: self.id,
                commitment,
            }
        })
    }

    /// Round 2: record everyone's commitment and open ours.
    pub fn seed_open(
        &mut self,
        inbox: &[SeedCommitMsg],
        meter: &mut Meter,
    ) -> Result<SeedOpenMsg> {
        meter.step(Stage::SeedOpen, |_| {
            if inbox.len() != self.n {
                return Err(Error::Missing("seed commitments incomplete"));
            }
            for message in inbox {
                self.seed_commits.insert(message.id, message.commitment);
            }
            Ok(SeedOpenMsg {
                id: self.id,
                contribution: self.seed_contribution,
            })
        })
    }

    /// Check every opening against its round-1 commitment, then derive the seeds.
    pub fn absorb_seeds(&mut self, inbox: &[SeedOpenMsg]) -> Result<()> {
        if inbox.len() != self.n {
            return Err(Error::Missing("seed openings incomplete"));
        }
        for message in inbox {
            let commitment = commit_hash(
                &self.pp,
                &self.session,
                message.id,
                DOMAIN_SEED_COMMIT,
                &message.contribution,
            );
            match self.seed_commits.get(&message.id) {
                Some(expected) if *expected == commitment => {}
                _ => return Err(Error::Verify("seed commitment does not open")),
            }
            self.contributions.insert(message.id, message.contribution);
        }
        self.seeds = Some(Seeds::from_contributions(self.id, &self.contributions)?);
        Ok(())
    }

    /// Round 3: deal `v_i` to everyone.
    pub fn deal(&mut self, meter: &mut Meter) -> (PvssMsg, Vec<(usize, ShareMsg)>) {
        meter.step(Stage::KeygenDeal, |meter| {
            let ctx = self.ctx(b"pvss", self.id);
            let dealt = pvss::deal(
                &self.pp,
                &ctx,
                &self.value,
                self.n,
                self.t,
                &self.delta,
                &mut self.rng,
                meter,
            );
            let shares = dealt
                .shares
                .iter()
                .enumerate()
                .map(|(position, share)| {
                    (
                        position + 1,
                        ShareMsg {
                            from: self.id,
                            share: share.clone(),
                        },
                    )
                })
                .collect();
            let message = PvssMsg {
                id: self.id,
                commitments: dealt.commitments.clone(),
                proofs: dealt.proofs.clone(),
            };
            self._deal = Some(dealt);
            (message, shares)
        })
    }

    /// Round 3: verify a dealer's commitments and my share from it.
    pub fn accept_deal(
        &mut self,
        message: &PvssMsg,
        share: &ShareMsg,
        meter: &mut Meter,
    ) -> Result<()> {
        meter.step(Stage::KeygenDeal, |meter| {
            if share.from != message.id {
                return Err(Error::Protocol("share does not match the dealer"));
            }
            let ctx = self.ctx(b"pvss", message.id);
            if !pvss::verify_deal(
                &self.pp,
                &ctx,
                &self.delta,
                &message.commitments,
                &message.proofs,
                self.n,
                self.t,
                meter,
            ) {
                return Err(Error::Verify("PVSS commitment proof"));
            }
            if !pvss::check_share(
                &self.pp.cl,
                &message.commitments,
                &self.delta,
                self.id,
                &share.share,
                meter,
            ) {
                return Err(Error::Verify("PVSS share check"));
            }
            self.sk_share = add(&self.sk_share, &share.share);
            self._received.insert(message.id, share.share.clone());
            self.deals.insert(message.id, message.clone());
            Ok(())
        })
    }

    /// `C_k = prod_j C_{j,k}`, so `C_0 = pk`.
    fn aggregates(&self, meter: &mut Meter) -> Result<(Vec<QFI>, QFI)> {
        let class = &self.pp.cl;
        if self.deals.len() != self.n {
            return Err(Error::Missing("PVSS transcripts incomplete"));
        }
        let mut aggregates: Vec<QFI> = (0..self.t).map(|_| class.identity().clone()).collect();
        for deal in self.deals.values() {
            for (position, commitment) in deal.commitments.iter().enumerate() {
                aggregates[position] = class.compose(&aggregates[position], commitment, meter);
            }
        }
        let pk = aggregates[0].clone();
        Ok((aggregates, pk))
    }

    /// Round 4: `D_i`, the encapsulation of `x_i`, and the commitment to it.
    pub fn keygen_commit(&mut self, meter: &mut Meter) -> Result<KeygenCommitMsg> {
        meter.step(Stage::KeygenCommit, |meter| {
            let class = &self.pp.cl;
            let (aggregates, pk) = self.aggregates(meter)?;

            // D_i = C_0^{Delta^2} * prod_{k>=1} C_k^{i^k}
            let mut d_i = class.exp(&aggregates[0], &square(&self.delta), meter);
            for (position, aggregate) in aggregates.iter().enumerate().skip(1) {
                let term = class.exp(aggregate, &index_pow(self.id, position), meter);
                d_i = class.compose(&d_i, &term, meter);
            }
            // The aggregate must agree with the shares checked in round 3.
            let gq_delta = class.gq_pow_delta(&self.delta, meter);
            let expected = class.exp(&gq_delta, &self.sk_share, meter);
            if d_i != expected {
                return Err(Error::Verify("D_i does not match the aggregated shares"));
            }
            self.d_i = Some(d_i.clone());

            let ctx = self.ctx(b"d-share", self.id);
            let bound = witness_bound(&self.pp, self.n, self.t);
            let d_proof = zkp::prove_dl(
                &self.pp,
                DOMAIN_KEY_D,
                &ctx,
                &gq_delta,
                &d_i,
                &self.sk_share,
                &bound,
                &mut self.rng,
                meter,
            );

            // (phi_{K_i}, K_i) <- Encap(pk; r_i), then encrypt x_i under K_i.
            self.randomness = class.sample_dq(&mut self.rng);
            let (phi_i, key) = cl::encap(class, &pk, &self.randomness, meter);
            self.secret = Scalar255::random(&mut rand_core::OsRng);
            self.x_bar_i = cl::dem(class, &key, &self.secret, meter);
            self.x_g2_i = self.pp.g2.scale(&self.secret);
            self.bases_i = Bases::derive(&self.pp, &seed32());
            self.phi_i = phi_i;

            let commitment = commit_hash(
                &self.pp,
                &self.session,
                self.id,
                DOMAIN_KEY_COMMIT,
                &payload_of(
                    &self.phi_i,
                    &self.x_bar_i,
                    &self.x_g2_i,
                    &self.bases_i,
                ),
            );

            Ok(KeygenCommitMsg {
                id: self.id,
                d_i,
                d_proof,
                commitment,
            })
        })
    }

    /// Round 5: check every round-4 message, then open my contribution.
    pub fn keygen_open(
        &mut self,
        inbox: &[KeygenCommitMsg],
        meter: &mut Meter,
    ) -> Result<KeygenOpenMsg> {
        meter.step(Stage::KeygenOpen, |meter| {
            let class = &self.pp.cl;
            if inbox.len() != self.n {
                return Err(Error::Missing("round-4 messages incomplete"));
            }
            let (aggregates, pk) = self.aggregates(meter)?;
            let gq_delta = class.gq_pow_delta(&self.delta, meter);
            let bound = witness_bound(&self.pp, self.n, self.t);

            for message in inbox {
                let ctx = self.ctx(b"d-share", message.id);
                if !zkp::verify_dl(
                    &self.pp,
                    DOMAIN_KEY_D,
                    &ctx,
                    &gq_delta,
                    &message.d_i,
                    &message.d_proof,
                    &bound,
                    meter,
                ) {
                    return Err(Error::Verify("D_i proof"));
                }
                let mut expected = class.exp(&aggregates[0], &square(&self.delta), meter);
                for (position, aggregate) in aggregates.iter().enumerate().skip(1) {
                    let term = class.exp(aggregate, &index_pow(message.id, position), meter);
                    expected = class.compose(&expected, &term, meter);
                }
                if expected != message.d_i {
                    return Err(Error::Verify("D_i disagrees with the DKG transcript"));
                }
                self.commits.insert(message.id, message.clone());
            }

            let ctx = self.ctx(b"enc", self.id);
            let enc_proof = zkp::prove_enc(
                &self.pp,
                &ctx,
                &pk,
                &self.phi_i,
                &self.x_bar_i,
                &self.x_g2_i,
                &self.secret,
                &self.randomness,
                &mut self.rng,
                meter,
            );
            Ok(KeygenOpenMsg {
                id: self.id,
                phi_i: self.phi_i.clone(),
                x_bar_i: self.x_bar_i.clone(),
                x_g2_i: self.x_g2_i.clone(),
                bases_i: self.bases_i.clone(),
                enc_proof,
            })
        })
    }

    /// Aggregate the transcript into the verifying key and this party's package.
    pub fn finish(&mut self, inbox: &[KeygenOpenMsg], meter: &mut Meter) -> Result<KeyPackage> {
        meter.step(Stage::KeygenFinish, |meter| {
            let class = &self.pp.cl;
            if inbox.len() != self.n {
                return Err(Error::Missing("round-5 messages incomplete"));
            }
            let (_aggregates, pk) = self.aggregates(meter)?;

            let mut x_g2 = G2::identity();
            let mut bases = Bases::zero(&self.pp);
            let mut phi_k = class.identity().clone();
            let mut x_bar = class.identity().clone();

            for message in inbox {
                let commit = self
                    .commits
                    .get(&message.id)
                    .ok_or(Error::Missing("round-4 commitment missing"))?;
                let recomputed = commit_hash(
                    &self.pp,
                    &self.session,
                    message.id,
                    DOMAIN_KEY_COMMIT,
                    &message.payload(),
                );
                if recomputed != commit.commitment {
                    return Err(Error::Verify("round-5 payload does not open"));
                }

                let ctx = self.ctx(b"enc", message.id);
                if !zkp::verify_enc(
                    &self.pp,
                    &ctx,
                    &pk,
                    &message.phi_i,
                    &message.x_bar_i,
                    &message.x_g2_i,
                    &message.enc_proof,
                    meter,
                ) {
                    return Err(Error::Verify("R_enc proof"));
                }
                if message.bases_i.message.len() != self.pp.config.message_len {
                    return Err(Error::Verify("base vector length"));
                }

                x_g2 = x_g2.combine(&message.x_g2_i);
                bases = bases.add(&message.bases_i, meter);
                phi_k = class.compose(&phi_k, &message.phi_i, meter);
                x_bar = class.compose(&x_bar, &message.x_bar_i, meter);
            }

            let d_i = self
                .d_i
                .clone()
                .ok_or(Error::Protocol("round-4 share was never produced"))?;
            let seeds = self
                .seeds
                .take()
                .ok_or(Error::Protocol("pairwise seeds were never derived"))?;

            Ok(KeyPackage {
                public: Arc::new(KeyPublic {
                    pp: self.pp.clone(),
                    pk,
                    phi_k,
                    x_bar,
                    x_g2,
                    bases,
                    n: self.n,
                    t: self.t,
                    delta: self.delta.clone(),
                }),
                share: KeyShare {
                    id: self.id,
                    sk_share: self.sk_share.clone(),
                    d_i,
                },
                seeds,
            })
        })
    }
}

fn payload_of(phi_i: &QFI, x_bar_i: &QFI, x_g2_i: &G2, bases_i: &Bases) -> Vec<u8> {
    let mut out = Vec::new();
    wire::put_qfi(&mut out, phi_i);
    wire::put_qfi(&mut out, x_bar_i);
    wire::put_g2(&mut out, x_g2_i);
    put_bases(&mut out, bases_i);
    out
}

/// `H(domain, pp, sid, id, payload)` — the hash commitment of `F_COM`.
pub fn commit_hash(
    pp: &PublicParameters,
    session: &[u8],
    id: usize,
    domain: &[u8],
    payload: &[u8],
) -> [u8; 32] {
    let mut transcript = Transcript::new(domain);
    pp.absorb(&mut transcript);
    transcript
        .absorb_bytes(b"sid", session)
        .absorb_u64(b"id", id as u64)
        .absorb_bytes(b"payload", payload);
    transcript.digest32()
}

/// Honest upper bound on `|sk_i| = |sum_j (Delta v_j + sum_k a_{j,k} i^k)|`.
///
/// `|v_j| < B_q`, `|a_{j,k}| < 2^{ell_0 + lambda_d}`, `i^k <= n^{t-1}`, hence
/// `|sk_i| < n (Delta B_q + (t-1) 2^{ell_0+lambda_d} n^{t-1})`. The `D_i` proof's range check
/// uses this bound, so a prover cannot shift the response interval.
pub fn witness_bound(pp: &PublicParameters, n: usize, t: usize) -> Mpz {
    let delta = factorial(n);
    let coefficient = pvss::coefficient_bound(pp, n, t);
    let spread = pow(&Mpz::from(n as u64), t.saturating_sub(1));
    let per_dealer = add(
        &mul(&delta, pp.cl.bound_bq()),
        &mul(
            &Mpz::from(t.saturating_sub(1) as u64),
            &mul(&coefficient, &spread),
        ),
    );
    mul(&Mpz::from(n as u64), &per_dealer)
}
