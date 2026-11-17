//! Distributed key generation (paper §3, three passes).
//!
//! ```text
//! Pass 1  P_1 -> P_2 :  h = H_0(X_1)                                  (commitment to X_1)
//! Pass 2  P_2 -> P_1 :  X_2, vk_2, Pi_{R_DL}(vk_2)
//! Pass 3  P_1 -> P_2 :  X_1, ek_1, C_key1 = CL-Enc(ek_1, x_1; rho_1), Pi_{R_CL-DL}
//! Output             :  X = X_1 + X_2
//! ```
//!
//! `X_1` is published in pass 3 because it is part of the `R_CL-DL` *statement*: the paper's
//! `F_ZK` hands the statement to the verifier, and `P_2` needs `X_1` to check
//! `h = H_0(X_1)` and to form `X = X_1 + X_2`. The commitment in pass 1 is what makes the
//! protocol unbiased — `P_1` fixes `X_1` before it sees `X_2`, so it cannot grind `x_1` to
//! steer the joint key.
//!
//! `C_key1` is what signing later depends on: `P_1`'s long-term encryption of `x_1` under its
//! own CL key `ek_1`, produced once so that `P_2` can homomorphically build
//! `r(x_1 + x_2 + e)` in a single pass.

use std::sync::Arc;

use bicycl::{Mpz, QFI, RandGen};

use threshold_bbs::algebra::Group;
use threshold_bbs::bls381::{Scalar255, G1, G2};
use threshold_bbs::hash::Transcript;

use crate::cl::{self, Cipher};
use crate::error::{Error, Result};
use crate::meter::{Meter, Op, Stage};
use crate::params::PublicParameters;
use crate::random::fresh_rng;
use crate::vrf::VrfKey;
use crate::wire::{self, Reader};
use crate::zkp::{self, ClDlProof, ClDlStatement, DlProof};

pub const DOMAIN_COMMIT: &[u8] = b"twopass-bbs/v01/keygen/commit";

/// `H_0 : G_2 -> {0,1}^lambda`, the commitment to `X_1`.
pub fn commit_share(pp: &PublicParameters, x_g2: &G2) -> [u8; 32] {
    let mut transcript = Transcript::new(DOMAIN_COMMIT);
    pp.absorb(&mut transcript);
    transcript.absorb_g2(b"X", x_g2);
    transcript.digest32()
}

// ---------------------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct DkgPass1 {
    pub commitment: [u8; 32],
}

impl DkgPass1 {
    pub fn encode(&self) -> Vec<u8> {
        self.commitment.to_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        let commitment = reader.hash()?;
        reader.finish()?;
        Ok(Self { commitment })
    }
}

#[derive(Clone, Debug)]
pub struct DkgPass2 {
    pub x_g2: G2,
    pub vk: G1,
    pub proof: DlProof,
}

impl DkgPass2 {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        wire::put_g2(&mut out, &self.x_g2);
        wire::put_g1(&mut out, &self.vk);
        self.proof.encode(&mut out);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        let message = Self {
            x_g2: reader.g2()?,
            vk: reader.g1()?,
            proof: DlProof::decode(&mut reader)?,
        };
        reader.finish()?;
        Ok(message)
    }
}

#[derive(Clone, Debug)]
pub struct DkgPass3 {
    /// `X_1`, the opened value behind pass 1's commitment.
    pub x_g2: G2,
    pub ek: QFI,
    pub c_key: Cipher,
    pub proof: ClDlProof,
}

impl DkgPass3 {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        wire::put_g2(&mut out, &self.x_g2);
        wire::put_qfi(&mut out, &self.ek);
        self.c_key.encode(&mut out);
        self.proof.encode(&mut out);
        out
    }

    pub fn decode(bytes: &[u8], pp: &PublicParameters) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        let message = Self {
            x_g2: reader.g2()?,
            ek: reader.qfi(&pp.cl)?,
            c_key: Cipher::decode(&mut reader, &pp.cl)?,
            proof: ClDlProof::decode(&mut reader)?,
        };
        reader.finish()?;
        Ok(message)
    }
}

// ---------------------------------------------------------------------------------------
// Long-term states
// ---------------------------------------------------------------------------------------

/// `P_1`'s state. The CL decryption key `dk` is what lets it finish a signature in place.
pub struct FirstParty {
    pub params: Arc<PublicParameters>,
    pub public_key: G2,
    pub own_share: Scalar255,
    /// `X_1 = x_1 G_2`.
    pub own_share_g2: G2,
    /// `X_2`, needed by `R_CL-Lin` (the relation is stated against `P_2`'s share).
    pub peer_share: G2,
    pub peer_vk: G1,
    pub ek: QFI,
    pub dk: Mpz,
    /// `rho_1` is not needed after `C_key1` is built; it is kept so tests can re-derive the
    /// `R_CL-DL` proof.
    pub rho1: Mpz,
    pub c_key: Cipher,
}

/// `P_2`'s state. The VRF key pins `(e, s)`; `(ek_1, C_key1)` is what it encrypts under.
pub struct SecondParty {
    pub params: Arc<PublicParameters>,
    pub public_key: G2,
    pub own_share: Scalar255,
    /// `X_2 = x_2 G_2`, the relation's `X` in `R_CL-Lin`.
    pub own_share_g2: G2,
    /// `X_1`.
    pub peer_share: G2,
    pub vrf: VrfKey,
    pub ek: QFI,
    pub c_key: Cipher,
}

// ---------------------------------------------------------------------------------------
// P_1
// ---------------------------------------------------------------------------------------

pub struct FirstSetup {
    params: Arc<PublicParameters>,
    rng: RandGen,
    x: Scalar255,
    x_g2: G2,
    peer_x_g2: Option<G2>,
    peer_vk: Option<G1>,
    cl: Option<(QFI, Mpz, Mpz, Cipher)>,
    session: Vec<u8>,
}

impl FirstSetup {
    /// Pass 1: sample `x_1` and commit to `X_1`.
    pub fn new(params: Arc<PublicParameters>, session: &[u8], meter: &mut Meter) -> (Self, DkgPass1) {
        meter.step(Stage::DkgOne, |meter| {
            let x = Scalar255::random(&mut rand_core::OsRng);
            meter.add(Op::G2Exp);
            let x_g2 = params.g2.scale(&x);
            let commitment = commit_share(&params, &x_g2);
            (
                Self {
                    params,
                    rng: fresh_rng(),
                    x,
                    x_g2,
                    peer_x_g2: None,
                    peer_vk: None,
                    cl: None,
                    session: session.to_vec(),
                },
                DkgPass1 { commitment },
            )
        })
    }

    /// Pass 3: check `P_2`'s proof, then publish `X_1`, `ek_1`, `C_key1` and its proof.
    pub fn pass3(&mut self, pass2: &DkgPass2, meter: &mut Meter) -> Result<DkgPass3> {
        meter.step(Stage::DkgThree, |meter| {
            let pp = self.params.clone();
            let ctx = zkp::context(&self.session, b"dkg/p2-dl", &[1, 2]);
            if !zkp::verify_dl(&pp, &ctx, &pp.g1, &pass2.vk, &pass2.proof, meter) {
                return Err(Error::Verify("R_DL for vk_2"));
            }

            let (ek, dk) = cl::keygen(&pp.cl, &mut self.rng, meter);
            let rho1 = pp.cl.sample_dq(&mut self.rng);
            let c_key = cl::encrypt(&pp.cl, &ek, &self.x, &rho1, meter);

            let statement = ClDlStatement {
                ek: &ek,
                x_g2: &self.x_g2,
                cipher: &c_key,
            };
            let ctx = zkp::context(&self.session, b"dkg/p1-cl-dl", &[1, 2]);
            let proof =
                zkp::prove_cl_dl(&pp, &ctx, &statement, &self.x, &rho1, &mut self.rng, meter);

            self.peer_x_g2 = Some(pass2.x_g2.clone());
            self.peer_vk = Some(pass2.vk.clone());
            self.cl = Some((ek.clone(), dk, rho1, c_key.clone()));

            Ok(DkgPass3 {
                x_g2: self.x_g2.clone(),
                ek,
                c_key,
                proof,
            })
        })
    }

    /// `X = X_1 + X_2`.
    pub fn finish(self, meter: &mut Meter) -> Result<FirstParty> {
        meter.step(Stage::DkgFinish, |_| {
            let peer_x_g2 = self
                .peer_x_g2
                .ok_or(Error::Protocol("pass 2 was never received"))?;
            let peer_vk = self
                .peer_vk
                .ok_or(Error::Protocol("vk_2 was never received"))?;
            let (ek, dk, rho1, c_key) = self
                .cl
                .ok_or(Error::Protocol("pass 3 was never produced"))?;
            Ok(FirstParty {
                public_key: self.x_g2.combine(&peer_x_g2),
                params: self.params,
                own_share: self.x,
                own_share_g2: self.x_g2,
                peer_share: peer_x_g2,
                peer_vk,
                ek,
                dk,
                rho1,
                c_key,
            })
        })
    }
}

// ---------------------------------------------------------------------------------------
// P_2
// ---------------------------------------------------------------------------------------

pub struct SecondSetup {
    params: Arc<PublicParameters>,
    x: Scalar255,
    x_g2: G2,
    vrf: VrfKey,
    commitment: [u8; 32],
    session: Vec<u8>,
}

impl SecondSetup {
    /// Pass 2: sample `x_2`, generate the VRF key pair, prove knowledge of `sk_2`.
    pub fn new(
        params: Arc<PublicParameters>,
        session: &[u8],
        pass1: &DkgPass1,
        meter: &mut Meter,
    ) -> Result<(Self, DkgPass2)> {
        meter.step(Stage::DkgTwo, |meter| {
            let x = Scalar255::random(&mut rand_core::OsRng);
            meter.add(Op::G2Exp);
            let x_g2 = params.g2.scale(&x);

            let vrf = VrfKey::generate(&params, &mut rand_core::OsRng);
            let ctx = zkp::context(session, b"dkg/p2-dl", &[1, 2]);
            let proof = zkp::prove_dl(
                params.as_ref(),
                &ctx,
                &params.g1,
                &vrf.vk,
                vrf.secret(),
                &mut rand_core::OsRng,
                meter,
            );

            let setup = Self {
                params,
                x,
                x_g2: x_g2.clone(),
                vrf,
                commitment: pass1.commitment,
                session: session.to_vec(),
            };
            let message = DkgPass2 {
                x_g2,
                vk: setup.vrf.vk.clone(),
                proof,
            };
            Ok((setup, message))
        })
    }

    /// Output: open the commitment, verify `C_key1`, fix `X`.
    pub fn finish(self, pass3: &DkgPass3, meter: &mut Meter) -> Result<SecondParty> {
        meter.step(Stage::DkgFinish, |meter| {
            let pp = self.params.clone();
            if commit_share(&pp, &pass3.x_g2) != self.commitment {
                return Err(Error::Verify("h = H_0(X_1)"));
            }

            let statement = ClDlStatement {
                ek: &pass3.ek,
                x_g2: &pass3.x_g2,
                cipher: &pass3.c_key,
            };
            let ctx = zkp::context(&self.session, b"dkg/p1-cl-dl", &[1, 2]);
            if !zkp::verify_cl_dl(&pp, &ctx, &statement, &pass3.proof, meter) {
                return Err(Error::Verify("R_CL-DL for C_key1"));
            }

            Ok(SecondParty {
                public_key: pass3.x_g2.combine(&self.x_g2),
                params: self.params,
                own_share: self.x,
                own_share_g2: self.x_g2,
                peer_share: pass3.x_g2.clone(),
                vrf: self.vrf,
                ek: pass3.ek.clone(),
                c_key: pass3.c_key.clone(),
            })
        })
    }
}
