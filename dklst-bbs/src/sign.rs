//! DKLST threshold BBS+: two-round signing plus client assembly.
//!
//! Round 1 publishes, per signer, a commitment to `(s_i, e_i)` and — for every pair in which
//! the signer plays the OT *receiver* — the SoftSpokenOT choice message. Round 2 opens
//! `(s_i, e_i)` and, for every pair in which the signer plays the OT *sender*, the `pi_Mul`
//! reply. Each signer then holds `u_i` and `R_i = r_i * B`; the client assembles
//! `A = sum_i R_i / sum_i u_i`.
//!
//! The multiplier inputs are `alpha = r_i` (the sender's own nonce share) and
//! `beta_j = lambda_j * p(j)` (the receiver's key share), so that
//! `sum_{i,j} r_i * lambda_j p(j) = r * x` and `u = r * (x + e)`.
//!
//! # Benchmark shortcuts (documented, not claimed secure)
//!
//! * keys come from a trusted dealer rather than the DKLs19 DKG that DKLST specifies;
//! * the bases `H_1 .. H_{ell+1}` are multiples of `G_1` derived from a hash, not
//!   hash-to-curve output — this avoids a `hash_to_curve` dependency and changes no timing.

use std::collections::HashMap;
use std::sync::Arc;

use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use ff::Field;
use sha2::{Digest, Sha256};

use crate::mul::{self, public_grip, MulReply, MulVariant, ReceiverState};
use crate::ot::{Backend, Counters, OtSetup};
use crate::params::{ELL, KAPPA, LAMBDA};

/// Public parameters of one instantiation.
pub struct PublicParams {
    pub g1: G1Projective,
    pub g2: G2Projective,
    /// `H_1 .. H_{ell+1}`; `H_1` is the base of `s`.
    pub h: Vec<G1Projective>,
    pub grip: Vec<Scalar>,
}

impl PublicParams {
    pub fn new(message_len: usize) -> Arc<Self> {
        let g1 = G1Projective::generator();
        let g2 = G2Projective::generator();
        let h = (0..=message_len)
            .map(|index| {
                let mut hasher = Sha256::new();
                hasher.update(b"dklst/h");
                hasher.update((index as u64).to_be_bytes());
                let digest = hasher.finalize();
                let mut wide = [0u8; 64];
                wide[..32].copy_from_slice(&digest);
                g1 * Scalar::from_bytes_wide(&wide)
            })
            .collect();
        Arc::new(Self {
            g1,
            g2,
            h,
            grip: public_grip(b"dklst/grip"),
        })
    }

    /// `B = G_1 + s*H_1 + sum_k m_k*H_{k+1}`.
    pub fn big_b(&self, s: &Scalar, message: &[Scalar]) -> G1Projective {
        let mut value = self.g1 + self.h[0] * s;
        for (base, scalar) in self.h[1..].iter().zip(message) {
            value += base * scalar;
        }
        value
    }
}

/// One signer's key material (trusted dealer).
#[derive(Clone)]
pub struct Keys {
    pub id: usize,
    pub share: Scalar,
    pub public_share: G2Projective,
    pub public: G2Projective,
}

pub fn keygen(parties: &[usize], threshold: usize) -> Vec<Keys> {
    let mut rng = rand::thread_rng();
    let mut coefficients = vec![Scalar::random(&mut rng)];
    for _ in 1..threshold {
        coefficients.push(Scalar::random(&mut rng));
    }
    let evaluate = |point: usize| {
        let x = Scalar::from(point as u64);
        let mut acc = Scalar::ZERO;
        let mut power = Scalar::ONE;
        for coefficient in &coefficients {
            acc += *coefficient * power;
            power *= x;
        }
        acc
    };
    let g2 = G2Projective::generator();
    let public = g2 * coefficients[0];
    parties
        .iter()
        .map(|id| {
            let share = evaluate(*id);
            Keys {
                id: *id,
                share,
                public_share: g2 * share,
                public,
            }
        })
        .collect()
}

fn lagrange(id: usize, quorum: &[usize]) -> Scalar {
    let mut numerator = Scalar::ONE;
    let mut denominator = Scalar::ONE;
    for peer in quorum {
        if *peer == id {
            continue;
        }
        numerator *= Scalar::from(*peer as u64);
        denominator *= Scalar::from((*peer as i64 - id as i64).unsigned_abs());
        if *peer < id {
            numerator = -numerator;
        }
    }
    numerator * denominator.invert().expect("distinct points")
}

/// Per-direction OT material: `(alice, bob)` owns one extension setup.
pub struct OtMaterial {
    backend: Backend,
    variant: MulVariant,
    pairs: HashMap<(usize, usize), OtSetup>,
}

impl OtMaterial {
    pub fn setup(quorum: &[usize]) -> Self {
        Self::with_backend(quorum, Backend::SlOblivious, MulVariant::default())
            .expect("sl-oblivious setup")
    }

    /// Build one setup per ordered pair with the requested OT backend and multiplication variant.
    ///
    /// For [`Backend::LibOte`] this also *runs* the base OTs (they are what the setup object
    /// holds), so the caller can time this call as the setup cost.
    pub fn with_backend(
        quorum: &[usize],
        backend: Backend,
        variant: MulVariant,
    ) -> Option<Self> {
        Self::with_options(quorum, backend, variant, 2)
    }

    /// As [`OtMaterial::with_backend`], with SoftSpokenOT's `field_bits` knob exposed.
    pub fn with_options(
        quorum: &[usize],
        backend: Backend,
        variant: MulVariant,
        field_bits: u32,
    ) -> Option<Self> {
        let mut pairs = HashMap::new();
        for alice in quorum {
            for bob in quorum {
                if alice != bob {
                    pairs.insert((*alice, *bob), OtSetup::with_options(backend, field_bits)?);
                }
            }
        }
        Some(Self {
            backend,
            variant,
            pairs,
        })
    }

    pub fn backend(&self) -> Backend {
        self.backend
    }

    pub fn variant(&self) -> MulVariant {
        self.variant
    }

    /// Summed base-OT cost of the `libOTe` backend: `(wall_ns, wire bytes)`, both parties.
    pub fn libote_setup_stats(&self) -> (u64, u64) {
        #[cfg(feature = "libote")]
        {
            let mut wall = 0u64;
            let mut bytes = 0u64;
            for setup in self.pairs.values() {
                if let OtSetup::Libote { pair, .. } = setup {
                    let stats = pair.base_ot_stats();
                    wall += stats.wall_ns;
                    bytes += stats.bytes_sender + stats.bytes_receiver;
                }
            }
            (wall, bytes)
        }
        #[cfg(not(feature = "libote"))]
        {
            (0, 0)
        }
    }

    fn get(&self, alice: usize, bob: usize) -> &OtSetup {
        &self.pairs[&(alice, bob)]
    }
}

/// Round-1 message.
pub struct Round1 {
    pub id: usize,
    pub commit: [u8; 32],
    /// `(alice, choice message)` for every pair where this signer is the receiver.
    pub choices: Vec<(usize, Vec<u8>)>,
}

/// Round-2 message.
pub struct Round2 {
    pub id: usize,
    pub s: Scalar,
    pub e: Scalar,
    /// `(bob, reply)` for every pair where this signer is the sender.
    pub replies: Vec<(usize, MulReply)>,
}

/// What a signer hands to the client.
pub struct Response {
    pub id: usize,
    pub s: Scalar,
    pub e: Scalar,
    pub u: Scalar,
    pub r: G1Projective,
}

/// Session state of one signer.
pub struct Signer {
    pub keys: Keys,
    pub quorum: Vec<usize>,
    pub pp: Arc<PublicParams>,
    r: Scalar,
    s: Scalar,
    e: Scalar,
    beta: Scalar,
    receivers: HashMap<usize, ReceiverState>,
    alice_shares: HashMap<usize, Scalar>,
    counters: Counters,
}

impl Signer {
    pub fn new(keys: Keys, quorum: &[usize], pp: Arc<PublicParams>) -> Self {
        let mut rng = rand::thread_rng();
        let lambda = lagrange(keys.id, quorum);
        let beta = lambda * keys.share;
        Self {
            r: Scalar::random(&mut rng),
            s: Scalar::random(&mut rng),
            e: Scalar::random(&mut rng),
            beta,
            receivers: HashMap::new(),
            alice_shares: HashMap::new(),
            counters: Counters::default(),
            keys,
            quorum: quorum.to_vec(),
            pp,
        }
    }

    /// Test hook: the signer's nonce share and encoded key share.
    pub fn debug_r_beta(&self) -> (Scalar, Scalar) {
        (self.r, self.beta)
    }

    pub fn counters(&self) -> Counters {
        self.counters
    }

    pub fn commitment(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"dklst/commit");
        hasher.update((self.keys.id as u64).to_be_bytes());
        hasher.update(self.s.to_bytes());
        hasher.update(self.e.to_bytes());
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }

    /// Round 1: commit and publish the receiver-side extension messages.
    pub fn round1(&mut self, session: &[u8], material: &OtMaterial) -> Round1 {
        // One 2*LAMBDA-bit commitment per peer (DKLST charges 4*LAMBDA; see the README).
        self.counters.bits += ((self.quorum.len() - 1) * 2 * LAMBDA) as u64;
        let mut choices = Vec::new();
        for alice in self.quorum.clone() {
            if alice == self.keys.id {
                continue;
            }
            let index = session_index(session, alice, self.keys.id);
            let (state, message) =
                mul::receive(&index, material.get(alice, self.keys.id), &self.beta, &self.pp.grip, &mut self.counters)
                    .expect("extension receiver");
            self.receivers.insert(alice, state);
            choices.push((alice, message));
        }
        Round1 {
            id: self.keys.id,
            commit: self.commitment(),
            choices,
        }
    }

    /// Round 2: open `(s_i, e_i)` and answer every peer from whom a choice message arrived.
    pub fn round2(
        &mut self,
        session: &[u8],
        material: &OtMaterial,
        inbox: &[Round1],
    ) -> Round2 {
        // Opening `(s_i, e_i)`: 2*KAPPA bits per peer.
        self.counters.bits += ((self.quorum.len() - 1) * 2 * KAPPA) as u64;
        let mut replies = Vec::new();
        for peer in self.quorum.clone() {
            if peer == self.keys.id {
                continue;
            }
            let from_peer = inbox
                .iter()
                .find(|round| round.id == peer)
                .expect("peer round-1 message");
            let message = from_peer
                .choices
                .iter()
                .find(|(alice, _)| *alice == self.keys.id)
                .expect("choice message for this signer")
                .1
                .clone();
            let index = session_index(session, self.keys.id, peer);
            let (reply, share) = mul::reply(
                &index,
                material.get(self.keys.id, peer),
                &message,
                &self.r,
                &self.pp.grip,
                material.variant(),
                &mut self.counters,
            )
            .expect("extension sender");
            self.alice_shares.insert(peer, share);
            replies.push((peer, reply));
        }
        Round2 {
            id: self.keys.id,
            s: self.s,
            e: self.e,
            replies,
        }
    }

    /// Assemble `u_i` and `R_i` once every round-2 message has arrived.
    pub fn finish(
        &mut self,
        session: &[u8],
        first: &[Round1],
        inbox: &[Round2],
        message: &[Scalar],
    ) -> Response {
        let mut s = self.s;
        let mut e = self.e;
        let mut u = Scalar::ZERO;

        // Shares from the pairs where this signer is the sender.
        for share in self.alice_shares.values() {
            u += share;
        }

        // Shares from the pairs where this signer is the receiver: verify the peer's reply.
        for peer in self.quorum.clone() {
            if peer == self.keys.id {
                continue;
            }
            let state = self
                .receivers
                .get(&peer)
                .expect("receiver state for the pair");
            let from_peer = inbox
                .iter()
                .find(|round| round.id == peer)
                .expect("peer round-2 message");
            let reply = from_peer
                .replies
                .iter()
                .find(|(bob, _)| *bob == self.keys.id)
                .expect("reply addressed to this signer")
                .1
                .clone();
            let index = session_index(session, peer, self.keys.id);
            let share = mul::finish(&index, state, &reply, &self.pp.grip)
                .expect("pi_Mul consistency check");
            u += share;

            // Openings: accumulate the coin-tossing contributions of the peers.
            let mut hasher = Sha256::new();
            hasher.update(b"dklst/commit");
            hasher.update((peer as u64).to_be_bytes());
            hasher.update(from_peer.s.to_bytes());
            hasher.update(from_peer.e.to_bytes());
            let digest = hasher.finalize();
            let mut expected = [0u8; 32];
            expected.copy_from_slice(&digest);
            let commitment = first
                .iter()
                .find(|round| round.id == peer)
                .expect("peer round-1 message")
                .commit;
            assert_eq!(expected, commitment, "opening does not match the commitment");
            s += from_peer.s;
            e += from_peer.e;
        }

        // The diagonal product `r_i * lambda_i p_i` is local: the signer knows both factors.
        u += self.r * self.beta;
        u += self.r * e;
        let r = self.pp.big_b(&s, message) * self.r;
        Response {
            id: self.keys.id,
            s,
            e,
            u,
            r,
        }
    }
}

fn session_index(session: &[u8], alice: usize, bob: usize) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"dklst/pair");
    hasher.update(session);
    hasher.update((alice as u64).to_be_bytes());
    hasher.update((bob as u64).to_be_bytes());
    let digest = hasher.finalize();
    digest.to_vec()
}

/// Client: `A = sum R_i / sum u_i`.
///
/// Every signer already reports the *aggregate* `(s, e)` it derived from the openings, so the
/// client takes them from one response rather than summing them again.
pub fn combine(responses: &[Response]) -> Option<(G1Projective, Scalar, Scalar)> {
    let first = responses.first()?;
    let mut numerator = G1Projective::identity();
    let mut denominator = Scalar::ZERO;
    for response in responses {
        numerator += response.r;
        denominator += response.u;
    }
    let inverse = denominator.invert().into_option()?;
    Some((numerator * inverse, first.s, first.e))
}

/// `e(A, X + e*G_2) = e(B, G_2)`.
pub fn verify(
    pp: &PublicParams,
    public: &G2Projective,
    message: &[Scalar],
    a: &G1Projective,
    e: &Scalar,
    s: &Scalar,
) -> bool {
    let b = pp.big_b(s, message);
    let g2 = G2Projective::generator();
    bls12_381::pairing(&G1Affine::from(a), &G2Affine::from(*public + g2 * e))
        == bls12_381::pairing(&G1Affine::from(b), &G2Affine::from(g2))
}

/// Multiplications per signer in a session of `t` signers.
pub fn multiplications_per_signer(t: usize) -> usize {
    2 * (t.saturating_sub(1))
}

/// Field elements per `pi_Mul` reply, for the size report.
pub fn reply_scalars() -> usize {
    ELL * 5 + 1
}
