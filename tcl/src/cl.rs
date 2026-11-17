//! The CL framework, its homomorphic operations, and the `Delta`-normalised threshold view
//! the two threshold-BBS+ papers use.

use std::sync::Arc;

use bicycl::{CL_HSMqk, Mpz, QFI, RandGen};

use threshold_bbs::algebra::Scalar;
use threshold_bbs::bls381::Scalar255;
use threshold_bbs::util::{mpz_bits, mpz_to_scalar, pow2, scalar_to_mpz};

use crate::error::{Error, Result};
use crate::meter::{Meter, Op};
use crate::share;
use crate::util::factorial;
use crate::wire::{self, Reader};

const LONG_EXPONENT_BITS: usize = 400;

/// `pp_cl = (s̃, q, f, g_q, F, G^q, Ĝ)` plus the sampling bound.
#[derive(Clone)]
pub struct ClParameters {
    group: CL_HSMqk,
    gq: QFI,
    f: QFI,
    identity: QFI,
    q: Mpz,
    delta_k: Mpz,
    bound_s: Mpz,
    bound_dq: Mpz,
    lambda: usize,
    lambda_d: usize,
}

impl ClParameters {
    pub fn setup(q: &Mpz, delta_k_bits: usize, lambda: usize, lambda_d: usize) -> Self {
        let mut rng = crate::random::fresh_rng();
        let group = CL_HSMqk::with_rand_gen(q, 1, delta_k_bits, &mut rng, &Mpz::from(128u64), false);
        let gq = group.h();
        let f = group.power_of_f(&Mpz::from(1u64));
        let identity = group.power_of_f(&Mpz::from(0u64));
        let bound_s = group.encrypt_randomness_bound();
        let delta_k = group.discriminant_K();
        Self {
            group,
            gq,
            f,
            identity,
            q: q.clone(),
            delta_k,
            bound_dq: pow2(lambda_d) * bound_s.clone(),
            bound_s,
            lambda,
            lambda_d,
        }
    }

    pub fn group(&self) -> &CL_HSMqk {
        &self.group
    }
    pub fn gq(&self) -> &QFI {
        &self.gq
    }
    pub fn f(&self) -> &QFI {
        &self.f
    }
    pub fn identity(&self) -> &QFI {
        &self.identity
    }
    pub fn modulus(&self) -> &Mpz {
        &self.q
    }
    pub fn bound_s(&self) -> &Mpz {
        &self.bound_s
    }
    /// `D_q = [0, 2^{lambda_d} s̃)`.
    pub fn bound_dq(&self) -> &Mpz {
        &self.bound_dq
    }
    pub fn lambda(&self) -> usize {
        self.lambda
    }
    pub fn lambda_d(&self) -> usize {
        self.lambda_d
    }

    pub fn exp(&self, base: &QFI, exponent: &Mpz, meter: &mut Meter) -> QFI {
        let op = if mpz_bits(exponent) > LONG_EXPONENT_BITS {
            Op::ClassExpLong
        } else {
            Op::ClassExpShort
        };
        meter.add(op);
        base.exp(&self.group, exponent)
    }

    pub fn exp_scalar(&self, base: &QFI, value: &Scalar255, meter: &mut Meter) -> QFI {
        meter.add(Op::ClassExpShort);
        base.exp(&self.group, &scalar_to_mpz(value))
    }

    pub fn compose(&self, lhs: &QFI, rhs: &QFI, meter: &mut Meter) -> QFI {
        meter.add(Op::Compose);
        lhs.compose(&self.group, rhs)
    }

    pub fn compose_many(&self, items: &[QFI], meter: &mut Meter) -> QFI {
        let mut accumulator = self.identity.clone();
        for item in items {
            accumulator = self.compose(&accumulator, item, meter);
        }
        accumulator
    }

    pub fn invert(&self, value: &QFI, meter: &mut Meter) -> QFI {
        meter.add(Op::ClassExpShort);
        value.exp(&self.group, &Mpz::from(-1i64))
    }

    pub fn f_exp(&self, m: &Scalar255) -> QFI {
        self.group.power_of_f(&scalar_to_mpz(m))
    }

    pub fn f_exp_mpz(&self, m: &Mpz) -> QFI {
        self.group.power_of_f(&scalar_to_mpz(&mpz_to_scalar(m)))
    }

    pub fn solve(&self, element: &QFI, meter: &mut Meter) -> Scalar255 {
        let mut label = element.clone();
        label.to_maximal_order(&self.q, &self.delta_k, true);
        label.lift(&self.q);
        let inverse = label.exp(&self.group, &Mpz::from(-1i64));
        let kernel = element.compose(&self.group, &inverse);
        meter.add(Op::Solve);
        mpz_to_scalar(&self.group.dlog_in_F(&kernel))
    }

    pub fn is_form(&self, form: &QFI) -> bool {
        let (a, b, c) = (form.a(), form.b(), form.c());
        let discriminant = b.clone() * b - Mpz::from(4u64) * a * c;
        discriminant == self.group.discriminant()
    }

    pub fn sample_dq(&self, rng: &mut RandGen) -> Mpz {
        rng.random_mpz(&self.bound_dq)
    }
}

/// `(c_0, c_1)`: the CL ciphertext shape used here, `c_0 = g_q^{Delta^2 rho}`,
/// `c_1 = f^m ek^rho`.
#[derive(Clone, Debug, PartialEq)]
pub struct Cipher {
    pub c0: QFI,
    pub c1: QFI,
}

impl Cipher {
    pub fn encode(&self, out: &mut Vec<u8>) {
        wire::put_qfi(out, &self.c0);
        wire::put_qfi(out, &self.c1);
    }

    pub fn decode(reader: &mut Reader<'_>, cl: &ClParameters) -> Result<Self> {
        Ok(Self {
            c0: reader.qfi(cl)?,
            c1: reader.qfi(cl)?,
        })
    }

    pub fn encoded_len(&self) -> usize {
        wire::qfi_len(&self.c0) + wire::qfi_len(&self.c1)
    }
}

// Free-standing operations on `Cipher`, for protocols that do not need the `Delta` view
// (TX25's MtA encrypts under a party's own key with the plain `g_q` base).

/// `CLE.Enc(ek, m; rho) = (g_q^rho, f^m ek^rho)`.
pub fn enc_plain(
    cl: &ClParameters,
    ek: &QFI,
    message: &Scalar255,
    rho: &Mpz,
    meter: &mut Meter,
) -> Cipher {
    let c0 = cl.exp(cl.gq(), rho, meter);
    let mask = cl.exp(ek, rho, meter);
    let kernel = cl.f_exp(message);
    let c1 = cl.compose(&mask, &kernel, meter);
    Cipher { c0, c1 }
}

/// `CLE.Dec(dk, (c0, c1)) = Dlog(c1 / c0^dk)`.
pub fn dec_plain(cl: &ClParameters, dk: &Mpz, cipher: &Cipher, meter: &mut Meter) -> Result<Scalar255> {
    if !cl.is_form(&cipher.c0) || !cl.is_form(&cipher.c1) {
        return Err(Error::Wire("ciphertext is not a form of Delta_q"));
    }
    let mask = cl.exp(&cipher.c0, dk, meter);
    let inverse = cl.invert(&mask, meter);
    let kernel = cl.compose(&cipher.c1, &inverse, meter);
    Ok(cl.solve(&kernel, meter))
}

pub fn add(cl: &ClParameters, lhs: &Cipher, rhs: &Cipher, meter: &mut Meter) -> Cipher {
    Cipher {
        c0: cl.compose(&lhs.c0, &rhs.c0, meter),
        c1: cl.compose(&lhs.c1, &rhs.c1, meter),
    }
}

pub fn add_many(cl: &ClParameters, items: &[Cipher], meter: &mut Meter) -> Cipher {
    let mut accumulator = Cipher {
        c0: cl.identity().clone(),
        c1: cl.identity().clone(),
    };
    for item in items {
        accumulator = add(cl, &accumulator, item, meter);
    }
    accumulator
}

/// `a odot c` without re-randomisation.
pub fn smul_star(cl: &ClParameters, a: &Scalar255, cipher: &Cipher, meter: &mut Meter) -> Cipher {
    Cipher {
        c0: cl.exp_scalar(&cipher.c0, a, meter),
        c1: cl.exp_scalar(&cipher.c1, a, meter),
    }
}

/// The `Delta`-normalised threshold CL view shared by both papers.
///
/// `Delta = n!`, `Delta^{-2}` as a field element, plus the two class-group bases the
/// ciphertext and the partial decryption use: `g_q^{Delta^2}` and `g_q^{Delta}`.
#[derive(Clone)]
pub struct ThresholdCl {
    pub cl: Arc<ClParameters>,
    pub delta: Mpz,
    pub gq_delta: QFI,
    pub gq_delta2: QFI,
    /// Honest upper bound on a Z-SS share: `n^t 2^{l^* + lambda_d}`. The partial-decryption
    /// proof masks and range-checks against *this*, not against `D_q`, because the share is an
    /// integer, not a residue.
    pub share_bound: Mpz,
    delta_inv2: Scalar255,
}

impl ThresholdCl {
    pub fn new(cl: Arc<ClParameters>, n: usize, t: usize, meter: &mut Meter) -> Self {
        let delta = factorial(n);
        let zss = crate::share::Zss::new(n, t, crate::util::bits(cl.bound_dq()), cl.lambda_d());
        let share_bound = zss.share_bound(n, t);
        let gq_delta = cl.exp(cl.gq(), &delta, meter);
        let gq_delta2 = cl.exp(&gq_delta, &delta, meter);
        let delta_scalar = mpz_to_scalar(&delta);
        let inverse = delta_scalar
            .invert()
            .expect("Delta is invertible mod q");
        Self {
            cl,
            delta,
            gq_delta,
            gq_delta2,
            share_bound,
            delta_inv2: inverse.mul(&inverse),
        }
    }

    pub fn delta_inv2(&self) -> &Scalar255 {
        &self.delta_inv2
    }

    /// `t-CL.Enc(ek, m; rho) = (g_q^{Delta^2 rho}, f^m ek^rho)`.
    pub fn enc(&self, ek: &QFI, message: &Scalar255, rho: &Mpz, meter: &mut Meter) -> Cipher {
        let c0 = self.cl.exp(&self.gq_delta2, rho, meter);
        let mask = self.cl.exp(ek, rho, meter);
        let kernel = self.cl.f_exp(message);
        let c1 = self.cl.compose(&mask, &kernel, meter);
        Cipher { c0, c1 }
    }

    /// `Enc` with the plain `g_q` base (`CLE.Enc` before the threshold normalisation).
    pub fn enc_plain(&self, ek: &QFI, message: &Scalar255, rho: &Mpz, meter: &mut Meter) -> Cipher {
        let c0 = self.cl.exp(self.cl.gq(), rho, meter);
        let mask = self.cl.exp(ek, rho, meter);
        let kernel = self.cl.f_exp(message);
        let c1 = self.cl.compose(&mask, &kernel, meter);
        Cipher { c0, c1 }
    }

    pub fn add(&self, lhs: &Cipher, rhs: &Cipher, meter: &mut Meter) -> Cipher {
        Cipher {
            c0: self.cl.compose(&lhs.c0, &rhs.c0, meter),
            c1: self.cl.compose(&lhs.c1, &rhs.c1, meter),
        }
    }

    pub fn add_many(&self, items: &[Cipher], meter: &mut Meter) -> Cipher {
        let mut accumulator = Cipher {
            c0: self.cl.identity.clone(),
            c1: self.cl.identity.clone(),
        };
        for item in items {
            accumulator = self.add(&accumulator, item, meter);
        }
        accumulator
    }

    /// `a odot c` with fresh randomness, as in `CLE.Eval(a, c, ·)`.
    pub fn smul_with_key(
        &self,
        a: &Scalar255,
        c: &Cipher,
        rho: &Mpz,
        ek: &QFI,
        meter: &mut Meter,
    ) -> Cipher {
        let scaled = self.smul_star(a, c, meter);
        let c0 = self
            .cl
            .compose(&scaled.c0, &self.cl.exp(&self.gq_delta2, rho, meter), meter);
        let mask = self.cl.exp(ek, rho, meter);
        let c1 = self.cl.compose(&scaled.c1, &mask, meter);
        Cipher { c0, c1 }
    }

    /// `SMul^*`: deterministic, no re-randomisation.
    pub fn smul_star(&self, a: &Scalar255, c: &Cipher, meter: &mut Meter) -> Cipher {
        Cipher {
            c0: self.cl.exp_scalar(&c.c0, a, meter),
            c1: self.cl.exp_scalar(&c.c1, a, meter),
        }
    }

    pub fn neg(&self, c: &Cipher, meter: &mut Meter) -> Cipher {
        Cipher {
            c0: self.cl.invert(&c.c0, meter),
            c1: self.cl.invert(&c.c1, meter),
        }
    }

    /// `cpd_i = c_0^{Delta k_i}`.
    pub fn part_dec(&self, c: &Cipher, share: &Mpz, meter: &mut Meter) -> QFI {
        let exponent = crate::util::mul(&self.delta, share);
        self.cl.exp(&c.c0, &exponent, meter)
    }

    /// `c_1^{Delta^2} / prod_i cpd_i^{Delta L_i}`, then `Dlog(.) / Delta^2`.
    pub fn combine(
        &self,
        c: &Cipher,
        partials: &[(usize, QFI)],
        quorum: &[usize],
        meter: &mut Meter,
    ) -> Result<Scalar255> {
        if quorum.len() < 2 {
            return Err(Error::Protocol("need at least two partial decryptions"));
        }
        let mut weights = Vec::with_capacity(partials.len());
        for (id, partial) in partials {
            let weight = share::delta_lagrange(&self.delta, *id, quorum);
            weights.push(self.cl.exp(partial, &weight, meter));
        }
        let combined = self.cl.compose_many(&weights, meter);
        let numerator = self
            .cl
            .exp(&c.c1, &crate::util::square(&self.delta), meter);
        let denominator = self.cl.invert(&combined, meter);
        let kernel = self.cl.compose(&numerator, &denominator, meter);
        Ok(self.cl.solve(&kernel, meter).mul(&self.delta_inv2))
    }

    /// Single-key decryption, for fixtures: `c_1^{Delta^2} / c_0^{Delta^3 k}`.
    pub fn dec(&self, c: &Cipher, key: &Mpz, meter: &mut Meter) -> Result<Scalar255> {
        let exponent = crate::util::mul(&crate::util::mul(&self.delta, &self.delta), &crate::util::mul(&self.delta, key));
        let mask = self.cl.exp(&c.c0, &exponent, meter);
        let inverse = self.cl.invert(&mask, meter);
        let kernel = self.cl.compose(&c.c1, &inverse, meter);
        let plain = self.cl.solve(&kernel, meter).mul(&self.delta_inv2);
        Ok(plain)
    }
}
