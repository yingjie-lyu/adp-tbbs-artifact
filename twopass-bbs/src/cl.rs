//! The Castagnos–Laguillaumie encryption scheme over BICYCL's `CL_HSMqk`.
//!
//! Paper §2.2. `G = <g_q> × <f>` with `f` of order `q` (the pairing group's scalar order) and
//! `g_q` the hard-subgroup generator of unknown order `s'`. Plaintext space `Z_q`, so — unlike
//! Paillier — no range proof is needed for the encrypted values.
//!
//! ```text
//! CL-KeyGen   dk <- D_q,  ek = g_q^dk
//! CL-Enc(ek, m; rho) = (g_q^rho, f^m ek^rho)
//! CL-Dec(dk, (c1,c2)) = Dlog(c2 / c1^dk)
//! C_{m+m'} = (c1 c1', c2 c2'),      C_{a m} = (c1^a, c2^a)
//! ```
//!
//! `D_q` is `[0, 2^{lambda_s} s_bar)`. The paper writes `[0, 2^{lambda_s} q s]`; the extra `q`
//! factor is not needed for `g_q^rho` to be near-uniform in `<g_q>` (whose order is `s' <= s_bar`)
//! and dropping it shortens every `rho` response by 256 bits.
//!
//! `Dlog` is BICYCL's `dlog_in_F`, which is exact on kernel elements. Decryption here always
//! feeds it an exact kernel element (`c2 / c1^dk = f^m`), so the maximal-order projection is
//! only a guard against a malformed ciphertext from the peer.

use bicycl::{CL_HSMqk, Mpz, QFI, RandGen};

use threshold_bbs::algebra::Scalar;
use threshold_bbs::bls381::Scalar255;
use threshold_bbs::util::{mpz_bits, mpz_to_scalar, pow2};

use crate::error::{Error, Result};
use crate::meter::{Meter, Op};
use crate::wire::{self, Reader};

/// `rho` and `dk` are ~1000 bits at production parameters; `Z_q` exponents are 255.
const LONG_EXPONENT_BITS: usize = 400;

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
    lambda_s: usize,
}

impl ClParameters {
    /// `CL.Gen(1^lambda, q)`.
    pub fn setup(q: &Mpz, delta_k_bits: usize, lambda: usize, lambda_s: usize) -> Self {
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
            bound_dq: pow2(lambda_s) * bound_s.clone(),
            bound_s,
            lambda,
            lambda_s,
        }
    }

    pub fn group(&self) -> &CL_HSMqk {
        &self.group
    }

    /// `g_q`, order `s'`.
    pub fn gq(&self) -> &QFI {
        &self.gq
    }

    /// `f`, order `q`.
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

    /// `D_q = [0, 2^{lambda_s} s_bar)`.
    pub fn bound_dq(&self) -> &Mpz {
        &self.bound_dq
    }

    pub fn lambda(&self) -> usize {
        self.lambda
    }

    pub fn lambda_s(&self) -> usize {
        self.lambda_s
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
        base.exp(&self.group, &threshold_bbs::util::scalar_to_mpz(value))
    }

    pub fn compose(&self, lhs: &QFI, rhs: &QFI, meter: &mut Meter) -> QFI {
        meter.add(Op::Compose);
        lhs.compose(&self.group, rhs)
    }

    pub fn invert(&self, value: &QFI, meter: &mut Meter) -> QFI {
        meter.add(Op::ClassExpShort);
        value.exp(&self.group, &Mpz::from(-1i64))
    }

    /// `f^m`; closed form in BICYCL, free in the cost model.
    pub fn f_exp(&self, m: &Scalar255) -> QFI {
        self.group
            .power_of_f(&threshold_bbs::util::scalar_to_mpz(m))
    }

    /// `f^m` for an integer exponent, reduced mod `q` first.
    pub fn f_exp_mpz(&self, m: &Mpz) -> QFI {
        let reduced = mpz_to_scalar(m);
        self.group
            .power_of_f(&threshold_bbs::util::scalar_to_mpz(&reduced))
    }

    /// `CL-Dec`'s final step: recover `m` from an element of the kernel.
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

    /// Uniform in `[0, D_q)`.
    pub fn sample_dq(&self, rng: &mut RandGen) -> Mpz {
        rng.random_mpz(&self.bound_dq)
    }
}

/// A CL ciphertext `(c1, c2) = (g_q^rho, f^m ek^rho)`.
#[derive(Clone, Debug, PartialEq)]
pub struct Cipher {
    pub c1: QFI,
    pub c2: QFI,
}

impl Cipher {
    pub fn encode(&self, out: &mut Vec<u8>) {
        wire::put_qfi(out, &self.c1);
        wire::put_qfi(out, &self.c2);
    }

    pub fn decode(reader: &mut Reader<'_>, cl: &ClParameters) -> Result<Self> {
        Ok(Self {
            c1: reader.qfi(cl)?,
            c2: reader.qfi(cl)?,
        })
    }

    pub fn encoded_len(&self) -> usize {
        wire::qfi_len(&self.c1) + wire::qfi_len(&self.c2)
    }
}

/// `CL-Enc(ek, m; rho)`.
pub fn encrypt(
    cl: &ClParameters,
    ek: &QFI,
    message: &Scalar255,
    randomness: &Mpz,
    meter: &mut Meter,
) -> Cipher {
    let c1 = cl.exp(cl.gq(), randomness, meter);
    let key = cl.exp(ek, randomness, meter);
    let kernel = cl.f_exp(message);
    let c2 = cl.compose(&key, &kernel, meter);
    Cipher { c1, c2 }
}

/// `C_{m+m'}`: component-wise product.
pub fn add(cl: &ClParameters, lhs: &Cipher, rhs: &Cipher, meter: &mut Meter) -> Cipher {
    Cipher {
        c1: cl.compose(&lhs.c1, &rhs.c1, meter),
        c2: cl.compose(&lhs.c2, &rhs.c2, meter),
    }
}

/// `C_{a m} = (c1^a, c2^a)`. This is the "Scalar multiplication" of §2.2, with the same `a`
/// on both components so the randomness scales too.
pub fn scale(cl: &ClParameters, cipher: &Cipher, factor: &Scalar255, meter: &mut Meter) -> Cipher {
    Cipher {
        c1: cl.exp_scalar(&cipher.c1, factor, meter),
        c2: cl.exp_scalar(&cipher.c2, factor, meter),
    }
}

/// `CL-Dec(dk, (c1, c2)) = Dlog(c2 / c1^dk)`.
pub fn decrypt(cl: &ClParameters, dk: &Mpz, cipher: &Cipher, meter: &mut Meter) -> Result<Scalar255> {
    if !cl.is_form(&cipher.c1) || !cl.is_form(&cipher.c2) {
        return Err(Error::Wire("ciphertext is not a form of Delta_q"));
    }
    let mask = cl.exp(&cipher.c1, dk, meter);
    let inverse = cl.invert(&mask, meter);
    let kernel = cl.compose(&cipher.c2, &inverse, meter);
    Ok(cl.solve(&kernel, meter))
}

/// `CL-KeyGen`: `dk <- D_q`, `ek = g_q^dk`.
pub fn keygen(cl: &ClParameters, rng: &mut RandGen, meter: &mut Meter) -> (QFI, Mpz) {
    let dk = cl.sample_dq(rng);
    let ek = cl.exp(cl.gq(), &dk, meter);
    (ek, dk)
}

/// `CL.Solve` is exported for the report; the protocol itself only decrypts.
pub fn solve(cl: &ClParameters, element: &QFI, meter: &mut Meter) -> Scalar255 {
    cl.solve(element, meter)
}

/// `Scalar::zero` shortcut used by the callers.
pub fn zero() -> Scalar255 {
    <Scalar255 as Scalar>::zero()
}
