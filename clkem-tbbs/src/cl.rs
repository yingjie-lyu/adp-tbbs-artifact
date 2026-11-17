//! The CL framework and the CL-KEM view of threshold decryption.
//!
//! Paper §2.2. The class group is BICYCL's `CL_HSMqk` at `k = 1`, i.e. `Cl(Delta)` with
//! `Delta = -p q^3`, split as `G = <g_q> x <f>` where
//!
//! * `g_q` — the paper's `gothic_g_q` — is BICYCL's `h`, the hard-subgroup generator of
//!   unknown order `s'`,
//! * `f` is the kernel generator of prime order `q`, the pairing group's scalar order, so
//!   the plaintext space is exactly `Z_q`.
//!
//! `CL.Solve` is `dlog_in_F` after projecting onto the kernel with the maximal-order coset
//! label; at `k = 1` BICYCL returns the exponent directly, with no discrete-log search.
//!
//! Randomness bounds follow the paper: `B_q = 2^{lambda_d} * s_bar` and `B = q * B_q`, with
//! `s_bar` taken from BICYCL's own `encrypt_randomness_bound` (about `2^{914}` at the
//! paper's 1828-bit discriminant). Sampling `[0, B_q)` gives a distribution on `Z_{s'}`
//! within `2^{-lambda_d}` of uniform, which is what the modified scaling argument needs.

use bicycl::{CL_HSMqk, Mpz, QFI, RandGen};

use threshold_bbs::bls381::Scalar255;
use threshold_bbs::util::{mpz_bits, mpz_to_scalar, pow2, scalar_to_mpz};

use crate::stats::{Meter, Op};


/// Exponents longer than this are counted as "long" in the cost report. The two regimes are
/// `gamma_i ~ B` (~1000 bits) and everything that is a `Z_q` scalar (~255 bits).
const LONG_EXPONENT_BITS: usize = 400;

/// `pp_cl = (q, s_bar, f, g_q, G_hat, F)` plus the sampling bounds.
#[derive(Clone)]
pub struct ClParameters {
    group: CL_HSMqk,
    gq: QFI,
    f: QFI,
    identity: QFI,
    q: Mpz,
    delta_k: Mpz,
    bound_s: Mpz,
    bound_bq: Mpz,
    bound_b: Mpz,
    lambda: usize,
    lambda_d: usize,
}

impl ClParameters {
    /// `CL.Gen(1^lambda, q)`, instantiated with BICYCL.
    pub fn setup(q: &Mpz, delta_k_bits: usize, lambda: usize, lambda_d: usize) -> Self {
        let mut rng = crate::random::fresh_rng();
        // 128 is BICYCL's fudge factor for the CL-HSM; it fixes the exponent bounds.
        let group = CL_HSMqk::with_rand_gen(q, 1, delta_k_bits, &mut rng, &Mpz::from(128u64), false);
        let gq = group.h();
        let f = group.power_of_f(&Mpz::from(1u64));
        let identity = group.power_of_f(&Mpz::from(0u64));
        let bound_s = group.encrypt_randomness_bound();
        let bound_bq = pow2(lambda_d) * bound_s.clone();
        let bound_b = q.clone() * bound_bq.clone();
        let delta_k = group.discriminant_K();
        Self {
            group,
            gq,
            f,
            identity,
            q: q.clone(),
            delta_k,
            bound_s,
            bound_bq,
            bound_b,
            lambda,
            lambda_d,
        }
    }

    pub fn group(&self) -> &CL_HSMqk {
        &self.group
    }

    /// `gothic_g_q`, order `s'`.
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

    /// `s_bar`, the class-number upper bound.
    pub fn bound_s(&self) -> &Mpz {
        &self.bound_s
    }

    /// `B_q = 2^{lambda_d} s_bar`, the bound for `D_q`.
    pub fn bound_bq(&self) -> &Mpz {
        &self.bound_bq
    }

    /// `B = 2^{lambda_d} q s_bar`, the bound for `D`.
    pub fn bound_b(&self) -> &Mpz {
        &self.bound_b
    }

    pub fn lambda(&self) -> usize {
        self.lambda
    }

    pub fn lambda_d(&self) -> usize {
        self.lambda_d
    }

    /// `base^exponent` in the class group. The exponent may be negative (BICYCL handles it)
    /// and may exceed `s'`, which is exactly what the modified scaling relies on.
    pub fn exp(&self, base: &QFI, exponent: &Mpz, meter: &mut Meter) -> QFI {
        let op = if mpz_bits(exponent) > LONG_EXPONENT_BITS {
            Op::ClassExpLong
        } else {
            Op::ClassExpShort
        };
        meter.add(op);
        base.exp(&self.group, exponent)
    }

    /// `base^value` for a `Z_q` scalar.
    pub fn exp_scalar(&self, base: &QFI, value: &Scalar255, meter: &mut Meter) -> QFI {
        meter.add(Op::ClassExpShort);
        base.exp(&self.group, &scalar_to_mpz(value))
    }

    pub fn compose(&self, lhs: &QFI, rhs: &QFI, meter: &mut Meter) -> QFI {
        meter.add(Op::Compose);
        lhs.compose(&self.group, rhs)
    }

    pub fn invert(&self, value: &QFI, meter: &mut Meter) -> QFI {
        meter.add(Op::ClassExpShort);
        value.exp(&self.group, &Mpz::from(-1i64))
    }

    /// `f^m`, closed form in BICYCL and free in the cost model.
    pub fn f_exp(&self, m: &Scalar255) -> QFI {
        self.group.power_of_f(&scalar_to_mpz(m))
    }

    /// `f^m` for an integer exponent, reduced mod `q` first.
    pub fn f_exp_mpz(&self, m: &Mpz) -> QFI {
        let reduced = mpz_to_scalar(m);
        self.group.power_of_f(&scalar_to_mpz(&reduced))
    }

    /// `CL.Solve`: recover `m` from a kernel element `f^m`.
    ///
    /// `CL.Solve` is only defined on `F = <f>` (paper §2.2), and the protocol only ever calls
    /// it on such an element: `prod_j pd_j = f^{Delta^2 gamma (x+e)}` holds *as a group
    /// element*, because the hard components `K^{gamma Delta^2}` cancel exactly against
    /// `(phi_{K^gamma}^{Delta^2})^{sk}`.
    ///
    /// The coset-label projection below is defensive, not mathematical: given an element with
    /// a hard component it lands in `F` but with a coset-label offset added, so it does not
    /// recover that element's kernel exponent (this is the same caveat as the parent crate's
    /// `ddlog`, which is only meaningful as a difference). Its purpose here is to guarantee
    /// the input handed to BICYCL's `dlog_in_F` really is a form of `F`, so a malformed `pd_i`
    /// from a corrupted signer yields a wrong `u` — caught by the final pairing check —
    /// instead of reaching a C++ path that aborts the process.
    pub fn solve(&self, element: &QFI, meter: &mut Meter) -> Scalar255 {
        let mut label = element.clone();
        label.to_maximal_order(&self.q, &self.delta_k, true);
        label.lift(&self.q);
        let inverse = label.exp(&self.group, &Mpz::from(-1i64));
        let kernel = element.compose(&self.group, &inverse);
        meter.add(Op::Solve);
        mpz_to_scalar(&self.group.dlog_in_F(&kernel))
    }

    /// `b^2 - 4ac = Delta_q`: the cheap membership test applied before any backend call.
    pub fn is_form(&self, form: &QFI) -> bool {
        let (a, b, c) = (form.a(), form.b(), form.c());
        let discriminant = b.clone() * b - Mpz::from(4u64) * a * c;
        discriminant == self.group.discriminant()
    }

    /// Uniform in `[0, B_q)`, i.e. the paper's `D_q`.
    pub fn sample_dq(&self, rng: &mut RandGen) -> Mpz {
        rng.random_mpz(&self.bound_bq)
    }

    /// Uniform in `[0, B)`, i.e. the paper's `D`.
    pub fn sample_d(&self, rng: &mut RandGen) -> Mpz {
        rng.random_mpz(&self.bound_b)
    }

    /// `(g_q)^{Delta}` for the PVSS commitments.
    pub fn gq_pow_delta(&self, delta: &Mpz, meter: &mut Meter) -> QFI {
        self.exp(&self.gq, delta, meter)
    }

    /// `base^w * other^v`, the two-base product that shows up in verification.
    pub fn compose_powers(
        &self,
        base: &QFI,
        w: &Mpz,
        other: &QFI,
        v: &Mpz,
        meter: &mut Meter,
    ) -> QFI {
        let first = self.exp(base, w, meter);
        let second = self.exp(other, v, meter);
        self.compose(&first, &second, meter)
    }
}

/// `Encap(pk; r) -> (phi_K, K)` with `phi_K = g_q^r` and `K = pk^r`.
pub fn encap(cl: &ClParameters, pk: &QFI, r: &Mpz, meter: &mut Meter) -> (QFI, QFI) {
    let phi = cl.exp(cl.gq(), r, meter);
    let key = cl.exp(pk, r, meter);
    (phi, key)
}

/// `Dem(K, m) = K * f^m`, the symmetric half of the CL ciphertext.
pub fn dem(cl: &ClParameters, key: &QFI, message: &Scalar255, meter: &mut Meter) -> QFI {
    let kernel = cl.f_exp(message);
    cl.compose(key, &kernel, meter)
}
