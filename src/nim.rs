//! Non-interactive multiplication in the CL-HSM class group.
//!
//! Instantiation of the scalar case of Abram–Roy–Scholl over the NIDLS framework of
//! Abram–Damgård–Orlandi–Scholl, matching the appendix of the paper:
//!
//! * `crs = (Delta_K, Delta_q, q, B, g_z, g_o)` with `g_o = g_z^theta`,
//! * role A encoding `g_z^r * g_o^v`, role B encoding `(g_z^w, f^y * g_o^w)`,
//! * `decode_A = ddlog(c0^r * c1^v)`, `decode_B = -ddlog(d^w)`.
//!
//! `g_z` is BICYCL's `h`, the generator of the q-power (hard) component, and `f` is the
//! kernel generator of order `q`. Note that `ddlog` is only meaningful as a *difference*:
//! individual decodings carry a coset-label offset that cancels when the two halves of one
//! product are added.

use bicycl::{CL_HSMqk, Mpz, RandGen, QFI};

use crate::algebra::{Breakdown, Operation, Scalar};
use crate::bls381::Scalar255;
use crate::util::{mpz_to_scalar, pow2, scalar_to_mpz};

/// Which instantiation of the NIM the CRS implements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NimVariant {
    /// Two bases `g_z, g_o` (the main construction): role B is `(g_z^w, f^y g_o^w)`.
    TwoBase,
    /// Single base `g` (Appendix `sec:sb`): role B is the single element `f^y g^w`, and role A
    /// is `g^{lift(v) + q r}`. Full-length role-B coins.
    SingleBase,
    /// The same, with role-B coins shortened to `2 lambda` bits under SEI.
    SingleBaseShort,
}

impl NimVariant {
    pub fn is_single_base(self) -> bool {
        !matches!(self, NimVariant::TwoBase)
    }

    pub fn label(self) -> &'static str {
        match self {
            NimVariant::TwoBase => "two-base",
            NimVariant::SingleBase => "single-base",
            NimVariant::SingleBaseShort => "single-base+short-exp",
        }
    }
}

/// Public NIM parameters. The trapdoor `theta` is dropped after setup.
#[derive(Clone)]
pub struct NimParameters {
    group: CL_HSMqk,
    g_z: QFI,
    g_o: QFI,
    f: QFI,
    identity: QFI,
    q: Mpz,
    bound_a: Mpz,
    bound_b: Mpz,
    variant: NimVariant,
}

pub struct EncodedA {
    pub element: QFI,
    pub randomness: Mpz,
}

#[derive(Clone, Debug)]
pub struct EncodedB {
    pub c0: QFI,
    pub c1: QFI,
    pub randomness: Mpz,
}

impl NimParameters {
    /// Build the CRS.
    ///
    /// `s_bound_bits` is `log2(B)` from the paper (`B >= ord(Cl(Delta_K))`, about 922 bits
    /// for a 1827-bit `Delta_K`). The randomness bounds are then
    /// `N_A = 2^kappa * q * 2^s_bound_bits` and `N_B = 2^kappa * 2^s_bound_bits`, which gives
    /// the appendix's ~1257-bit and ~1002-bit coins.
    pub fn setup(q: Mpz, delta_k_bits: usize, s_bound_bits: usize, kappa_stat: usize) -> Self {
        let mut rng = RandGen::new();
        // 128 is BICYCL's fudge factor for the CL-HSM, which fixes the exponent bound.
        let group =
            CL_HSMqk::with_rand_gen(&q, 1, delta_k_bits, &mut rng, &Mpz::from(128u64), false);

        let bound_a = pow2(kappa_stat) * q.clone() * pow2(s_bound_bits);
        let bound_b = pow2(kappa_stat) * pow2(s_bound_bits);

        let g_z = group.h();
        let theta = rng.random_mpz(&bound_a);
        let g_o = g_z.exp(&group, &theta);
        let f = group.power_of_f(&Mpz::from(1u64));

        let identity = group.power_of_f(&Mpz::from(0u64));
        Self {
            group,
            g_z,
            g_o,
            f,
            identity,
            q,
            bound_a,
            bound_b,
            variant: NimVariant::TwoBase,
        }
    }

    /// The single-base CRS of Appendix `sec:sb`: only `g` and `f`, no trapdoor.
    ///
    /// `N_A = 2^kappa * 2^{s_bound_bits}` (no factor `q`, since the role-A shift is a residue
    /// modulo `ord(g)`), and `N_B` is the same for full coins or `2^{2 lambda}` for short ones.
    pub fn setup_single_base(
        q: Mpz,
        delta_k_bits: usize,
        s_bound_bits: usize,
        kappa_stat: usize,
        short_coins: bool,
        lambda: usize,
    ) -> Self {
        let mut rng = RandGen::new();
        let group =
            CL_HSMqk::with_rand_gen(&q, 1, delta_k_bits, &mut rng, &Mpz::from(128u64), false);

        let bound_a = pow2(kappa_stat) * pow2(s_bound_bits);
        let bound_b = if short_coins {
            pow2(2 * lambda)
        } else {
            bound_a.clone()
        };

        let g_z = group.h();
        let f = group.power_of_f(&Mpz::from(1u64));
        let identity = group.power_of_f(&Mpz::from(0u64));

        Self {
            group,
            g_o: g_z.clone(),
            g_z,
            f,
            identity,
            q,
            bound_a,
            bound_b,
            variant: if short_coins {
                NimVariant::SingleBaseShort
            } else {
                NimVariant::SingleBase
            },
        }
    }

    pub fn variant(&self) -> NimVariant {
        self.variant
    }

    /// The principal form, used as the placeholder `c1` in the single-base variant.
    pub fn identity(&self) -> &QFI {
        &self.identity
    }

    pub fn group(&self) -> &CL_HSMqk {
        &self.group
    }
    pub fn modulus(&self) -> &Mpz {
        &self.q
    }
    pub fn g_z(&self) -> &QFI {
        &self.g_z
    }
    pub fn g_o(&self) -> &QFI {
        &self.g_o
    }
    pub fn f(&self) -> &QFI {
        &self.f
    }
    pub fn bound_a(&self) -> &Mpz {
        &self.bound_a
    }
    pub fn bound_b(&self) -> &Mpz {
        &self.bound_b
    }

    /// `b^2 - 4ac = Delta_q`, the cheap discriminant check that lets a verifier reject a
    /// malformed form before handing it to the backend.
    pub fn is_form_of(&self, form: &QFI) -> bool {
        let (a, b, c) = (form.a(), form.b(), form.c());
        let discriminant = b.clone() * b - Mpz::from(4u64) * a * c;
        discriminant == self.group.discriminant()
    }

    /// Role-A encoding `g_z^r * g_o^lift(v)` with fresh `r in [0, N_A)`.
    pub fn encode_a(
        &self,
        value: &Scalar255,
        rng: &mut RandGen,
        stats: &mut Breakdown,
    ) -> EncodedA {
        let randomness = rng.random_mpz(&self.bound_a);
        let element = self.encode_a_with(value, &randomness, stats);
        EncodedA {
            element,
            randomness,
        }
    }

    /// Deterministic role-A encoding with given coins.
    pub fn encode_a_with(&self, value: &Scalar255, randomness: &Mpz, stats: &mut Breakdown) -> QFI {
        if self.variant.is_single_base() {
            // `pe_A = g^{lift(v) + q r}`: one long exponentiation.
            let exponent = scalar_to_mpz(value) + self.q.clone() * randomness.clone();
            return self.measure_exp(&self.g_z, &exponent, true, stats);
        }
        let first = self.measure_exp(&self.g_z, randomness, true, stats);
        let second = self.measure_exp(&self.g_o, &scalar_to_mpz(value), false, stats);
        crate::algebra::measure(stats, Operation::ClassGroupComposition, || {
            first.compose(&self.group, &second)
        })
    }

    /// Role-B encoding `(g_z^w, f^lift(y) * g_o^w)` with fresh `w in [0, N_B)`.
    pub fn encode_b(
        &self,
        value: &Scalar255,
        rng: &mut RandGen,
        stats: &mut Breakdown,
    ) -> EncodedB {
        let randomness = rng.random_mpz(&self.bound_b);
        if self.variant.is_single_base() {
            // `pe_B = f^{lift(y)} g^{w}`: one element instead of a pair.
            let message = self.f.exp(&self.group, &scalar_to_mpz(value));
            let long = !matches!(self.variant, NimVariant::SingleBaseShort);
            let blind = self.measure_exp(&self.g_z, &randomness, long, stats);
            let c0 = crate::algebra::measure(stats, Operation::ClassGroupComposition, || {
                message.compose(&self.group, &blind)
            });
            return EncodedB {
                c0,
                c1: self.identity.clone(),
                randomness,
            };
        }
        let c0 = self.measure_exp(&self.g_z, &randomness, true, stats);
        // Powers of the kernel generator are closed form and not counted.
        let message = self.f.exp(&self.group, &scalar_to_mpz(value));
        let blind = self.measure_exp(&self.g_o, &randomness, true, stats);
        let c1 = crate::algebra::measure(stats, Operation::ClassGroupComposition, || {
            message.compose(&self.group, &blind)
        });
        EncodedB { c0, c1, randomness }
    }

    /// `decode_A(crs, pe_B, (r, v)) = ddlog(c0^r * c1^lift(v))`.
    pub fn decode_a(
        &self,
        encoded: &EncodedB,
        randomness_a: &Mpz,
        value: &Scalar255,
        stats: &mut Breakdown,
    ) -> Scalar255 {
        if self.variant.is_single_base() {
            // `ddlog(pe_B^{lift(v) + q r})`.
            let exponent = scalar_to_mpz(value) + self.q.clone() * randomness_a.clone();
            let powered = self.measure_exp(&encoded.c0, &exponent, true, stats);
            return mpz_to_scalar(&self.ddlog(&powered, stats));
        }
        let first = self.measure_exp(&encoded.c0, randomness_a, true, stats);
        let second = self.measure_exp(&encoded.c1, &scalar_to_mpz(value), false, stats);
        let combined = crate::algebra::measure(stats, Operation::ClassGroupComposition, || {
            first.compose(&self.group, &second)
        });
        mpz_to_scalar(&self.ddlog(&combined, stats))
    }

    /// `decode_B(crs, pe_A, w) = -ddlog(pe_A^w)`, returned in `Z_q`.
    pub fn decode_b(
        &self,
        encoded: &EncodedA,
        randomness_b: &Mpz,
        stats: &mut Breakdown,
    ) -> Scalar255 {
        let powered = self.measure_exp(&encoded.element, randomness_b, true, stats);
        Scalar255::zero().sub(&mpz_to_scalar(&self.ddlog(&powered, stats)))
    }

    /// `ddlog(alpha) = dlog_f(alpha / lab(alpha))`: project onto the kernel with the
    /// ideal-extension coset label, then take the easy discrete logarithm in `F`.
    pub fn ddlog(&self, value: &QFI, stats: &mut Breakdown) -> Mpz {
        let mut label = value.clone();
        crate::algebra::measure(stats, Operation::ClassGroupCosetLabel, || {
            label.to_maximal_order(&self.q, &self.group.discriminant_K(), true)
        });
        crate::algebra::measure(stats, Operation::ClassGroupReduction, || {
            label.lift(&self.q)
        });
        let inverse = label.exp(&self.group, &Mpz::from(-1i64));
        let kernel = value.compose(&self.group, &inverse);
        crate::algebra::measure(stats, Operation::ClassGroupKernelDlog, || {
            self.group.dlog_in_F(&kernel)
        })
    }

    fn measure_exp(&self, base: &QFI, exponent: &Mpz, long: bool, stats: &mut Breakdown) -> QFI {
        let op = if long {
            Operation::ClassGroupExponentiationLong
        } else {
            Operation::ClassGroupExponentiationShort
        };
        crate::algebra::measure(stats, op, || base.exp(&self.group, exponent))
    }
}
