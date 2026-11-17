//! Threshold ElGamal over `G_1`, in the additive notation both papers use for `G_1`.
//!
//! `EG.Enc(X̂, M; r) = (r G_1, M + r X̂)`, `EG.Dec(x̂, (A_1, A_2)) = A_2 - x̂ A_1`.
//! The threshold version shares `x̂` over `Z_q`: `M_i = x̂_i A_1`, and `EG.Combine` computes
//! `A_2 - sum_i L_i M_i`.

use std::collections::BTreeMap;

use threshold_bbs::algebra::Group;
use threshold_bbs::bls381::{Scalar255, G1};

use crate::meter::{Meter, Op};
use crate::share::lagrange_scalar;
use crate::wire::{self, Reader};

#[derive(Clone, Debug, PartialEq)]
pub struct EgCipher {
    pub a1: G1,
    pub a2: G1,
}

impl EgCipher {
    pub fn encode(&self, out: &mut Vec<u8>) {
        wire::put_g1(out, &self.a1);
        wire::put_g1(out, &self.a2);
    }

    pub fn decode(reader: &mut Reader<'_>) -> crate::error::Result<Self> {
        Ok(Self {
            a1: reader.g1()?,
            a2: reader.g1()?,
        })
    }

    pub fn encoded_len(&self) -> usize {
        96
    }
}

/// `EG.Enc(X̂, M; r)`: `(r G_1, M + r X̂)`.
pub fn encrypt_with(
    base: &G1,
    public_key: &G1,
    message: &G1,
    randomness: &Scalar255,
    meter: &mut Meter,
) -> EgCipher {
    meter.add_n(Op::G1Exp, 2);
    EgCipher {
        a1: base.scale(randomness),
        a2: message.combine(&public_key.scale(randomness)),
    }
}

/// `EG.SMul^*`: deterministic scaling, `(a A_1, a A_2)`.
pub fn smul_star(a: &Scalar255, cipher: &EgCipher, meter: &mut Meter) -> EgCipher {
    meter.add_n(Op::G1Exp, 2);
    EgCipher {
        a1: cipher.a1.scale(a),
        a2: cipher.a2.scale(a),
    }
}

/// `EG.Add`.
pub fn add(lhs: &EgCipher, rhs: &EgCipher) -> EgCipher {
    EgCipher {
        a1: lhs.a1.combine(&rhs.a1),
        a2: lhs.a2.combine(&rhs.a2),
    }
}

pub fn add_many(items: &[EgCipher]) -> EgCipher {
    let mut accumulator = EgCipher {
        a1: G1::identity(),
        a2: G1::identity(),
    };
    for item in items {
        accumulator = add(&accumulator, item);
    }
    accumulator
}

/// `EG.Dec(x̂, ·)`.
pub fn decrypt(secret: &Scalar255, cipher: &EgCipher, meter: &mut Meter) -> G1 {
    meter.add(Op::G1Exp);
    cipher
        .a2
        .combine(&cipher.a1.scale(secret).inverse())
}

/// `EG.PartDec`: `M_i = x̂_i A_1`.
pub fn part_dec(share: &Scalar255, cipher: &EgCipher, meter: &mut Meter) -> G1 {
    meter.add(Op::G1Exp);
    cipher.a1.scale(share)
}

/// `EG.Combine`: `A_2 - sum_i L_i M_i`, skipping the shares whose proofs failed.
pub fn combine(
    cipher: &EgCipher,
    partials: &BTreeMap<usize, G1>,
    quorum: &[usize],
    meter: &mut Meter,
) -> G1 {
    let mut total = G1::identity();
    for id in quorum {
        if let Some(partial) = partials.get(id) {
            meter.add(Op::G1Exp);
            total = total.combine(&partial.scale(&lagrange_scalar(*id, quorum)));
        }
    }
    cipher.a2.combine(&total.inverse())
}
