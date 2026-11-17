//! End-to-end: two rounds plus client assembly, for a few signer counts.

use bls12_381::Scalar;
use ff::Field;

use dklst_bbs::mul::MulVariant;
use dklst_bbs::params::{ELL, KAPPA, LAMBDA, ROUND1_BYTES};
use dklst_bbs::sign::{
    combine, keygen, multiplications_per_signer, verify, OtMaterial, PublicParams, Response, Round1,
    Round2, Signer,
};

fn message(len: usize) -> Vec<Scalar> {
    (0..len)
        .map(|index| Scalar::from(index as u64 + 1))
        .collect()
}

/// Bits one signer puts on the wire per peer, from our own accounting constants.
///
/// * sender side of a `pi_Mul`: the correlation publication plus `r, u`;
/// * receiver side: the extension's choice message (`sl-oblivious` round 1, `ROUND1_BYTES`);
/// * the round-1 commitment (`2*lambda`) and the round-2 opening (`2*kappa`).
fn bits_per_peer(variant: MulVariant) -> u64 {
    let mul = (ELL * variant.bits_per_ot() + (ELL + 1) * KAPPA) as u64;
    let extension = (ROUND1_BYTES * 8) as u64;
    let commit = (2 * LAMBDA) as u64;
    let open = (2 * KAPPA) as u64;
    mul + extension + commit + open
}

fn session(signers: usize, t: usize, variant: MulVariant) -> (bool, u64) {
    let pp = PublicParams::new(2);
    let parties: Vec<usize> = (1..=signers).collect();
    let keys = keygen(&parties, t);
    let public = keys[0].public;
    let material = OtMaterial::with_backend(&parties, dklst_bbs::ot::Backend::SlOblivious, variant)
        .expect("setup");

    let mut party_signers: Vec<Signer> = keys
        .into_iter()
        .map(|item| Signer::new(item, &parties, pp.clone()))
        .collect();

    let sid = format!("sess-{signers}-{t}-{}", variant.name());
    let sid = sid.as_bytes();
    let round1: Vec<Round1> = party_signers
        .iter_mut()
        .map(|signer| signer.round1(sid, &material))
        .collect();
    let round2: Vec<Round2> = party_signers
        .iter_mut()
        .map(|signer| signer.round2(sid, &material, &round1))
        .collect();

    let msg = message(2);
    let responses: Vec<Response> = party_signers
        .iter_mut()
        .map(|signer| signer.finish(sid, &round1, &round2, &msg))
        .collect();

    // `counters()` belong to a single signer, so they are not halved here.
    let bits: u64 = party_signers.iter().map(|signer| signer.counters().bits).sum();

    let (a, s, e) = combine(&responses).expect("invertible denominator");
    let ok = verify(&pp, &public, &msg, &a, &e, &s);

    println!(
        "t = {signers}/{t} [{:<10}]: multiplications per signer {}, bits per signer {}",
        variant.name(),
        multiplications_per_signer(signers),
        bits / signers as u64
    );
    (ok, bits / signers as u64)
}

#[test]
fn two_of_two() {
    for variant in [MulVariant::Correction, MulVariant::Masked] {
        let (ok, _) = session(2, 2, variant);
        assert!(ok, "signature must verify");
    }
}

#[test]
fn three_of_three() {
    for variant in [MulVariant::Correction, MulVariant::Masked] {
        let (ok, bits) = session(3, 3, variant);
        assert!(ok, "signature must verify");
        assert_eq!(
            bits,
            (3 - 1) * bits_per_peer(variant),
            "per-signer wire accounting ({})",
            variant.name()
        );
    }
}

/// Isolates the pairing code from the protocol: build `A = B/(x+e)` from the dealer's shares.
#[test]
fn pairing_check_is_correct() {
    let pp = PublicParams::new(2);
    let parties: Vec<usize> = (1..=2).collect();
    let keys = keygen(&parties, 2);
    let public = keys[0].public;

    let lambda = |id: usize| {
        let mut num = Scalar::ONE;
        let mut den = Scalar::ONE;
        for peer in &parties {
            if *peer == id {
                continue;
            }
            num *= Scalar::from(*peer as u64);
            den *= Scalar::from((*peer as i64 - id as i64).unsigned_abs());
            if *peer < id {
                num = -num;
            }
        }
        num * den.invert().unwrap()
    };
    let x: Scalar = keys
        .iter()
        .map(|item| lambda(item.id) * item.share)
        .sum();

    let msg = message(2);
    let e = Scalar::from(42u64);
    let s = Scalar::from(7u64);
    let b = pp.big_b(&s, &msg);
    let a = b * (x + e).invert().unwrap();
    assert!(verify(&pp, &public, &msg, &a, &e, &s), "pairing check");
}
