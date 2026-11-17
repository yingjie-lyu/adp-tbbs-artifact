//! `pi_Mul` correctness and its wire cost against DKLs18's formula.

use bls12_381::Scalar;

use dklst_bbs::mul::{
    encode, finish, multiply, omega_as_scalar, public_grip, receive, reply, MulVariant,
};
use dklst_bbs::ot::{base_ot, Counters, OtSetup};
use dklst_bbs::params::{ELL, KAPPA, ROUND1_BYTES};

const VARIANTS: [MulVariant; 2] = [MulVariant::Correction, MulVariant::Masked];

#[test]
fn encoding_represents_the_input() {
    let grip = public_grip(b"test-grip");
    let mut gamma = vec![0u8; 52];
    rand::Rng::fill(&mut rand::thread_rng(), &mut gamma[..]);
    for beta in [Scalar::from(1u64), Scalar::from(7654321u64), -Scalar::from(42u64)] {
        let omega = encode(&grip, &beta, &gamma);
        assert_eq!(omega_as_scalar(&grip, &omega), beta, "sum_j g_j omega_j == beta");
    }
}

#[test]
fn shares_add_up_to_the_product() {
    let grip = public_grip(b"test-grip");
    let setup = OtSetup::new();

    for variant in VARIANTS {
        let mut counters = Counters::default();
        for round in 0..4u64 {
            let alpha = Scalar::from(1234567u64 + round);
            let beta = Scalar::from(7654321u64 + round);
            let (a, b) = multiply(
                &round.to_be_bytes(),
                &setup,
                &setup,
                &alpha,
                &beta,
                &grip,
                variant,
                &mut counters,
            )
            .expect("pi_Mul");
            assert_eq!(a + b, alpha * beta, "t_A + t_B must equal alpha*beta");
        }

        let per_mult = counters.bits / 4;
        println!(
            "{:<10} pi_Mul: {} bits per multiplication (per party {}), {} OTs",
            variant.name(),
            per_mult,
            counters.per_party_bits() / 4,
            counters.ots / 4
        );

        // The two variants differ only in the sender's per-OT publication.
        let expected = (ELL * variant.bits_per_ot() + (ELL + 1) * KAPPA) as u64;
        let extension = (ROUND1_BYTES * 8) as u64; // one sl-oblivious round-1 message
        assert_eq!(per_mult, expected + extension, "{} wire accounting", variant.name());
    }
}

#[test]
fn the_correction_variant_matches_dklst_cost_model() {
    let grip = public_grip(b"test-grip");
    let setup = OtSetup::new();
    let mut counters = Counters::default();
    let alpha = Scalar::from(1234567u64);
    let beta = Scalar::from(7654321u64);
    let (a, b) = multiply(
        b"model",
        &setup,
        &setup,
        &alpha,
        &beta,
        &grip,
        MulVariant::Correction,
        &mut counters,
    )
    .expect("pi_Mul");
    assert_eq!(a + b, alpha * beta);

    let per_party = counters.per_party_bits();
    println!("per party per multiplication: {per_party} bits");
    // DKLST's closed form is `COTeCost + kappa*(ell+1)/2` with `COTeCost = ell*n/2 + ROTeCost`.
    let correction = (ELL * 2 * KAPPA / 2) as u64; // ell*n/2, n = 2*kappa
    let check = (KAPPA * (ELL + 1) / 2) as u64;
    let extension = per_party - correction - check;
    println!(
        "  correction {} + check {} + extension {} = {} (DKLST model: 308576 with ROTeCost 50400)",
        correction,
        check,
        extension,
        correction + check + extension
    );
    assert_eq!(correction, 172_032, "ell*n/2 with n = 2*kappa");
    assert_eq!(check, 86_144, "kappa*(ell+1)/2");
}

#[test]
fn base_ot_runs_and_is_counted() {
    let mut counters = Counters::default();
    base_ot(b"setup-session", &mut counters).expect("base OT");
    assert!(counters.bits > 0);
    println!(
        "base OT (Endemic, 2 messages): {} bits total, {} per party, {} EC ops",
        counters.bits,
        counters.per_party_bits(),
        counters.ec_ops
    );
}

/// The protocol uses the split form: Bob publishes a choice message, Alice answers, Bob checks.
#[test]
fn split_multiplier_is_consistent() {
    let grip = public_grip(b"test-grip");
    let setup = OtSetup::new();

    for variant in VARIANTS {
        let mut counters = Counters::default();
        let alpha = Scalar::from(1234567u64);
        let beta = Scalar::from(7654321u64);

        let (state, message) =
            receive(b"split", &setup, &beta, &grip, &mut counters).expect("receive");
        let (answer, share_a) = reply(
            b"split",
            &setup,
            &message,
            &alpha,
            &grip,
            variant,
            &mut counters,
        )
        .expect("reply");
        let share_b = finish(b"split", &state, &answer, &grip).expect("finish");
        assert_eq!(share_a + share_b, alpha * beta, "split pi_Mul");
        println!(
            "{:<10} split pi_Mul: {} bits total, {} per party",
            variant.name(),
            counters.bits,
            counters.per_party_bits()
        );
    }
}
