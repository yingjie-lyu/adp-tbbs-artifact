//! Signing benchmark for the DKLST baseline: setup and signing reported separately.
//!
//! ```text
//! cargo run --release --bin bench -- --t-min 2 --t-max 7 --reps 5 --len 10
//! cargo run --release --features libote --bin bench -- --ot-backend libote
//! cargo run --release --bin bench -- --mul-variant masked      # the pessimistic instantiation
//! ```
//!
//! Data lands in `data/<YYYYmmdd-HHMMSS>/` (one directory per run) as `dklst.csv` plus a
//! Markdown summary, so a rerun never overwrites earlier numbers.

use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use bls12_381::Scalar;
use dklst_bbs::mul::{multiply, public_grip, MulVariant};
use dklst_bbs::ot::{base_ot, Backend, Counters};
use dklst_bbs::params::{ELL, KAPPA, LAMBDA};
use dklst_bbs::sign::{
    combine, keygen, multiplications_per_signer, verify, OtMaterial, PublicParams, Response, Round1,
    Round2, Signer,
};

#[derive(Clone, Copy, PartialEq, Eq)]
struct Config {
    backend: Backend,
    variant: MulVariant,
    /// SoftSpokenOT's `field_bits`; only meaningful for the `libOTe` backend.
    field_bits: u32,
}

impl Config {
    fn label(&self) -> String {
        match self.backend {
            Backend::LibOte => format!(
                "{}/k={}/{}",
                self.backend.name(),
                self.field_bits,
                self.variant.name()
            ),
            Backend::SlOblivious => format!("{}/{}", self.backend.name(), self.variant.name()),
        }
    }
}

struct Args {
    t_min: usize,
    t_max: usize,
    reps: usize,
    len: usize,
    out: PathBuf,
    backends: Vec<Backend>,
    variants: Vec<MulVariant>,
    field_bits: Vec<u32>,
}

fn parse_backends(value: &str) -> Vec<Backend> {
    match value {
        "sl" | "sl-oblivious" => vec![Backend::SlOblivious],
        "libote" => vec![Backend::LibOte],
        "both" => vec![Backend::SlOblivious, Backend::LibOte],
        other => panic!("unknown backend {other}"),
    }
}

fn parse_variants(value: &str) -> Vec<MulVariant> {
    match value {
        "correction" => vec![MulVariant::Correction],
        "masked" => vec![MulVariant::Masked],
        "both" => vec![MulVariant::Correction, MulVariant::Masked],
        other => panic!("unknown multiplication variant {other}"),
    }
}

fn parse_args() -> Args {
    let mut args = Args {
        t_min: 2,
        t_max: 7,
        reps: 5,
        len: 10,
        out: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("data"),
        backends: vec![Backend::SlOblivious],
        variants: vec![MulVariant::Correction],
        // libOTe's own default is 2, but 4 is both faster here and matches Roy's `k = 2` cost
        // model in practice (304 436 vs the paper's 308 576 bits/party). Sweep with
        // `--field-bits 2,3,4,5,6,8`.
        field_bits: vec![4],
    };
    let mut argv = std::env::args().skip(1);
    while let Some(flag) = argv.next() {
        let mut value = || argv.next().unwrap_or_default();
        match flag.as_str() {
            "--t-min" => args.t_min = value().parse().unwrap_or(2),
            "--t-max" => args.t_max = value().parse().unwrap_or(7),
            "--reps" => args.reps = value().parse().unwrap_or(5),
            "--len" => args.len = value().parse().unwrap_or(10),
            "--out" => args.out = PathBuf::from(value()),
            "--ot-backend" => args.backends = parse_backends(&value()),
            "--mul-variant" => args.variants = parse_variants(&value()),
            "--field-bits" => {
                args.field_bits = value()
                    .split(',')
                    .map(|item| item.trim().parse().expect("field_bits"))
                    .collect()
            }
            other => panic!("unknown flag {other}"),
        }
    }
    args
}

fn stamp() -> String {
    let out = std::process::Command::new("date")
        .arg("+%Y%m%d-%H%M%S")
        .output()
        .ok()
        .map(|value| String::from_utf8_lossy(&value.stdout).trim().to_string())
        .filter(|value| !value.is_empty());
    out.unwrap_or_else(|| "run".to_string())
}

fn message(len: usize) -> Vec<Scalar> {
    (0..len).map(|index| Scalar::from(index as u64 + 1)).collect()
}

/// DKLST's closed forms (Section 6, Table 6.2), all in bits per party.
mod paper {
    pub const LAMBDA: usize = 128;
    pub const KAPPA: usize = 256;
    pub const STAT: usize = 80;

    /// `(3/2 + 1/(2k))*(lambda^2 + lambda) + lambda*ell/(2k)`, with `k = 2`.
    pub fn rote_cost(ell: usize) -> usize {
        let k = 2usize;
        let base = LAMBDA * LAMBDA + LAMBDA;
        (3 * base) / 2 + base / (2 * k) + LAMBDA * ell / (2 * k)
    }

    /// `ell*n/2 + ROTeCost(lambda, ell)` with `n = 2*kappa`.
    pub fn cote_cost(ell: usize) -> usize {
        ell * (2 * KAPPA) / 2 + rote_cost(ell)
    }

    /// `COTeCost(lambda, 2k+2s, 2k) + kappa*(2k+2s+1)/2`.
    pub fn mul_cost() -> usize {
        let ell = 2 * KAPPA + 2 * STAT;
        cote_cost(ell) + KAPPA * (ell + 1) / 2
    }

    /// The per-peer term of `SignCost`: `4*lambda + 2*kappa + 2*MulCost`.
    pub fn signing_per_pair() -> usize {
        4 * LAMBDA + 2 * KAPPA + 2 * mul_cost()
    }

    /// `(t-1) * signing_per_pair()`.
    pub fn signing_cost(t: usize) -> usize {
        (t - 1) * signing_per_pair()
    }

    /// `3*kappa + |G2| + |G1|*(ell+2) + t*log2 n`.
    pub fn response_cost(t: usize, ell: usize) -> usize {
        3 * KAPPA + 768 + 384 * (ell + 2) + t * 3
    }
}

/// One `pi_Mul` measured in isolation: the number DKLST's `Mul Cost` row is comparable with.
fn mul_probe(config: Config) -> (u64, f64) {
    let grip = public_grip(b"dklst/probe");
    // One setup object carries both halves of a pair's extension material.
    let pair = dklst_bbs::ot::OtSetup::with_options(config.backend, config.field_bits)
        .expect("setup");
    let mut counters = Counters::default();
    let reps = 20;
    // Warm-up: the first extension also runs libOTe's one-time VOLE expansion.
    let _ = multiply(
        b"warm-up",
        &pair,
        &pair,
        &Scalar::from(3u64),
        &Scalar::from(5u64),
        &grip,
        config.variant,
        &mut Counters::default(),
    )
    .expect("warm-up pi_Mul");
    let started = Instant::now();
    for round in 0..reps {
        let (a, b) = multiply(
            &(round as u64).to_be_bytes(),
            &pair,
            &pair,
            &Scalar::from(7u64 + round),
            &Scalar::from(11u64 + round),
            &grip,
            config.variant,
            &mut counters,
        )
        .expect("pi_Mul");
        assert_eq!(a + b, Scalar::from(7u64 + round) * Scalar::from(11u64 + round));
    }
    let per_mult = counters.per_party_bits() / reps as u64;
    let per_mult_ms = started.elapsed().as_secs_f64() * 1e3 / reps as f64;
    (per_mult, per_mult_ms)
}

struct Row {
    config: Config,
    t: usize,
    setup_ms: f64,
    setup_bits_per_party: u64,
    sign_ms_per_party: f64,
    sign_bits_per_party: u64,
    mults: usize,
}

fn measure(config: Config, t: usize, reps: usize, len: usize) -> Row {
    let pp = PublicParams::new(len);
    let parties: Vec<usize> = (1..=t).collect();
    let keys = keygen(&parties, t);
    let public = keys[0].public;

    // --- setup ------------------------------------------------------------------------------
    // The sl-oblivious backend measures the Endemic base OTs on their own: its extension seeds
    // come from `generate_all_but_one_seed_ot`, so the setup object itself is free. libOTe stores
    // the base OTs inside the setup object, so building it *is* the measurement.
    let setup_start = Instant::now();
    let setup_bits;
    let material = match config.backend {
        Backend::SlOblivious => {
            let mut setup_counters = Counters::default();
            for alice in &parties {
                for bob in &parties {
                    if alice != bob {
                        let session = format!("setup-{alice}-{bob}");
                        base_ot(session.as_bytes(), &mut setup_counters).expect("base OT");
                    }
                }
            }
            setup_bits = setup_counters.per_party_bits();
            OtMaterial::with_options(&parties, config.backend, config.variant, config.field_bits)
                .expect("sl-oblivious setup")
        }
        Backend::LibOte => {
            let material =
                OtMaterial::with_options(&parties, config.backend, config.variant, config.field_bits)
                    .expect("libOTe setup");
            let (_, bytes) = material.libote_setup_stats();
            setup_bits = bytes * 8 / 2;
            material
        }
    };
    let setup_ms = setup_start.elapsed().as_secs_f64() * 1e3;

    // --- signing ----------------------------------------------------------------------------
    let msg = message(len);
    let mut total_ms = 0.0;
    let mut total_bits = 0u64;
    let mut checks = 0;

    // Discarded warm-up session. The first SoftSpokenOT extension on a libOTe pair also performs
    // the one-time subspace-VOLE expansion; DKLST's `MulCost` is a steady-state per-multiplication
    // figure, so charging that bootstrap to the first signature would inflate it. The
    // sl-oblivious backend derives its seeds per call and is unaffected.
    {
        let mut warm: Vec<Signer> = keys
            .clone()
            .into_iter()
            .map(|item| Signer::new(item, &parties, pp.clone()))
            .collect();
        let session = b"warm-up";
        let round1: Vec<Round1> = warm
            .iter_mut()
            .map(|signer| signer.round1(session, &material))
            .collect();
        let round2: Vec<Round2> = warm
            .iter_mut()
            .map(|signer| signer.round2(session, &material, &round1))
            .collect();
        let _: Vec<Response> = warm
            .iter_mut()
            .map(|signer| signer.finish(session, &round1, &round2, &msg))
            .collect();
    }

    for rep in 0..reps {
        let session = format!("sign-{t}-{rep}-{}-{}", config.backend.name(), config.variant.name());
        let session = session.as_bytes();
        let mut signers: Vec<Signer> = keys
            .clone()
            .into_iter()
            .map(|item| Signer::new(item, &parties, pp.clone()))
            .collect();

        let start = Instant::now();
        let round1: Vec<Round1> = signers
            .iter_mut()
            .map(|signer| signer.round1(session, &material))
            .collect();
        let round2: Vec<Round2> = signers
            .iter_mut()
            .map(|signer| signer.round2(session, &material, &round1))
            .collect();
        let responses: Vec<Response> = signers
            .iter_mut()
            .map(|signer| signer.finish(session, &round1, &round2, &msg))
            .collect();
        let rounds_ms = start.elapsed().as_secs_f64() * 1e3;

        // Every party assembles the signature itself, so the combination is charged once against
        // each party's runtime rather than amortised over the signers.
        let combine_start = Instant::now();
        let (a, s, e) = combine(&responses).expect("invertible");
        if verify(&pp, &public, &msg, &a, &e, &s) {
            checks += 1;
        }
        let combine_ms = combine_start.elapsed().as_secs_f64() * 1e3;

        total_ms += rounds_ms / t as f64 + combine_ms;
        total_bits += signers.iter().map(|signer| signer.counters().bits).sum::<u64>() / t as u64;
    }
    assert_eq!(checks, reps, "every repetition must verify");

    Row {
        config,
        t,
        setup_ms,
        setup_bits_per_party: setup_bits,
        sign_ms_per_party: total_ms / reps as f64,
        sign_bits_per_party: total_bits / reps as u64,
        mults: multiplications_per_signer(t),
    }
}

fn main() {
    let args = parse_args();
    let out = args.out.join(stamp());
    fs::create_dir_all(&out).expect("output directory");

    println!(
        "DKLST baseline: t = {}..={}, {} reps, ell = {} messages, {} OTs per multiplication",
        args.t_min, args.t_max, args.reps, args.len, ELL
    );
    #[cfg(feature = "libote")]
    if args.backends.contains(&Backend::LibOte) {
        println!("libOTe: {}", dklst_bbs::libote::version());
        println!(
            "libOTe base OTs per pair: {}",
            dklst_bbs::libote::base_ot_count()
        );
    }
    #[cfg(not(feature = "libote"))]
    if args.backends.contains(&Backend::LibOte) {
        panic!("rebuild with --features libote");
    }

    // --- alignment with DKLST Section 6 ------------------------------------------------------
    println!(
        "\nDKLST closed forms: MulCost = {} bits/party, SignCost = (t-1)*{} + response",
        paper::mul_cost(),
        paper::signing_per_pair()
    );
    let mut configs: Vec<Config> = Vec::new();
    for backend in &args.backends {
        for variant in &args.variants {
            // `field_bits` only applies to libOTe; the sl-oblivious batch is fixed at L = 768.
            let bits: Vec<u32> = match backend {
                Backend::LibOte => args.field_bits.clone(),
                Backend::SlOblivious => vec![0],
            };
            for field_bits in bits {
                configs.push(Config {
                    backend: *backend,
                    variant: *variant,
                    field_bits,
                });
            }
        }
    }
    for config in &configs {
        let (bits, ms) = mul_probe(*config);
        println!(
            "  {:<26} pi_Mul {:>7} bits/party, {:>6.2} ms/mult  (paper {:>7}, delta {:>+6.1}%)",
            config.label(),
            bits,
            ms,
            paper::mul_cost(),
            100.0 * (bits as f64 - paper::mul_cost() as f64) / paper::mul_cost() as f64
        );
    }
    println!();

    let mut rows: Vec<Row> = Vec::new();
    for config in &configs {
        for t in args.t_min..=args.t_max {
            let row = measure(*config, t, args.reps, args.len);
            println!(
                "  t = {:<2} [{:<22}] sign {:>7.2} ms/signer, {:>8} bit/signer ({:>7.1} KiB), \
                 {} mults; setup {:>7.1} ms, {} bit/party",
                row.t,
                row.config.label(),
                row.sign_ms_per_party,
                row.sign_bits_per_party,
                row.sign_bits_per_party as f64 / 8.0 / 1024.0,
                row.mults,
                row.setup_ms,
                row.setup_bits_per_party
            );
            rows.push(row);
        }
    }

    let mut csv = String::from(
        "backend,mul_variant,t,reps,mults_per_signer,sign_ms_per_signer,sign_bits_per_signer,setup_ms,setup_bits_per_party\n",
    );
    for row in &rows {
        csv.push_str(&format!(
            "{},{},{},{},{},{:.3},{},{:.3},{}\n",
            row.config.backend.name(),
            row.config.variant.name(),
            row.t,
            args.reps,
            row.mults,
            row.sign_ms_per_party,
            row.sign_bits_per_party,
            row.setup_ms,
            row.setup_bits_per_party
        ));
    }
    fs::write(out.join("dklst.csv"), csv).expect("csv");

    let mut md = String::from("# DKLST baseline\n\n");
    md.push_str(&format!(
        "`ell = {}` messages, `{}` repetitions, `{}` OTs per multiplication, \
         `lambda = {LAMBDA}`, `kappa = {KAPPA}`.\n\n",
        args.len, args.reps, ELL
    ));
    md.push_str(&format!(
        "DKLST Section 6 closed forms: `MulCost` = **{}** bits/party, \
         `SignCost` = `(t-1)*{}` + response.\n\n",
        paper::mul_cost(),
        paper::signing_per_pair()
    ));
    md.push_str(
        "| backend / variant | t | mults / signer | sign ms / signer | sign KiB / signer | sign bits / signer | DKLST `SignCost` | setup ms | setup KiB / party |\n",
    );
    md.push_str("|---|---:|---:|---:|---:|---:|---:|---:|---:|\n");
    for row in &rows {
        md.push_str(&format!(
            "| {} | {} | {} | {:.2} | {:.1} | {} | {} | {:.1} | {:.1} |\n",
            row.config.label(),
            row.t,
            row.mults,
            row.sign_ms_per_party,
            row.sign_bits_per_party as f64 / 8.0 / 1024.0,
            row.sign_bits_per_party,
            paper::signing_cost(row.t),
            row.setup_ms,
            row.setup_bits_per_party as f64 / 8.0 / 1024.0
        ));
    }
    md.push_str(&format!(
        "\nThe DKLST column is `(t-1)*{}` bits, i.e. the peer-to-peer term of `SignCost`; it \
         excludes the response to the client (`3*kappa + |G2| + |G1|*(ell+2) + t*log2 n` = {} bits).\n",
        paper::signing_cost(2),
        paper::response_cost(2, args.len)
    ));
    fs::write(out.join("report.md"), md).expect("report");

    println!(
        "profiling: SHA-256 coins {:.1} ms total, SoftSpokenOT {:.1} ms total",
        dklst_bbs::mul::coin_ns() as f64 / 1e6,
        dklst_bbs::ot::ext_ns() as f64 / 1e6
    );
    println!("written to {}", out.display());
}
