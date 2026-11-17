//! Signing-runtime driver for the threshold BBS+ schemes in this workspace.
//!
//! What it measures: **signing only**. Setup and distributed key generation run once per
//! `(ell, t)` before the timed loop and are excluded.
//!
//! What it writes: everything under `bench/data/` (or `--out`), so a run is reproducible and
//! the numbers in the paper can be regenerated from the CSVs:
//!
//! * `meta.md` — parameters, toolchain, exact command line,
//! * `ours_phases.csv` — our scheme, per internal phase, per signer,
//! * `ours_totals.csv` — our scheme, six logical stages + wire, per signer,
//! * `fit_ours.csv` — least-squares `a + b t` per stage and per phase,
//! * `others_stages.csv`, `others_totals.csv` — the other five schemes, coarse,
//! * `report.md` — all of the above as tables, plus the fitted formulas.
//!
//! Usage:
//!
//! ```text
//! cargo run --release -p tbbs-bench -- --t-min 2 --t-max 7 --reps 5 --len 10
//! ```
//!
//! `t` is both the threshold and the number of signers (`n = t`, quorum = all), which is the
//! axis the paper's `a + b t` formula is stated in. `robot-bbs` needs `|P| > t`, so it runs
//! with `n = t` and threshold `t - 1`; `twopass-bbs` is two-party only.

mod others;
mod ours;
mod stats;

use threshold_bbs::nim::NimVariant;

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use stats::{Line, Summary};

struct Args {
    t_min: usize,
    t_max: usize,
    reps: usize,
    len: usize,
    out: PathBuf,
    /// Whether `--out` was given. Without it the run goes into `data/<timestamp>/`.
    out_explicit: bool,
    /// Optional label appended to the timestamped directory name, e.g. `zen3gmp`.
    tag: Option<String>,
    schemes: Vec<String>,
}

const ALL_SCHEMES: [&str; 8] = [
    "ours",
    "ours-sb",
    "ours-sb-short",
    "clkem",
    "twopass",
    "robot",
    "wmc24",
    "tx25",
];

/// The three instantiations of our construction that the paper benchmarks side by side.
const VARIANTS: [(&str, NimVariant); 3] = [
    ("ours", NimVariant::TwoBase),
    ("ours-sb", NimVariant::SingleBase),
    ("ours-sb-short", NimVariant::SingleBaseShort),
];

fn usage() -> ! {
    eprintln!(
        "usage: tbbs-bench [--t-min N] [--t-max N] [--reps N] [--len N] [--out DIR] \\
         [--schemes ours,clkem,twopass,robot,wmc24,tx25]\n\
         defaults: --t-min 2 --t-max 7 --reps 5 --len 10 --out <manifest>/data/<timestamp>[-tag],
         all schemes;  --tag NAME labels a variant build (e.g. --tag zen3gmp)"
    );
    std::process::exit(2)
}

fn parse_args() -> Args {
    let mut args = Args {
        t_min: 2,
        t_max: 7,
        reps: 5,
        len: 10,
        out: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("data"),
        out_explicit: false,
        tag: None,
        schemes: ALL_SCHEMES.iter().map(|name| name.to_string()).collect(),
    };
    let mut argv = std::env::args().skip(1);
    while let Some(flag) = argv.next() {
        let mut value = || {
            argv.next().unwrap_or_else(|| {
                eprintln!("missing value for {flag}");
                usage()
            })
        };
        match flag.as_str() {
            "--t-min" => args.t_min = value().parse().unwrap_or_else(|_| usage()),
            "--t-max" => args.t_max = value().parse().unwrap_or_else(|_| usage()),
            "--reps" => args.reps = value().parse().unwrap_or_else(|_| usage()),
            "--len" => args.len = value().parse().unwrap_or_else(|_| usage()),
            "--out" => {
                args.out = PathBuf::from(value());
                args.out_explicit = true;
            }
            "--tag" => args.tag = Some(value()),
            "--schemes" => {
                args.schemes = value()
                    .split(',')
                    .map(|name| name.trim().to_string())
                    .filter(|name| !name.is_empty())
                    .collect()
            }
            "--help" | "-h" => usage(),
            other => {
                eprintln!("unknown flag {other}");
                usage()
            }
        }
    }
    if args.t_min < 2 || args.t_max < args.t_min || args.reps == 0 || args.len == 0 {
        usage();
    }
    if !args.out_explicit {
        // One directory per run: a rerun never overwrites earlier numbers. A `--tag` is
        // appended so a variant build stays recognisable from the directory name alone.
        let stamp = timestamp();
        let name = match args.tag.as_deref() {
            Some(tag) if !tag.is_empty() => format!("{stamp}-{tag}"),
            _ => stamp,
        };
        args.out = args.out.join(name);
    }
    args
}

/// `YYYYmmdd-HHMMSS` from the system clock, so consecutive runs never collide.
fn timestamp() -> String {
    let from_date = std::process::Command::new("date")
        .arg("+%Y%m%d-%H%M%S")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .filter(|value| !value.is_empty());
    if let Some(value) = from_date {
        return value;
    }
    // Portable fallback: seconds since the epoch.
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    format!("epoch-{seconds}")
}

fn main() {
    let args = parse_args();
    fs::create_dir_all(&args.out).expect("create the output directory");
    let ts: Vec<usize> = (args.t_min..=args.t_max).collect();
    let started = Instant::now();

    println!(
        "signing runtime, ell = {}, t = {}..={}, {} reps, out = {}",
        args.len,
        args.t_min,
        args.t_max,
        args.reps,
        args.out.display()
    );
    println!(
        "threads in this process: {:?} (BICYCL_WITH_PTHREADS is off, so no worker threads)",
        thread_count()
    );

    // --- our scheme -------------------------------------------------------------------
    let mut ours_samples: BTreeMap<&'static str, BTreeMap<usize, ours::Sample>> = BTreeMap::new();
    for (label, variant) in VARIANTS {
        if !args.schemes.iter().any(|name| name == label) {
            continue;
        }
        for &t in &ts {
            let clock = Instant::now();
            let sample = ours::measure(args.len, t, args.reps, variant)
                .unwrap_or_else(|error| panic!("{label}, t = {t}: {error}"));
            let spread = Summary::of(&sample.total_reps);
            eprintln!(
                "  {label:<13} t = {t:<2} {:>8.2} ± {:.2} ms/signer  \
                 [median {:.2}, min {:.2}, max {:.2}, n = {}]  ({:.1} s wall)",
                sample.total_ms,
                spread.stddev,
                spread.median,
                spread.min,
                spread.max,
                spread.samples,
                clock.elapsed().as_secs_f64()
            );
            ours_samples.entry(label).or_default().insert(t, sample);
            report_threads(&format!("after {label} t = {t}"));
        }
    }
    if !ours_samples.is_empty() {
        write_ours(&args, &ours_samples);
    }

    // --- the other schemes ------------------------------------------------------------
    let mut coarse: BTreeMap<&'static str, BTreeMap<usize, others::Coarse>> = BTreeMap::new();
    for scheme in ["clkem", "twopass", "robot", "wmc24", "tx25"] {
        if !args.schemes.iter().any(|name| name == scheme) {
            continue;
        }
        for &t in &ts {
            if scheme == "twopass" && t != 2 {
                continue;
            }
            let clock = Instant::now();
            let result = match scheme {
                "clkem" => others::clkem(args.len, t, args.reps),
                "twopass" => others::twopass(args.len, args.reps),
                "robot" => others::robot(args.len, t, args.reps),
                "wmc24" => others::wmc24(args.len, t, args.reps),
                "tx25" => others::tx25(args.len, t, args.reps),
                _ => unreachable!(),
            };
            let sample =
                result.unwrap_or_else(|error| panic!("{scheme}, t = {t}: {error}"));
            eprintln!(
                "  {scheme:<9} t = {t:<2} {:>8.2} ms/signer   ({:.1} s wall)",
                sample.total_ms,
                clock.elapsed().as_secs_f64()
            );
            coarse.entry(scheme_name(scheme)).or_default().insert(t, sample);
        }
    }
    if !coarse.is_empty() {
        write_others(&args, &coarse);
    }

    write_meta(&args, started);
    write_report(&args, &ours_samples, &coarse);

    if !args.out_explicit {
        append_index(&args, started);
    }

    println!(
        "\ndone in {:.1} s; files in {}",
        started.elapsed().as_secs_f64(),
        args.out.display()
    );
}

/// Number of threads in this process (Linux `/proc/self/status`), so a measurement can show it
/// ran single-threaded. `None` where that file does not exist.
fn thread_count() -> Option<usize> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("Threads:")?.trim().parse::<usize>().ok())
}

fn report_threads(where_: &str) {
    if let Some(count) = thread_count() {
        if count != 1 {
            eprintln!(
                "  WARNING: {count} threads alive {where_} - single-threaded numbers are only \
                 comparable while this stays 1"
            );
        }
    }
}

/// What the numbers actually run on: the GMP build (its hand-written `mpn` assembly is where
/// class-group time goes) and the code-generation target of our own code.
fn library_info() -> String {
    let mut lines: Vec<String> = Vec::new();

    // Fedora splits the version macros into `gmp-<arch>.h`, included by `gmp.h`, so scan the
    // whole family rather than one path.
    let mut candidates: Vec<std::path::PathBuf> =
        vec![std::path::PathBuf::from("/usr/include/gmp.h")];
    if let Ok(entries) = std::fs::read_dir("/usr/include") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("gmp-") && name.ends_with(".h") {
                candidates.push(entry.path());
            }
        }
    }
    for candidate in candidates {
        let Ok(header) = std::fs::read_to_string(&candidate) else {
            continue;
        };
        let mut parts: Vec<String> = Vec::new();
        for key in [
            "__GNU_MP_VERSION ",
            "__GNU_MP_VERSION_MINOR ",
            "__GNU_MP_VERSION_PATCHLEVEL ",
        ] {
            if let Some(value) = header.lines().find_map(|line| {
                line.trim()
                    .strip_prefix("#define ")
                    .and_then(|rest| rest.strip_prefix(key))
            }) {
                parts.push(value.trim().to_string());
            }
        }
        if !parts.is_empty() {
            lines.push(format!("GMP headers: {} ({})", parts.join("."), candidate.display()));
            break;
        }
    }

    if let Ok(output) = std::process::Command::new("rpm").args(["-q", "gmp"]).output() {
        if output.status.success() {
            lines.push(format!(
                "GMP package: {}",
                String::from_utf8_lossy(&output.stdout).trim()
            ));
        }
    }

    // A fat GMP dispatches to per-CPU `mpn` routines at load time; a native build has none.
    // Resolve the library the process actually loaded, so a `LD_LIBRARY_PATH` override for a
    // micro-architecture-specific build shows up in the record.
    let loaded = std::fs::read_to_string("/proc/self/maps").ok().and_then(|maps| {
        maps.lines()
            .filter_map(|line| line.split_whitespace().last())
            .find(|path| path.contains("libgmp.so"))
            .map(|path| path.to_string())
    });
    if let Some(path) = &loaded {
        lines.push(format!("GMP loaded by this process: {path}"));
    }
    let candidates: Vec<String> = match &loaded {
        Some(path) => vec![path.clone()],
        None => vec![
            "/usr/lib64/libgmp.so.10".to_string(),
            "/usr/lib/libgmp.so.10".to_string(),
        ],
    };
    for lib in candidates {
        let lib = lib.as_str();
        if let Ok(output) = std::process::Command::new("nm").args(["-D", lib]).output() {
            if !output.status.success() {
                continue;
            }
            let text = String::from_utf8_lossy(&output.stdout);
            let fat = text.contains("__gmpn_cpuvec");
            let mut variants: Vec<String> = text
                .split_whitespace()
                .filter(|token| token.starts_with("__gmpn_"))
                .filter_map(|token| token.split_once("_core").map(|(_, rest)| rest.to_string()))
                .filter(|rest| !rest.is_empty() && rest.len() <= 8)
                .map(|rest| format!("core{rest}"))
                .collect();
            variants.sort();
            variants.dedup();
            let suffix = if variants.is_empty() {
                String::new()
            } else {
                format!(", variants: {}", variants.join("/"))
            };
            lines.push(format!("GMP library {lib}: fat = {fat}{suffix}"));
            break;
        }
    }

    // `rustc --print cfg` reflects the host default, not the flags this binary was built with,
    // so record the environment too — a `-C target-cpu=native` run must not look baseline.
    for variable in ["RUSTFLAGS", "CXXFLAGS"] {
        if let Ok(value) = std::env::var(variable) {
            if !value.trim().is_empty() {
                lines.push(format!("{variable} at build time: {value}"));
            }
        }
    }
    if let Ok(output) = std::process::Command::new("rustc")
        .args(["--print", "cfg"])
        .output()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        let features: Vec<&str> = text
            .lines()
            .filter_map(|line| line.trim().strip_prefix("target_feature=\""))
            .filter_map(|rest| rest.strip_suffix('"'))
            .collect();
        if !features.is_empty() {
            lines.push(format!(
                "rustc target features: {} (no -C target-cpu=native)",
                features.join(", ")
            ));
        }
    }

    if lines.is_empty() {
        return "- not recorded\n".to_string();
    }
    lines
        .iter()
        .map(|line| format!("- {line}\n"))
        .collect::<String>()
}

/// One line per run in `data/index.md`, so past runs are findable without opening each
/// `meta.md`.
fn append_index(args: &Args, started: Instant) {
    use std::io::Write;

    let dir_name = args
        .out
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_default();
    let parent = match args.out.parent() {
        Some(path) => path,
        None => return,
    };
    let path = parent.join("index.md");
    let header_needed = !path.exists();
    let mut file = match fs::OpenOptions::new().create(true).append(true).open(&path) {
        Ok(file) => file,
        Err(_) => return,
    };
    if header_needed {
        let _ = writeln!(
            file,
            "# Runs\n\n| directory | ell | t | reps | schemes | wall clock |\n|---|---:|---|---:|---|---:|"
        );
    }
    let _ = writeln!(
        file,
        "| `{dir_name}` | {} | {}..={} | {} | {} | {:.0} s |",
        args.len,
        args.t_min,
        args.t_max,
        args.reps,
        args.schemes.join(", "),
        started.elapsed().as_secs_f64()
    );
}

fn scheme_name(name: &str) -> &'static str {
    match name {
        "clkem" => "clkem-tbbs (3 rounds, CL-KEM)",
        "twopass" => "twopass-bbs (2 passes, 2 parties)",
        "robot" => "robot-bbs (2 rounds)",
        "wmc24" => "wmc24-bbs (4 rounds)",
        "tx25" => "tx25-bbs (2 offline + 1 online)",
        _ => "ours",
    }
}

// ---------------------------------------------------------------------------------------
// our scheme
// ---------------------------------------------------------------------------------------

fn write_ours(args: &Args, samples: &BTreeMap<&'static str, BTreeMap<usize, ours::Sample>>) {
    let path = args.out.join("ours_phases.csv");
    let mut text = String::from("variant,stage,phase,per_peer,t,mean_ms_per_signer\n");
    if !samples.is_empty() {
        text.push_str("## Total per signer, all instantiations\n\n| t |");
        for variant in samples.keys() {
            text.push_str(&format!(" {} |", variant_label(variant)));
        }
        text.push_str("\n|---:|");
        for _ in samples.keys() {
            text.push_str("---:|");
        }
        text.push('\n');
        let mut all_t: Vec<usize> = samples
            .values()
            .flat_map(|per_t| per_t.keys().copied())
            .collect();
        all_t.sort_unstable();
        all_t.dedup();
        for t in all_t {
            text.push_str(&format!("| {t} |"));
            for per_t in samples.values() {
                match per_t.get(&t) {
                    Some(sample) => text.push_str(&format!(" {:.2} |", sample.total_ms)),
                    None => text.push_str(" - |"),
                }
            }
            text.push('\n');
        }
        text.push('\n');
    }

    for (variant, per_t) in samples {
        for (&t, sample) in per_t {
            for (label, phases) in ours::GROUPS {
                for phase in phases {
                    let value = sample.per_phase_ms.get(phase.label()).copied().unwrap_or(0.0);
                    text.push_str(&format!(
                        "\"{variant}\",\"{label}\",\"{}\",{},{},{:.4}\n",
                        phase.label(),
                        ours::is_per_peer(*phase),
                        t,
                        value
                    ));
                }
            }
        }
    }
    fs::write(&path, text).expect("write ours_phases.csv");

    let path = args.out.join("ours_totals.csv");
    let mut text = String::from("variant,stage,t,mean_ms_per_signer,stddev_ms\n");
    for (variant, per_t) in samples {
        for (&t, sample) in per_t {
            for (label, value) in &sample.per_stage_ms {
                text.push_str(&format!("\"{variant}\",\"{label}\",{t},{value:.4}\n"));
            }
            let total = Summary::of(&sample.total_reps);
            text.push_str(&format!(
                "\"{variant}\",\"total (six stages)\",{t},{:.4},{:.4}\n",
                total.mean, total.stddev
            ));
            let wire = Summary::of(&sample.wire_reps);
            text.push_str(&format!(
                "\"{variant}\",\"wire encode/decode (separate run)\",{t},{:.4},{:.4}\n",
                wire.mean, wire.stddev
            ));
        }
    }
    fs::write(&path, text).expect("write ours_totals.csv");

    // Least squares `a + b t` for every stage and every phase, per variant.
    let path = args.out.join("fit_ours.csv");
    let mut text = String::from(
        "variant,quantity,a_ms,b_ms_per_signer,r2,formula_at_t_min,formula_at_t_max\n",
    );
    for (variant, per_t) in samples {
        for line in fits(per_t) {
            text.push_str(&format!(
                "\"{variant}\",\"{}\",{:.4},{:.4},{:.6},{:.3},{:.3}\n",
                line.0,
                line.1.a,
                line.1.b,
                line.1.r2,
                line.1.eval(args.t_min as f64),
                line.1.eval(args.t_max as f64)
            ));
        }
    }
    fs::write(&path, text).expect("write fit_ours.csv");
}

/// `(name, fitted line)` for the six stages, the total, and every internal phase.
fn fits(samples: &BTreeMap<usize, ours::Sample>) -> Vec<(String, Line)> {
    let mut out = Vec::new();
    let mut quantities: Vec<String> = Vec::new();
    for (label, _) in ours::GROUPS {
        quantities.push((*label).to_string());
    }
    quantities.push("total (six stages)".to_string());
    for phase in ours::phase_order() {
        quantities.push(format!("phase: {}", phase.label()));
    }

    for name in quantities {
        let mut points = Vec::new();
        for (&t, sample) in samples {
            let value = if name == "total (six stages)" {
                Some(sample.total_ms)
            } else if let Some(label) = ours::GROUPS
                .iter()
                .find(|(label, _)| *label == name.as_str())
                .map(|(label, _)| *label)
            {
                sample.per_stage_ms.get(label).copied()
            } else {
                let phase_label = name.trim_start_matches("phase: ");
                sample.per_phase_ms.get(phase_label).copied()
            };
            if let Some(value) = value {
                points.push((t as f64, value));
            }
        }
        if points.len() >= 2 {
            out.push((name, Line::fit(&points)));
        }
    }
    out
}

// ---------------------------------------------------------------------------------------
// the other schemes
// ---------------------------------------------------------------------------------------

fn write_others(
    args: &Args,
    coarse: &BTreeMap<&'static str, BTreeMap<usize, others::Coarse>>,
) {
    let path = args.out.join("others_stages.csv");
    let mut text = String::from("scheme,t,stage,mean_ms_per_signer\n");
    for (scheme, per_t) in coarse {
        for (&t, sample) in per_t {
            for (stage, value) in &sample.stages {
                text.push_str(&format!("\"{scheme}\",{t},\"{stage}\",{value:.4}\n"));
            }
        }
    }
    fs::write(&path, text).expect("write others_stages.csv");

    let path = args.out.join("others_totals.csv");
    let mut text = String::from("scheme,t,parties,mean_ms_per_signer\n");
    for (scheme, per_t) in coarse {
        for (&t, sample) in per_t {
            text.push_str(&format!(
                "\"{scheme}\",{t},{},{:.4}\n",
                sample.parties, sample.total_ms
            ));
        }
    }
    fs::write(&path, text).expect("write others_totals.csv");
}

// ---------------------------------------------------------------------------------------
// metadata and the human-readable report
// ---------------------------------------------------------------------------------------

fn write_meta(args: &Args, started: Instant) {
    let path = args.out.join("meta.md");
    let rustc = std::process::Command::new("rustc")
        .arg("--version")
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .unwrap_or_else(|_| "rustc not on PATH".to_string());
    let mut text = format!(
        "# Benchmark run\n\n\
         - scheme mix: {}\n\
         - threshold / signer count: t = {}..={} (n = t, quorum = all)\n\
         - message length ell = {}\n\
         - repetitions per point: {}\n\
         - wall clock of the whole run: {:.1} s\n\
         - toolchain: {rustc}\n\
         - host: {} {}\n\
         - this run's data: `{}` (replaying the command above writes a *new* timestamped directory)\n\n\
         ## Reproduce\n\n\
         ```text\n\
         cd threshold-bbs && CARGO_TARGET_DIR=$HOME/tbbs-target \\\n  \
         cargo run --release -p tbbs-bench -- --t-min {tmin} --t-max {tmax} --reps {reps} --len {len} {out_flag}\n\
         ```\n\n\
         ## Conventions\n\n\
         - Only signing is timed: setup and DKG happen once per `(ell, t)` before the loop.\n\
         - `ms/signer` for a stage is the stage's total over all signers divided by their count.\n\
         - The stage that assembles and verifies the signature runs on every party, because any\n\
           party may want the signature; it is charged in full against each party's runtime, so\n\
           every runtime is `a + b t` with no `1/t` term.\n\
         - Our scheme is measured twice per repetition: the typed driver (no encoding, feeds\n\
           the six-stage table) and the wire driver (everything encoded/decoded, reported as a\n\
           separate `wire` line, not inside the six stages).\n\
         - `robot-bbs` needs `|P| > t`, so it runs with `n = t` and threshold `t - 1`;\n\
           `twopass-bbs` is two-party only and appears for `t = 2`.\n",
        args.schemes.join(", "),
        args.t_min,
        args.t_max,
        args.len,
        args.reps,
        started.elapsed().as_secs_f64(),
        std::env::consts::OS,
        std::env::consts::ARCH,
        args.out.display(),
        tmin = args.t_min,
        tmax = args.t_max,
        reps = args.reps,
        len = args.len,
        out_flag = if args.out_explicit {
            format!("--out {}", args.out.display())
        } else {
            String::new()
        }
    );
    text.push_str("\n## Environment\n\n");
    text.push_str(&library_info());
    fs::write(path, text).expect("write meta.md");
}

fn variant_label(variant: &str) -> &'static str {
    match variant {
        "ours" => "two-base (main)",
        "ours-sb" => "single base",
        "ours-sb-short" => "single base + short exp",
        _ => "our construction",
    }
}

/// One section of `report.md` per instantiation: the six logical stages, the internal phases
/// and the fitted `a + b t`.
fn ours_section(
    text: &mut String,
    variant: &str,
    samples: &BTreeMap<usize, ours::Sample>,
    args: &Args,
) {
    let ts: Vec<usize> = samples.keys().copied().collect();
    if ts.is_empty() {
        return;
    }
    let label = variant_label(variant);

    text.push_str(&format!("## {label}: the six logical stages\n\n"));
    text.push_str(&format!(
        "Mean over {} repetitions; the total row also shows one standard deviation.\n\n",
        args.reps
    ));
    text.push_str("| stage |");
    for t in &ts {
        text.push_str(&format!(" t={t} |"));
    }
    text.push_str("\n|---|");
    for _ in &ts {
        text.push_str("---:|");
    }
    text.push('\n');
    for (group, _) in ours::GROUPS {
        text.push_str(&format!("| {group} |"));
        for t in &ts {
            let value = samples[t].per_stage_ms.get(group).copied().unwrap_or(0.0);
            text.push_str(&format!(" {value:.2} |"));
        }
        text.push('\n');
    }
    text.push_str("| **total** |");
    for t in &ts {
        let summary = Summary::of(&samples[t].total_reps);
        text.push_str(&format!(" **{:.2} ± {:.2}** |", summary.mean, summary.stddev));
    }
    text.push_str("\n\n");

    text.push_str(&format!("## {label}: internal phases\n\n"));
    text.push_str("| internal phase |");
    for t in &ts {
        text.push_str(&format!(" t={t} |"));
    }
    text.push_str("\n|---|");
    for _ in &ts {
        text.push_str("---:|");
    }
    text.push('\n');
    for phase in ours::phase_order() {
        let any = ts
            .iter()
            .any(|t| samples[t].per_phase_ms.get(phase.label()).copied().unwrap_or(0.0) > 0.0);
        if !any {
            continue;
        }
        text.push_str(&format!("| {} |", phase.label()));
        for t in &ts {
            let value = samples[t].per_phase_ms.get(phase.label()).copied().unwrap_or(0.0);
            text.push_str(&format!(" {value:.2} |"));
        }
        text.push('\n');
    }
    text.push('\n');

    text.push_str(&format!(
        "### Fitted `a + b t` for {label} (t = number of signers, ms per signer)\n\n"
    ));
    text.push_str("| quantity | a (ms) | b (ms / signer) | R^2 |\n|---|---:|---:|---:|\n");
    for (name, line) in fits(samples) {
        text.push_str(&format!(
            "| {name} | {:.2} | {:.3} | {:.4} |\n",
            line.a, line.b, line.r2
        ));
    }
    text.push('\n');
}

fn write_report(
    args: &Args,
    samples: &BTreeMap<&'static str, BTreeMap<usize, ours::Sample>>,
    coarse: &BTreeMap<&'static str, BTreeMap<usize, others::Coarse>>,
) {
    let mut text = String::new();
    text.push_str("# Signing runtime\n\n");
    text.push_str(&format!(
        "ell = {}, {} repetitions per point, mean over repetitions, milliseconds per signer.\n\
         Setup and DKG excluded. `n = t`, quorum = all signers.\n\n",
        args.len, args.reps
    ));

    for (variant, per_t) in samples {
        ours_section(&mut text, variant, per_t, args);
    }

    if !coarse.is_empty() {
        text.push_str("## Other schemes (coarse)\n\n");
        text.push_str(
            "Stages are read from each crate's own meter; only the dominant ones are shown.\n\n",
        );
        text.push_str("| scheme | t | stages (ms per signer) | total |\n|---|---:|---|---:|\n");
        for (scheme, per_t) in coarse {
            for (&t, sample) in per_t {
                let stages = sample
                    .stages
                    .iter()
                    .map(|(name, value)| format!("{name} {value:.1}"))
                    .collect::<Vec<_>>()
                    .join("; ");
                text.push_str(&format!(
                    "| {scheme} | {t} | {stages} | {:.1} |\n",
                    sample.total_ms
                ));
            }
        }
        text.push('\n');
    }

    if let Some((_, sample)) = samples.iter().next() {
        let _ = sample;
    }
    let _ = Summary::of(&[]);
    fs::write(args.out.join("report.md"), text).expect("write report.md");
}
