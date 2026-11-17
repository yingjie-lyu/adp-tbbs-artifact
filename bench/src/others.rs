//! The other five implementations in this workspace, at coarse granularity: only the stages
//! that dominate their signing cost, read straight off each crate's own meter.

use std::collections::BTreeMap;
use std::sync::Arc;

use bicycl::Mpz;

use tcl::meter::Meter;

use threshold_bbs::algebra::Scalar;
use threshold_bbs::bls381::{Scalar255, SCALAR_MODULUS_DECIMAL};

/// Coarse measurement of one scheme at one `(ell, t)`.
pub struct Coarse {
    pub stages: BTreeMap<String, f64>,
    pub total_ms: f64,
    pub parties: usize,
}

fn messages(len: usize) -> Vec<Scalar255> {
    (0..len)
        .map(|index| Scalar255::from_u64(index as u64 + 1))
        .collect()
}

fn cl_parameters(lambda_s: usize) -> Arc<tcl::ClParameters> {
    Arc::new(tcl::ClParameters::setup(
        &Mpz::from(SCALAR_MODULUS_DECIMAL),
        1827,
        128,
        lambda_s,
    ))
}

/// Average of each named step over `reps` runs, divided by the number of signers.
///
/// Unlike the parent crate, all five baselines call their output/combine step once *per party*
/// inside `run_signing`, so dividing by `parties` already charges every party its own local
/// assembly of the signature. No special case is needed here.
fn collect(meter: &Meter, parties: usize, samples: &mut BTreeMap<String, Vec<f64>>) {
    for (name, (calls, elapsed)) in meter.steps() {
        if calls == 0 {
            continue;
        }
        let entry = samples.entry(name.to_string()).or_default();
        entry.push(elapsed.as_secs_f64() * 1e3 / parties as f64);
    }
}

fn finish(mut samples: BTreeMap<String, Vec<f64>>, parties: usize) -> Coarse {
    let mut stages = BTreeMap::new();
    let mut total_ms = 0.0;
    for (name, values) in samples.iter_mut() {
        let mean = values.iter().sum::<f64>() / values.len() as f64;
        stages.insert(name.clone(), mean);
        total_ms += mean;
    }
    Coarse {
        stages,
        total_ms,
        parties,
    }
}

/// `clkem-tbbs`: three signing rounds over a CL KEM (`n = t`, quorum = all).
pub fn clkem(message_len: usize, t: usize, reps: usize) -> Result<Coarse, String> {
    use clkem_tbbs::params::PublicParameters;
    use clkem_tbbs::session::{run_keygen, run_signing};
    use clkem_tbbs::stats::Meter as ClMeter;

    let pp = PublicParameters::production(message_len);
    let quorum: Vec<usize> = (1..=t).collect();
    let message = messages(message_len);
    let mut keygen_meter = ClMeter::new();
    let keygen = run_keygen(pp, t, t, b"bench", &mut keygen_meter)
        .map_err(|error| format!("clkem keygen: {error}"))?;

    let mut samples: BTreeMap<String, Vec<f64>> = BTreeMap::new();
    for rep in 0..reps {
        let mut meter = ClMeter::new();
        let session = format!("bench-clkem-{rep}");
        run_signing(&keygen.parties, &quorum, &message, session.as_bytes(), &mut meter)
            .map_err(|error| format!("clkem signing: {error}"))?;
        for stage in clkem_tbbs::stats::Stage::ALL {
            let (calls, elapsed) = meter.stage(stage);
            if calls == 0 {
                continue;
            }
            samples
                .entry(stage.label().to_string())
                .or_default()
                .push(elapsed.as_secs_f64() * 1e3 / t as f64);
        }
    }
    Ok(finish(samples, t))
}

/// `twopass-bbs`: two parties, two passes (only defined for `t = 2`).
pub fn twopass(message_len: usize, reps: usize) -> Result<Coarse, String> {
    use twopass_bbs::params::PublicParameters;
    use twopass_bbs::session::{run_dkg, run_signing};
    use twopass_bbs::sign::{SignerOne, SignerTwo};

    use twopass_bbs::meter::{Meter as TwMeter, Stage as TwStage};

    let pp = PublicParameters::production(message_len);
    let message = messages(message_len);
    let mut samples: BTreeMap<String, Vec<f64>> = BTreeMap::new();
    for rep in 0..reps {
        let mut dkg_meter = TwMeter::new();
        let dkg = run_dkg(pp.clone(), b"bench", &mut dkg_meter)
            .map_err(|error| format!("twopass dkg: {error}"))?;
        let mut first = SignerOne::new(dkg.first);
        let mut second = SignerTwo::new(dkg.second);
        let mut meter = TwMeter::new();
        let session = format!("bench-twopass-{rep}");
        run_signing(&mut first, &mut second, &message, session.as_bytes(), &mut meter)
            .map_err(|error| format!("twopass signing: {error}"))?;
        for stage in TwStage::ALL {
            let (calls, elapsed) = meter.stage(stage);
            if calls == 0 {
                continue;
            }
            samples
                .entry(stage.label().to_string())
                .or_default()
                .push(elapsed.as_secs_f64() * 1e3 / 2.0);
        }
    }
    Ok(finish(samples, 2))
}

fn tcl_keyset(
    lambda_s: usize,
    parties: &[usize],
    t: usize,
    len: usize,
) -> Result<
    (
        Arc<tcl::ClParameters>,
        BTreeMap<usize, tcl::ThresholdKeys>,
    ),
    String,
> {
    let cl = cl_parameters(lambda_s);
    let mut meter = Meter::new();
    let keys = tcl::setup(cl.clone(), parties, t, b"bench", &mut meter)
        .map_err(|error| format!("dkg: {error}"))?;
    let _ = len;
    Ok((cl, keys))
}

/// `robot-bbs`: two rounds. The scheme needs `|P| > t`, so the quorum here is `t` parties with
/// threshold `t - 1`.
pub fn robot(message_len: usize, t: usize, reps: usize) -> Result<Coarse, String> {
    use robot_bbs::bbs::{Bases, PublicParameters};
    use robot_bbs::session::run_signing;

    let parties: Vec<usize> = (1..=t).collect();
    let threshold = t.saturating_sub(1).max(1);
    let (cl, keys) = tcl_keyset(80, &parties, threshold, message_len)?;
    let params = PublicParameters::new(cl, message_len);
    let bases = Bases::derive(&keys[&1].x_public, message_len);
    let message = messages(message_len);

    let mut samples: BTreeMap<String, Vec<f64>> = BTreeMap::new();
    for rep in 0..reps {
        let mut meter = Meter::new();
        let session = format!("bench-robot-{rep}");
        run_signing(
            &keys,
            &bases,
            params.clone(),
            &parties,
            &message,
            session.as_bytes(),
            &mut meter,
        )
        .map_err(|error| format!("robot signing: {error}"))?;
        collect(&meter, t, &mut samples);
    }
    Ok(finish(samples, t))
}

/// `wmc24-bbs`: four rounds.
pub fn wmc24(message_len: usize, t: usize, reps: usize) -> Result<Coarse, String> {
    use wmc24_bbs::bbs::PublicParameters;
    use wmc24_bbs::session::run_signing;

    let parties: Vec<usize> = (1..=t).collect();
    let (cl, keys) = tcl_keyset(80, &parties, t, message_len)?;
    let params = PublicParameters::new(cl, message_len);
    let message = messages(message_len);

    let mut samples: BTreeMap<String, Vec<f64>> = BTreeMap::new();
    for rep in 0..reps {
        let mut meter = Meter::new();
        let session = format!("bench-wmc24-{rep}");
        run_signing(
            &keys,
            params.clone(),
            &parties,
            &message,
            session.as_bytes(),
            &mut meter,
        )
        .map_err(|error| format!("wmc24 signing: {error}"))?;
        collect(&meter, t, &mut samples);
    }
    Ok(finish(samples, t))
}

/// `tx25-bbs`: two offline rounds plus one online round.
pub fn tx25(message_len: usize, t: usize, reps: usize) -> Result<Coarse, String> {
    use tx25_bbs::keys;
    use tx25_bbs::params::PublicParameters;
    use tx25_bbs::session::run_signing;

    let parties: Vec<usize> = (1..=t).collect();
    let cl = cl_parameters(80);
    let params = PublicParameters::new(cl, message_len);
    let mut setup_meter = Meter::new();
    let keys = keys::setup(params.clone(), &parties, t, b"bench", &mut setup_meter)
        .map_err(|error| format!("tx25 setup: {error}"))?;
    let message = messages(message_len);

    let mut samples: BTreeMap<String, Vec<f64>> = BTreeMap::new();
    for rep in 0..reps {
        let mut meter = Meter::new();
        let session = format!("bench-tx25-{rep}");
        run_signing(&keys, &parties, &message, session.as_bytes(), &mut meter)
            .map_err(|error| format!("tx25 signing: {error}"))?;
        collect(&meter, t, &mut samples);
    }
    Ok(finish(samples, t))
}
