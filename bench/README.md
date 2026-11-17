# `tbbs-bench` — signing-runtime driver

Produces the runtime data for the paper: **signing only** (no setup, no DKG), one CSV/Markdown
file per table, plus a least-squares `a + b t` fit for every stage of our construction.

## Reproduce

```bash
cd threshold-bbs
CARGO_TARGET_DIR=$HOME/tbbs-target \
  cargo run --release -p tbbs-bench -- --t-min 2 --t-max 7 --reps 5 --len 10
```

Flags: `--t-min`, `--t-max`, `--reps`, `--len`, `--out DIR`,
`--schemes ours,clkem,twopass,robot,wmc24,tx25`.
Defaults are exactly the command above. Each run writes into its own directory,
`bench/data/<YYYYmmdd-HHMMSS>/`, and appends one row to `bench/data/index.md`, so a rerun never
overwrites earlier numbers — even a partial rerun (`--schemes ours`) lands in a fresh directory
and leaves the previous full dataset intact. Pass `--out DIR` to write into an exact directory
instead (no timestamp is appended); that is the escape hatch for scripted comparisons.

Use `--release`. The class-group arithmetic behind BICYCL is C++ and is unusably slow in a debug
build (the workspace's `[profile.test] opt-level = 2` does not apply to binaries).

## What is timed

* **Only the signing protocol.** `PublicParameters::setup` and `keygen` run once per `(ell, t)`
  before the timed loop and are excluded.
* `t` is both the threshold and the number of signers (`n = t`, quorum = all), which is the axis
  the `a + b t` formula is stated in.
* `robot-bbs` needs `|P| > t`, so it runs with `n = t` and threshold `t - 1`.
* `twopass-bbs` is two-party only; it appears for `t = 2` and nothing else.
* Each `(scheme, t)` point is the mean over `--reps` independent sessions; the total row also
  reports one standard deviation.

## Per-stage accounting

`ms/signer` for a stage is the stage's total over all signers divided by their number. The
exception is the signature-assembly stage: any party may want the signature, so we charge one
full execution of it against every party's runtime instead of amortising it over the signers.
This is the convention the paper's comparison table uses, and it makes every runtime `a + b t`
in `t` with no `1/t` term.

In the parent crate (`threshold-bbs`) the assembly runs once per session, so `ours.rs` charges
it in full. The five baseline crates already call their `output()`/`combine()` step once per
party inside `run_signing`, so `others.rs` divides their totals by the party count as before;
no special case is needed there.

Our construction is measured twice per repetition:

1. the **typed** driver (`session::run_views_with`) — no encoding; this feeds the six-stage
   table, because the paper's stages are computational;
2. the **wire** driver (`session::run_over_bus_with`) — every message encoded and decoded;
   reported as a separate `wire encode/decode` line and *not* folded into the six stages.

## The six logical stages and the internal phases behind them

| logical stage | internal phases (`algebra::Phase`) |
|---|---|
| 1. generating presigning message | `Round1Hash`, `Round1VrfShare`, `Round1EncodeB` |
| 2. generating presigning proof | `Round1Proof` |
| 3. verifying each peer's presigning proof | `Round2Verify` (once per peer) |
| 4. NIM decoding with each peer | `Round2Decode` (once per peer) |
| 5. finalizing online signing message | `Round2Session`, `Round2Masks`, `Round2Assemble` |
| 6. signature combination | `CombineAggregate`, `CombineVerify` |

Stages 3 and 4 are paid per peer, so their contribution is `(t - 1)` times a per-peer unit cost;
that is exactly where the `b t` term of the fit comes from.

## Files written

Everything lands in `bench/data/<timestamp>/`:

| file | contents |
|---|---|
| `meta.md` | parameters, toolchain, host, thread count, the exact command line |
| `ours_phases.csv` | our scheme: every internal phase, per `t`, per signer |
| `ours_totals.csv` | our scheme: the six stages, the total (± stddev), and wire, per `t` |
| `fit_ours.csv` | `a + b t` per stage and per phase, with `R²` |
| `others_stages.csv` | the other five schemes: their dominant stages, per `t` |
| `others_totals.csv` | the other five schemes: totals per `t` |
| `report.md` | all of the above as Markdown tables, plus the fitted formulas |

`bench/data/index.md` (one level up) indexes every run: directory, `ell`, `t` range, repetitions,
scheme mix and wall clock.

## Single-threaded, by construction

BICYCL spawns a `std::thread` in three `CL_HSMqk::CipherText` constructors (it overlaps
`h^r` with `p^r f^m`). In the upstream header that thread is unconditional, which would let a
benchmark quietly use a second core. Two things make that impossible here:

1. `bicycl/src/bicycl.h` gates those three sites (and the `<thread>` include) behind
   `BICYCL_WITH_PTHREADS`, which this workspace never defines; the fallback computes `h^r`
   inline, so the results are identical and the process stays single-threaded.
2. None of the protocols here calls the affected APIs anyway — every crate builds its own
   ciphertexts from `power_of_h`, `power_of_f` and `nucomp`, never `CL_HSMqk::encrypt` /
   `add_ciphertexts` / `scal_ciphertexts` (grep for those names: no hits).

The driver reports the process thread count at start-up and warns if it is ever not 1, so the
claim is checked on every run rather than assumed:

```text
threads in this process: Some(1) (BICYCL_WITH_PTHREADS is off, so no worker threads)
```

Belt and braces on a noisy machine: `taskset -c 0 cargo run --release -p tbbs-bench -- ...`
pins the whole run to one core, so even a stray thread could not add throughput.

## Architecture and GMP

Class-group time is dominated by GMP's hand-written `mpn` assembly, not by our Rust/C++ code:

* Fedora's `gmp-6.3.0` is a **fat** build — at load time it dispatches to one of five x86_64
  routine sets (`core2 / coreinhm / coreisbr / coreibwl / coreihwl`). On a Zen 4 CPU it picks
  the `coreihwl` set, i.e. Haswell/Broadwell class code; GMP has no Zen-specific `mpn` set in
  this build.
* Our own code is compiled for the **baseline** `x86-64` target: `RUSTFLAGS` is empty and
  `bicycl/build.rs` passes only `-std=c++14`, so no `-march=native` / `-C target-cpu=native`.
  With the arithmetic inside libgmp the effect of a native rebuild on total time is small.

Every scheme in this workspace links the same libgmp and the same baseline code generation, so
the cross-scheme comparison is fair and the absolute numbers stay portable. `meta.md` records
the GMP version, whether it is a fat build, and the rustc target features of each run.

If a "tuned" column is ever wanted: rebuild GMP with a Zen-targeted `--host`, set
`RUSTFLAGS="-C target-cpu=native"`, and report the CPU model next to the numbers — they then
stop being comparable with another machine's.

## Caveats worth stating in the paper

* Numbers are from one machine; the `meta.md` records the toolchain and host. Rerun on the
  target machine and quote from the regenerated `report.md`.
* The other five schemes are read off their own internal meters and are coarse by design —
  only their dominant stages are reported.
* `wire` is a separate line: including or excluding serialisation changes the total by ~10%.
