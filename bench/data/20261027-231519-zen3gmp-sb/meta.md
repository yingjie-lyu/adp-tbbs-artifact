# Benchmark run

- scheme mix: ours, ours-sb, ours-sb-short, clkem, twopass, robot, wmc24, tx25
- threshold / signer count: t = 2..=7 (n = t, quorum = all)
- message length ell = 10
- repetitions per point: 5
- wall clock of the whole run: 711.6 s
- toolchain: rustc 1.99.0 (b940084d7 2026-09-28) (Fedora 1.99.0-1.fc44)
- host: linux x86_64
- this run's data: `bench/data/20261027-231519-zen3gmp-sb` (replaying the command above writes a *new* timestamped directory)

## Reproduce

```text
CARGO_TARGET_DIR=$HOME/tbbs-target \
  cargo run --release -p tbbs-bench -- --t-min 2 --t-max 7 --reps 5 --len 10 
```

## Conventions

- Only signing is timed: setup and DKG happen once per `(ell, t)` before the loop.
- `ms/signer` for a stage is the stage's total over all signers divided by their count,
so a stage that only the combiner runs is amortised the same way.
- Our scheme is measured twice per repetition: the typed driver (no encoding, feeds
the six-stage table) and the wire driver (everything encoded/decoded, reported as a
separate `wire` line, not inside the six stages).
- `robot-bbs` needs `|P| > t`, so it runs with `n = t` and threshold `t - 1`;
`twopass-bbs` is two-party only and appears for `t = 2`.

## Environment

- GMP headers: 6.3.0 (/usr/include/gmp-x86_64.h)
- GMP package: gmp-6.3.0-5.fc44.x86_64
- GMP loaded by this process: /root/gmp-native/lib/libgmp.so.10.5.0
- GMP library /root/gmp-native/lib/libgmp.so.10.5.0: fat = false
- RUSTFLAGS at build time: -C target-cpu=native -L native=/root/gmp-native/lib
- CXXFLAGS at build time: -march=native -O3
- rustc target features: fxsr, sse, sse2 (no -C target-cpu=native)
