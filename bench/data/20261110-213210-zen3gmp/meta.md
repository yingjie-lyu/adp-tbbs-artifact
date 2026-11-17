# Benchmark run

- scheme mix: ours, ours-sb, ours-sb-short
- threshold / signer count: t = 2..=7 (n = t, quorum = all)
- message length ell = 10
- repetitions per point: 5
- wall clock of the whole run: 216.6 s
- toolchain: rustc 1.99.0 (b940084d7 2026-09-28) (Fedora 1.99.0-1.fc44)
- host: linux x86_64
- this run's data: `bench/data/20261110-213210-zen3gmp` (replaying the command above writes a *new* timestamped directory)

## Reproduce

```text
CARGO_TARGET_DIR=$HOME/tbbs-target \
  cargo run --release -p tbbs-bench -- --t-min 2 --t-max 7 --reps 5 --len 10 
```

## Conventions

- Only signing is timed: setup and DKG happen once per `(ell, t)` before the loop.
- `ms/signer` for a stage is the stage's total over all signers divided by their count.
- The stage that assembles and verifies the signature runs on every party, because any
party may want the signature; it is charged in full against each party's runtime, so
every runtime is `a + b t` with no `1/t` term.
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
- rustc target features: fxsr, sse, sse2 (no -C target-cpu=native)
