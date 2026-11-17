# Runs

| directory | ell | t | reps | schemes | wall clock |
|---|---:|---|---:|---|---:|
| `20261026-1525` | 10 | 2..=7 | 5 | ours, clkem, twopass, robot, wmc24, tx25 | 655 s |
| `20261027-134618-zen3gmp` | 10 | 2..=7 | 5 | ours, clkem, twopass, robot, wmc24, tx25 | 595 s |
| `20261027-231519-zen3gmp-sb` | 10 | 2..=7 | 5 | ours, ours-sb, ours-sb-short, clkem, twopass, robot, wmc24, tx25 | 712 s |
| `20261110-210514-zen3gmp` | 10 | 2..=7 | 5 | ours, ours-sb, ours-sb-short | 214 s |
| `20261110-210915-zen3gmp` | 10 | 2..=7 | 5 | clkem, twopass, robot, wmc24, tx25 | 510 s |
| `20261110-211950-zen3gmp` | 10 | 2..=7 | 5 | clkem, twopass, robot, wmc24, tx25 | 502 s |
| `20261110-213210-zen3gmp` | 10 | 2..=7 | 5 | ours, ours-sb, ours-sb-short | 217 s |
| `20261110-214615-zen3gmp-r10` | 10 | 2..=7 | 10 | ours, ours-sb, ours-sb-short | 414 s |
| `20261110-215320-zen3gmp-r10` | 10 | 2..=7 | 10 | clkem, twopass, robot | 265 s |
| `20261110-215753-zen3gmp-r10a` | 10 | 2..=5 | 10 | wmc24, tx25 | 267 s |
| `20261110-220227-zen3gmp-r10b` | 10 | 6..=7 | 10 | wmc24, tx25 | 406 s |

`20261110-210915-zen3gmp` is **invalid** (the signature-assembly stage was charged `t`
times per party) and is superseded by `20261110-211950-zen3gmp`.

The 5-rep runs of 2026-11-10 already use the combine-in-full convention but are superseded by
the 10-rep runs below, which were made after closing other programs: ours `t = 7` stddev fell
from 31 ms to 1.6 ms.

**Final paper figures (10 reps):** `20261110-214615-zen3gmp-r10` (ours),
`20261110-215320-zen3gmp-r10` (clkem, twopass, robot),
`20261110-215753-zen3gmp-r10a` + `20261110-220227-zen3gmp-r10b` (wmc24, tx25 for `t = 2..5`
and `t = 6..7`), plus `dklst-bbs/data/20261110-220959` and `20261110-221049` for DKL+23.
