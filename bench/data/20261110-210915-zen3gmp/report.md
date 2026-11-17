# Signing runtime

ell = 10, 5 repetitions per point, mean over repetitions, milliseconds per signer.
Setup and DKG excluded. `n = t`, quorum = all signers.

## Other schemes (coarse)

Stages are read from each crate's own meter; only the dominant ones are shown.

| scheme | t | stages (ms per signer) | total |
|---|---:|---|---:|
| clkem-tbbs (3 rounds, CL-KEM) | 2 | sign r1: commit, phi^gamma 52.3; sign r2: open (e_i, s_i) 21.2; sign r3: R_i, pd_i 18.9; sign: BBS+ verify 12.7; sign: combine 13.4 | 118.5 |
| clkem-tbbs (3 rounds, CL-KEM) | 3 | sign r1: commit, phi^gamma 51.8; sign r2: open (e_i, s_i) 42.1; sign r3: R_i, pd_i 18.4; sign: BBS+ verify 18.4; sign: combine 19.6 | 150.2 |
| clkem-tbbs (3 rounds, CL-KEM) | 4 | sign r1: commit, phi^gamma 51.2; sign r2: open (e_i, s_i) 62.7; sign r3: R_i, pd_i 18.6; sign: BBS+ verify 24.9; sign: combine 26.5 | 183.9 |
| clkem-tbbs (3 rounds, CL-KEM) | 5 | sign r1: commit, phi^gamma 51.6; sign r2: open (e_i, s_i) 84.7; sign r3: R_i, pd_i 19.0; sign: BBS+ verify 30.9; sign: combine 33.1 | 219.4 |
| clkem-tbbs (3 rounds, CL-KEM) | 6 | sign r1: commit, phi^gamma 51.7; sign r2: open (e_i, s_i) 105.5; sign r3: R_i, pd_i 19.1; sign: BBS+ verify 37.2; sign: combine 39.9 | 253.4 |
| clkem-tbbs (3 rounds, CL-KEM) | 7 | sign r1: commit, phi^gamma 51.6; sign r2: open (e_i, s_i) 125.9; sign r3: R_i, pd_i 19.3; sign: BBS+ verify 43.7; sign: combine 47.2 | 287.8 |
| robot-bbs (2 rounds) | 2 | sign output 176.5; sign r1 84.4; sign r2 175.1 | 436.0 |
| robot-bbs (2 rounds) | 3 | sign output 382.8; sign r1 83.2; sign r2 235.7 | 701.7 |
| robot-bbs (2 rounds) | 4 | sign output 667.8; sign r1 86.2; sign r2 296.5 | 1050.5 |
| robot-bbs (2 rounds) | 5 | sign output 1095.1; sign r1 87.6; sign r2 368.6 | 1551.3 |
| robot-bbs (2 rounds) | 6 | sign output 1489.3; sign r1 83.3; sign r2 409.5 | 1982.1 |
| robot-bbs (2 rounds) | 7 | sign output 2053.0; sign r1 84.2; sign r2 457.3 | 2594.5 |
| twopass-bbs (2 passes, 2 parties) | 2 | sign output (verify, decrypt) 73.3; sign pass 1 (beta1) 0.0; sign pass 2 (VRF, C, D, R_CL-Lin) 39.1 | 112.4 |
| tx25-bbs (2 offline + 1 online) | 2 | offline output 144.2; offline r1 54.1; offline r2 182.5; online 3.1; output 18.9 | 402.9 |
| tx25-bbs (2 offline + 1 online) | 3 | offline output 239.2; offline r1 53.2; offline r2 254.7; online 3.1; output 29.3 | 579.4 |
| tx25-bbs (2 offline + 1 online) | 4 | offline output 351.4; offline r1 53.3; offline r2 327.1; online 3.1; output 40.2 | 775.1 |
| tx25-bbs (2 offline + 1 online) | 5 | offline output 509.8; offline r1 55.0; offline r2 415.1; online 3.3; output 53.9 | 1037.0 |
| tx25-bbs (2 offline + 1 online) | 6 | offline output 658.0; offline r1 56.6; offline r2 490.5; online 3.2; output 68.5 | 1276.8 |
| tx25-bbs (2 offline + 1 online) | 7 | offline output 874.4; offline r1 57.1; offline r2 580.1; online 3.3; output 82.9 | 1597.8 |
| wmc24-bbs (4 rounds) | 2 | sign output 162.6; sign r1 114.2; sign r2 236.7; sign r3 207.3; sign r4 85.0 | 805.8 |
| wmc24-bbs (4 rounds) | 3 | sign output 366.6; sign r1 113.9; sign r2 308.8; sign r3 286.5; sign r4 104.3 | 1180.2 |
| wmc24-bbs (4 rounds) | 4 | sign output 657.1; sign r1 116.0; sign r2 380.9; sign r3 369.2; sign r4 124.3 | 1647.4 |
| wmc24-bbs (4 rounds) | 5 | sign output 1011.7; sign r1 116.5; sign r2 468.6; sign r3 450.3; sign r4 139.0 | 2186.3 |
| wmc24-bbs (4 rounds) | 6 | sign output 1376.5; sign r1 106.5; sign r2 485.9; sign r3 489.4; sign r4 149.6 | 2607.8 |
| wmc24-bbs (4 rounds) | 7 | sign output 1946.4; sign r1 108.5; sign r2 568.4; sign r3 592.7; sign r4 180.4 | 3396.5 |

