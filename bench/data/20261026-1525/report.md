# Signing runtime

ell = 10, 5 repetitions per point, mean over repetitions, milliseconds per signer.
Setup and DKG excluded. `n = t`, quorum = all signers.

## Our construction: the six logical stages

| stage | t=2 | t=3 | t=4 | t=5 | t=6 | t=7 |
|---|---:|---:|---:|---:|---:|---:|
| 1. generating presigning message | 29.75 | 29.26 | 29.50 | 29.42 | 29.38 | 29.76 |
| 2. generating presigning proof | 35.72 | 35.48 | 35.69 | 35.75 | 35.52 | 35.97 |
| 3. verifying each peer's presigning proof | 40.65 | 81.08 | 121.89 | 163.38 | 204.38 | 246.44 |
| 4. NIM decoding with each peer | 35.78 | 71.22 | 106.39 | 142.92 | 178.92 | 215.97 |
| 5. finalizing online signing message | 5.62 | 5.52 | 5.70 | 5.97 | 6.37 | 6.71 |
| 6. signature combination | 3.15 | 2.09 | 1.55 | 1.25 | 1.03 | 0.90 |
| **total** | **150.68** | **224.64** | **300.72** | **378.68** | **455.58** | **535.75** |
| wire encode/decode (separate run) | 0.75 | 1.01 | 1.29 | 1.52 | 1.79 | 2.10 |

## Our construction: internal phases

| internal phase | t=2 | t=3 | t=4 | t=5 | t=6 | t=7 |
|---|---:|---:|---:|---:|---:|---:|
| round1: hashvrf | 0.18 | 0.18 | 0.18 | 0.17 | 0.17 | 0.18 |
| round1: W_i | 1.07 | 1.08 | 1.07 | 1.06 | 1.07 | 1.07 |
| round1: encode_B | 28.50 | 28.01 | 28.25 | 28.19 | 28.13 | 28.52 |
| round1: sigma prove | 35.72 | 35.48 | 35.69 | 35.75 | 35.52 | 35.97 |
| round2: verify pi_j | 40.65 | 81.08 | 121.89 | 163.38 | 204.38 | 246.44 |
| round2: decode mu/nu | 35.78 | 71.22 | 106.39 | 142.92 | 178.92 | 215.97 |
| round2: W,(e,phi),U,tr | 5.52 | 5.33 | 5.43 | 5.62 | 5.94 | 6.18 |
| round2: masks | 0.10 | 0.18 | 0.27 | 0.35 | 0.43 | 0.52 |
| round2: u_i,S_i | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| combine: aggregate | 0.14 | 0.09 | 0.07 | 0.05 | 0.05 | 0.04 |
| combine: bbs verify | 3.01 | 2.00 | 1.48 | 1.19 | 0.99 | 0.86 |

### Fitted `a + b t` (t = number of signers, ms per signer)

| quantity | a (ms) | b (ms / signer) | R^2 |
|---|---:|---:|---:|
| 1. generating presigning message | 29.47 | 0.009 | 0.0067 |
| 2. generating presigning proof | 35.50 | 0.041 | 0.1802 |
| 3. verifying each peer's presigning proof | -42.21 | 41.152 | 1.0000 |
| 4. NIM decoding with each peer | -36.87 | 36.016 | 0.9999 |
| 5. finalizing online signing message | 4.92 | 0.236 | 0.8835 |
| 6. signature combination | 3.56 | -0.421 | 0.8703 |
| total (six stages) | -5.63 | 77.031 | 0.9999 |
| phase: setup | 0.00 | 0.000 | 1.0000 |
| phase: keygen | 0.00 | 0.000 | 1.0000 |
| phase: round1: hashvrf | 0.18 | -0.000 | 0.1086 |
| phase: round1: W_i | 1.08 | -0.001 | 0.1870 |
| phase: round1: encode_B | 28.22 | 0.011 | 0.0096 |
| phase: round1: sigma prove | 35.50 | 0.041 | 0.1802 |
| phase: wire encode/decode | 0.00 | 0.000 | 1.0000 |
| phase: round2: verify pi_j | -42.21 | 41.152 | 1.0000 |
| phase: round2: decode mu/nu | -36.87 | 36.016 | 0.9999 |
| phase: round2: W,(e,phi),U,tr | 4.99 | 0.152 | 0.7631 |
| phase: round2: masks | -0.07 | 0.084 | 0.9996 |
| phase: round2: u_i,S_i | 0.00 | 0.000 | 0.0621 |
| phase: combine: aggregate | 0.16 | -0.019 | 0.8655 |
| phase: combine: bbs verify | 3.40 | -0.403 | 0.8705 |

## Other schemes (coarse)

Stages are read from each crate's own meter; only the dominant ones are shown.

| scheme | t | stages (ms per signer) | total |
|---|---:|---|---:|
| clkem-tbbs (3 rounds, CL-KEM) | 2 | sign r1: commit, phi^gamma 54.8; sign r2: open (e_i, s_i) 22.2; sign r3: R_i, pd_i 19.6; sign: BBS+ verify 6.0; sign: combine 6.4 | 109.0 |
| clkem-tbbs (3 rounds, CL-KEM) | 3 | sign r1: commit, phi^gamma 53.9; sign r2: open (e_i, s_i) 44.1; sign r3: R_i, pd_i 19.1; sign: BBS+ verify 5.9; sign: combine 6.3 | 129.3 |
| clkem-tbbs (3 rounds, CL-KEM) | 4 | sign r1: commit, phi^gamma 54.3; sign r2: open (e_i, s_i) 66.1; sign r3: R_i, pd_i 19.3; sign: BBS+ verify 5.9; sign: combine 6.3 | 152.0 |
| clkem-tbbs (3 rounds, CL-KEM) | 5 | sign r1: commit, phi^gamma 54.2; sign r2: open (e_i, s_i) 88.6; sign r3: R_i, pd_i 19.7; sign: BBS+ verify 5.9; sign: combine 6.4 | 174.7 |
| clkem-tbbs (3 rounds, CL-KEM) | 6 | sign r1: commit, phi^gamma 54.3; sign r2: open (e_i, s_i) 110.9; sign r3: R_i, pd_i 19.8; sign: BBS+ verify 5.9; sign: combine 6.4 | 197.3 |
| clkem-tbbs (3 rounds, CL-KEM) | 7 | sign r1: commit, phi^gamma 55.7; sign r2: open (e_i, s_i) 135.1; sign r3: R_i, pd_i 20.7; sign: BBS+ verify 6.0; sign: combine 6.5 | 224.0 |
| robot-bbs (2 rounds) | 2 | sign output 93.1; sign r1 91.1; sign r2 186.0 | 370.2 |
| robot-bbs (2 rounds) | 3 | sign output 133.0; sign r1 88.5; sign r2 246.7 | 468.3 |
| robot-bbs (2 rounds) | 4 | sign output 176.9; sign r1 88.8; sign r2 310.0 | 575.6 |
| robot-bbs (2 rounds) | 5 | sign output 220.2; sign r1 88.9; sign r2 370.7 | 679.8 |
| robot-bbs (2 rounds) | 6 | sign output 263.4; sign r1 88.1; sign r2 431.6 | 783.1 |
| robot-bbs (2 rounds) | 7 | sign output 310.3; sign r1 88.7; sign r2 496.3 | 895.3 |
| twopass-bbs (2 passes, 2 parties) | 2 | sign output (verify, decrypt) 37.9; sign pass 1 (beta1) 0.0; sign pass 2 (VRF, C, D, R_CL-Lin) 41.0 | 78.9 |
| tx25-bbs (2 offline + 1 online) | 2 | offline output 160.9; offline r1 60.2; offline r2 204.9; online 3.2; output 9.7 | 438.9 |
| tx25-bbs (2 offline + 1 online) | 3 | offline output 269.7; offline r1 60.3; offline r2 287.0; online 3.2; output 10.0 | 630.2 |
| tx25-bbs (2 offline + 1 online) | 4 | offline output 396.5; offline r1 60.1; offline r2 368.8; online 3.2; output 10.4 | 839.0 |
| tx25-bbs (2 offline + 1 online) | 5 | offline output 544.3; offline r1 60.4; offline r2 451.5; online 3.3; output 10.8 | 1070.2 |
| tx25-bbs (2 offline + 1 online) | 6 | offline output 719.9; offline r1 60.9; offline r2 536.9; online 3.2; output 11.4 | 1332.4 |
| tx25-bbs (2 offline + 1 online) | 7 | offline output 897.2; offline r1 60.9; offline r2 617.9; online 3.2; output 11.6 | 1590.8 |
| wmc24-bbs (4 rounds) | 2 | sign output 85.6; sign r1 120.8; sign r2 251.4; sign r3 217.8; sign r4 89.3 | 764.8 |
| wmc24-bbs (4 rounds) | 3 | sign output 127.7; sign r1 121.1; sign r2 325.4; sign r3 297.7; sign r4 108.4 | 980.3 |
| wmc24-bbs (4 rounds) | 4 | sign output 170.2; sign r1 119.8; sign r2 398.9; sign r3 382.2; sign r4 127.7 | 1198.8 |
| wmc24-bbs (4 rounds) | 5 | sign output 212.3; sign r1 119.6; sign r2 470.4; sign r3 462.9; sign r4 146.1 | 1411.3 |
| wmc24-bbs (4 rounds) | 6 | sign output 257.5; sign r1 119.8; sign r2 547.3; sign r3 551.0; sign r4 166.7 | 1642.2 |
| wmc24-bbs (4 rounds) | 7 | sign output 302.9; sign r1 120.7; sign r2 624.1; sign r3 640.2; sign r4 185.9 | 1873.7 |

