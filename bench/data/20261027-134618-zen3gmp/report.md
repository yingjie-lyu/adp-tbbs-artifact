# Signing runtime

ell = 10, 5 repetitions per point, mean over repetitions, milliseconds per signer.
Setup and DKG excluded. `n = t`, quorum = all signers.

## Our construction: the six logical stages

| stage | t=2 | t=3 | t=4 | t=5 | t=6 | t=7 |
|---|---:|---:|---:|---:|---:|---:|
| 1. generating presigning message | 26.56 | 26.59 | 26.79 | 26.51 | 26.48 | 26.67 |
| 2. generating presigning proof | 32.20 | 32.27 | 32.43 | 32.11 | 32.24 | 32.36 |
| 3. verifying each peer's presigning proof | 37.37 | 74.28 | 110.74 | 146.71 | 184.35 | 221.83 |
| 4. NIM decoding with each peer | 32.22 | 64.69 | 96.60 | 127.75 | 160.23 | 192.74 |
| 5. finalizing online signing message | 5.51 | 5.48 | 5.59 | 5.83 | 6.19 | 6.54 |
| 6. signature combination | 3.12 | 2.08 | 1.57 | 1.24 | 1.04 | 0.88 |
| **total** | **136.99** | **205.39** | **273.72** | **340.15** | **410.53** | **481.03** |
| wire encode/decode (separate run) | 0.72 | 0.97 | 1.22 | 1.46 | 1.72 | 1.99 |

## Our construction: internal phases

| internal phase | t=2 | t=3 | t=4 | t=5 | t=6 | t=7 |
|---|---:|---:|---:|---:|---:|---:|
| round1: hashvrf | 0.18 | 0.18 | 0.18 | 0.18 | 0.18 | 0.18 |
| round1: W_i | 1.05 | 1.05 | 1.05 | 1.05 | 1.05 | 1.05 |
| round1: encode_B | 25.33 | 25.36 | 25.56 | 25.28 | 25.25 | 25.45 |
| round1: sigma prove | 32.20 | 32.27 | 32.43 | 32.11 | 32.24 | 32.36 |
| round2: verify pi_j | 37.37 | 74.28 | 110.74 | 146.71 | 184.35 | 221.83 |
| round2: decode mu/nu | 32.22 | 64.69 | 96.60 | 127.75 | 160.23 | 192.74 |
| round2: W,(e,phi),U,tr | 5.42 | 5.31 | 5.33 | 5.49 | 5.76 | 6.03 |
| round2: masks | 0.09 | 0.17 | 0.25 | 0.34 | 0.42 | 0.51 |
| round2: u_i,S_i | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| combine: aggregate | 0.14 | 0.09 | 0.07 | 0.05 | 0.04 | 0.04 |
| combine: bbs verify | 2.99 | 1.99 | 1.50 | 1.19 | 0.99 | 0.85 |

### Fitted `a + b t` (t = number of signers, ms per signer)

| quantity | a (ms) | b (ms / signer) | R^2 |
|---|---:|---:|---:|
| 1. generating presigning message | 26.61 | -0.002 | 0.0013 |
| 2. generating presigning proof | 32.22 | 0.011 | 0.0320 |
| 3. verifying each peer's presigning proof | -36.45 | 36.815 | 0.9999 |
| 4. NIM decoding with each peer | -31.67 | 32.010 | 1.0000 |
| 5. finalizing online signing message | 4.89 | 0.214 | 0.8815 |
| 6. signature combination | 3.54 | -0.419 | 0.8787 |
| total (six stages) | -0.86 | 68.629 | 0.9999 |
| phase: setup | 0.00 | 0.000 | 1.0000 |
| phase: keygen | 0.00 | 0.000 | 1.0000 |
| phase: round1: hashvrf | 0.18 | 0.000 | 0.4703 |
| phase: round1: W_i | 1.06 | -0.001 | 0.8040 |
| phase: round1: encode_B | 25.38 | -0.001 | 0.0004 |
| phase: round1: sigma prove | 32.22 | 0.011 | 0.0320 |
| phase: wire encode/decode | 0.00 | 0.000 | 1.0000 |
| phase: round2: verify pi_j | -36.45 | 36.815 | 0.9999 |
| phase: round2: decode mu/nu | -31.67 | 32.010 | 1.0000 |
| phase: round2: W,(e,phi),U,tr | 4.97 | 0.131 | 0.7395 |
| phase: round2: masks | -0.08 | 0.084 | 0.9998 |
| phase: round2: u_i,S_i | 0.00 | -0.000 | 0.0001 |
| phase: combine: aggregate | 0.15 | -0.018 | 0.8776 |
| phase: combine: bbs verify | 3.39 | -0.401 | 0.8788 |

## Other schemes (coarse)

Stages are read from each crate's own meter; only the dominant ones are shown.

| scheme | t | stages (ms per signer) | total |
|---|---:|---|---:|
| clkem-tbbs (3 rounds, CL-KEM) | 2 | sign r1: commit, phi^gamma 48.9; sign r2: open (e_i, s_i) 19.9; sign r3: R_i, pd_i 17.5; sign: BBS+ verify 5.9; sign: combine 6.3 | 98.5 |
| clkem-tbbs (3 rounds, CL-KEM) | 3 | sign r1: commit, phi^gamma 48.6; sign r2: open (e_i, s_i) 39.6; sign r3: R_i, pd_i 17.5; sign: BBS+ verify 5.9; sign: combine 6.3 | 117.8 |
| clkem-tbbs (3 rounds, CL-KEM) | 4 | sign r1: commit, phi^gamma 49.8; sign r2: open (e_i, s_i) 60.1; sign r3: R_i, pd_i 17.9; sign: BBS+ verify 6.0; sign: combine 6.4 | 140.2 |
| clkem-tbbs (3 rounds, CL-KEM) | 5 | sign r1: commit, phi^gamma 48.7; sign r2: open (e_i, s_i) 79.5; sign r3: R_i, pd_i 18.3; sign: BBS+ verify 5.9; sign: combine 6.3 | 158.7 |
| clkem-tbbs (3 rounds, CL-KEM) | 6 | sign r1: commit, phi^gamma 48.6; sign r2: open (e_i, s_i) 99.4; sign r3: R_i, pd_i 18.0; sign: BBS+ verify 5.9; sign: combine 6.3 | 178.2 |
| clkem-tbbs (3 rounds, CL-KEM) | 7 | sign r1: commit, phi^gamma 48.8; sign r2: open (e_i, s_i) 119.5; sign r3: R_i, pd_i 18.4; sign: BBS+ verify 5.9; sign: combine 6.4 | 199.0 |
| robot-bbs (2 rounds) | 2 | sign output 83.5; sign r1 80.8; sign r2 166.0 | 330.3 |
| robot-bbs (2 rounds) | 3 | sign output 121.3; sign r1 80.5; sign r2 223.4 | 425.2 |
| robot-bbs (2 rounds) | 4 | sign output 160.4; sign r1 80.8; sign r2 280.7 | 521.9 |
| robot-bbs (2 rounds) | 5 | sign output 200.6; sign r1 81.0; sign r2 337.1 | 618.6 |
| robot-bbs (2 rounds) | 6 | sign output 240.9; sign r1 80.5; sign r2 393.3 | 714.7 |
| robot-bbs (2 rounds) | 7 | sign output 282.4; sign r1 80.6; sign r2 451.2 | 814.2 |
| twopass-bbs (2 passes, 2 parties) | 2 | sign output (verify, decrypt) 34.7; sign pass 1 (beta1) 0.0; sign pass 2 (VRF, C, D, R_CL-Lin) 37.1 | 71.8 |
| tx25-bbs (2 offline + 1 online) | 2 | offline output 150.1; offline r1 55.5; offline r2 191.7; online 3.2; output 9.9 | 410.4 |
| tx25-bbs (2 offline + 1 online) | 3 | offline output 246.2; offline r1 54.7; offline r2 260.6; online 3.2; output 10.0 | 574.6 |
| tx25-bbs (2 offline + 1 online) | 4 | offline output 363.7; offline r1 54.7; offline r2 336.1; online 3.2; output 10.4 | 768.1 |
| tx25-bbs (2 offline + 1 online) | 5 | offline output 500.1; offline r1 55.7; offline r2 412.5; online 3.2; output 10.7 | 982.3 |
| tx25-bbs (2 offline + 1 online) | 6 | offline output 650.7; offline r1 54.6; offline r2 484.6; online 3.2; output 11.3 | 1204.3 |
| tx25-bbs (2 offline + 1 online) | 7 | offline output 818.2; offline r1 55.1; offline r2 563.9; online 3.2; output 11.4 | 1451.9 |
| wmc24-bbs (4 rounds) | 2 | sign output 77.3; sign r1 108.9; sign r2 226.3; sign r3 195.7; sign r4 80.7 | 689.0 |
| wmc24-bbs (4 rounds) | 3 | sign output 120.1; sign r1 111.4; sign r2 298.0; sign r3 280.8; sign r4 102.0 | 912.2 |
| wmc24-bbs (4 rounds) | 4 | sign output 158.3; sign r1 111.7; sign r2 369.8; sign r3 351.8; sign r4 118.7 | 1110.1 |
| wmc24-bbs (4 rounds) | 5 | sign output 194.6; sign r1 109.2; sign r2 431.7; sign r3 422.3; sign r4 133.5 | 1291.3 |
| wmc24-bbs (4 rounds) | 6 | sign output 233.6; sign r1 109.5; sign r2 496.1; sign r3 497.4; sign r4 151.0 | 1487.6 |
| wmc24-bbs (4 rounds) | 7 | sign output 283.0; sign r1 110.1; sign r2 570.5; sign r3 580.6; sign r4 170.9 | 1715.0 |

