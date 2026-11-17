# Signing runtime

ell = 10, 5 repetitions per point, mean over repetitions, milliseconds per signer.
Setup and DKG excluded. `n = t`, quorum = all signers.

## two-base (main): the six logical stages

Mean over 5 repetitions; the total row also shows one standard deviation.

| stage | t=2 | t=3 | t=4 | t=5 | t=6 | t=7 |
|---|---:|---:|---:|---:|---:|---:|
| 1. generating presigning message | 26.83 | 26.93 | 26.93 | 27.07 | 26.69 | 27.05 |
| 2. generating presigning proof | 32.85 | 32.69 | 32.70 | 32.82 | 32.37 | 32.81 |
| 3. verifying each peer's presigning proof | 37.43 | 74.79 | 112.69 | 149.76 | 185.29 | 223.57 |
| 4. NIM decoding with each peer | 32.73 | 65.66 | 98.11 | 130.43 | 161.59 | 194.87 |
| 5. finalizing online signing message | 5.52 | 5.47 | 5.63 | 5.95 | 6.28 | 6.59 |
| 6. signature combination | 3.17 | 2.08 | 1.64 | 1.25 | 1.07 | 0.89 |
| **total** | **138.54 ± 1.36** | **207.63 ± 3.22** | **277.69 ± 1.92** | **347.28 ± 2.03** | **413.28 ± 2.67** | **485.78 ± 3.55** |

## two-base (main): internal phases

| internal phase | t=2 | t=3 | t=4 | t=5 | t=6 | t=7 |
|---|---:|---:|---:|---:|---:|---:|
| round1: hashvrf | 0.18 | 0.17 | 0.17 | 0.18 | 0.17 | 0.17 |
| round1: W_i | 1.06 | 1.05 | 1.05 | 1.07 | 1.05 | 1.06 |
| round1: encode_B | 25.59 | 25.70 | 25.71 | 25.83 | 25.46 | 25.82 |
| round1: sigma prove | 32.85 | 32.69 | 32.70 | 32.82 | 32.37 | 32.81 |
| round2: verify pi_j | 37.43 | 74.79 | 112.69 | 149.76 | 185.29 | 223.57 |
| round2: decode mu/nu | 32.73 | 65.66 | 98.11 | 130.43 | 161.59 | 194.87 |
| round2: W,(e,phi),U,tr | 5.43 | 5.29 | 5.36 | 5.59 | 5.85 | 6.08 |
| round2: masks | 0.09 | 0.18 | 0.27 | 0.36 | 0.43 | 0.51 |
| round2: u_i,S_i | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| combine: aggregate | 0.14 | 0.09 | 0.07 | 0.05 | 0.05 | 0.04 |
| combine: bbs verify | 3.03 | 1.99 | 1.57 | 1.20 | 1.01 | 0.85 |

### Fitted `a + b t` for two-base (main) (t = number of signers, ms per signer)

| quantity | a (ms) | b (ms / signer) | R^2 |
|---|---:|---:|---:|
| 1. generating presigning message | 26.85 | 0.015 | 0.0408 |
| 2. generating presigning proof | 32.84 | -0.030 | 0.1003 |
| 3. verifying each peer's presigning proof | -36.46 | 37.121 | 0.9999 |
| 4. NIM decoding with each peer | -31.49 | 32.309 | 0.9999 |
| 5. finalizing online signing message | 4.87 | 0.230 | 0.9130 |
| 6. signature combination | 3.59 | -0.424 | 0.8816 |
| total (six stages) | 0.20 | 69.221 | 0.9999 |
| phase: setup | 0.00 | 0.000 | 1.0000 |
| phase: keygen | 0.00 | 0.000 | 1.0000 |
| phase: round1: hashvrf | 0.18 | -0.000 | 0.0457 |
| phase: round1: W_i | 1.05 | 0.001 | 0.0579 |
| phase: round1: encode_B | 25.62 | 0.015 | 0.0404 |
| phase: round1: sigma prove | 32.84 | -0.030 | 0.1003 |
| phase: wire encode/decode | 0.00 | 0.000 | 1.0000 |
| phase: round2: verify pi_j | -36.46 | 37.121 | 0.9999 |
| phase: round2: decode mu/nu | -31.49 | 32.309 | 0.9999 |
| phase: round2: W,(e,phi),U,tr | 4.94 | 0.146 | 0.8022 |
| phase: round2: masks | -0.07 | 0.084 | 0.9992 |
| phase: round2: u_i,S_i | 0.00 | 0.000 | 0.7815 |
| phase: combine: aggregate | 0.15 | -0.018 | 0.8638 |
| phase: combine: bbs verify | 3.44 | -0.406 | 0.8822 |

## single base: the six logical stages

Mean over 5 repetitions; the total row also shows one standard deviation.

| stage | t=2 | t=3 | t=4 | t=5 | t=6 | t=7 |
|---|---:|---:|---:|---:|---:|---:|
| 1. generating presigning message | 14.27 | 14.25 | 14.36 | 14.43 | 14.42 | 14.42 |
| 2. generating presigning proof | 17.59 | 17.50 | 17.54 | 17.70 | 17.61 | 17.65 |
| 3. verifying each peer's presigning proof | 20.29 | 40.62 | 61.48 | 82.20 | 102.99 | 123.30 |
| 4. NIM decoding with each peer | 28.93 | 58.07 | 87.48 | 117.01 | 146.82 | 175.29 |
| 5. finalizing online signing message | 5.53 | 5.44 | 5.65 | 5.95 | 6.25 | 6.58 |
| 6. signature combination | 3.10 | 2.08 | 1.56 | 1.25 | 1.05 | 0.89 |
| **total** | **89.70 ± 0.63** | **137.95 ± 1.42** | **188.08 ± 1.46** | **238.53 ± 2.07** | **289.13 ± 1.49** | **338.14 ± 1.24** |

## single base: internal phases

| internal phase | t=2 | t=3 | t=4 | t=5 | t=6 | t=7 |
|---|---:|---:|---:|---:|---:|---:|
| round1: hashvrf | 0.17 | 0.17 | 0.17 | 0.17 | 0.18 | 0.17 |
| round1: W_i | 1.04 | 1.05 | 1.06 | 1.06 | 1.06 | 1.06 |
| round1: encode_B | 13.05 | 13.03 | 13.13 | 13.20 | 13.19 | 13.19 |
| round1: sigma prove | 17.59 | 17.50 | 17.54 | 17.70 | 17.61 | 17.65 |
| round2: verify pi_j | 20.29 | 40.62 | 61.48 | 82.20 | 102.99 | 123.30 |
| round2: decode mu/nu | 28.93 | 58.07 | 87.48 | 117.01 | 146.82 | 175.29 |
| round2: W,(e,phi),U,tr | 5.44 | 5.27 | 5.39 | 5.60 | 5.82 | 6.07 |
| round2: masks | 0.09 | 0.18 | 0.26 | 0.35 | 0.43 | 0.51 |
| round2: u_i,S_i | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| combine: aggregate | 0.13 | 0.09 | 0.07 | 0.05 | 0.05 | 0.04 |
| combine: bbs verify | 2.96 | 1.99 | 1.49 | 1.19 | 1.00 | 0.85 |

### Fitted `a + b t` for single base (t = number of signers, ms per signer)

| quantity | a (ms) | b (ms / signer) | R^2 |
|---|---:|---:|---:|
| 1. generating presigning message | 14.19 | 0.038 | 0.7801 |
| 2. generating presigning proof | 17.49 | 0.023 | 0.3681 |
| 3. verifying each peer's presigning proof | -21.13 | 20.654 | 1.0000 |
| 4. NIM decoding with each peer | -29.85 | 29.360 | 1.0000 |
| 5. finalizing online signing message | 4.87 | 0.229 | 0.9123 |
| 6. signature combination | 3.51 | -0.413 | 0.8779 |
| total (six stages) | -10.92 | 49.892 | 0.9999 |
| phase: setup | 0.00 | 0.000 | 1.0000 |
| phase: keygen | 0.00 | 0.000 | 1.0000 |
| phase: round1: hashvrf | 0.17 | 0.001 | 0.4677 |
| phase: round1: W_i | 1.04 | 0.002 | 0.4632 |
| phase: round1: encode_B | 12.97 | 0.036 | 0.7748 |
| phase: round1: sigma prove | 17.49 | 0.023 | 0.3681 |
| phase: wire encode/decode | 0.00 | 0.000 | 1.0000 |
| phase: round2: verify pi_j | -21.13 | 20.654 | 1.0000 |
| phase: round2: decode mu/nu | -29.85 | 29.360 | 1.0000 |
| phase: round2: W,(e,phi),U,tr | 4.95 | 0.144 | 0.8026 |
| phase: round2: masks | -0.08 | 0.085 | 0.9997 |
| phase: round2: u_i,S_i | 0.00 | 0.000 | 0.2067 |
| phase: combine: aggregate | 0.15 | -0.018 | 0.8801 |
| phase: combine: bbs verify | 3.36 | -0.395 | 0.8778 |

## single base + short exp: the six logical stages

Mean over 5 repetitions; the total row also shows one standard deviation.

| stage | t=2 | t=3 | t=4 | t=5 | t=6 | t=7 |
|---|---:|---:|---:|---:|---:|---:|
| 1. generating presigning message | 5.23 | 5.32 | 5.24 | 5.22 | 5.24 | 5.34 |
| 2. generating presigning proof | 8.46 | 8.65 | 8.47 | 8.35 | 8.46 | 8.52 |
| 3. verifying each peer's presigning proof | 11.38 | 22.93 | 34.13 | 45.40 | 57.06 | 68.59 |
| 4. NIM decoding with each peer | 20.06 | 40.28 | 60.01 | 79.94 | 100.06 | 120.59 |
| 5. finalizing online signing message | 5.48 | 5.44 | 5.62 | 5.89 | 6.19 | 6.60 |
| 6. signature combination | 3.11 | 2.09 | 1.56 | 1.25 | 1.04 | 0.89 |
| **total** | **53.72 ± 0.20** | **84.71 ± 0.54** | **115.03 ± 0.64** | **146.04 ± 1.53** | **178.05 ± 0.53** | **210.53 ± 2.28** |

## single base + short exp: internal phases

| internal phase | t=2 | t=3 | t=4 | t=5 | t=6 | t=7 |
|---|---:|---:|---:|---:|---:|---:|
| round1: hashvrf | 0.17 | 0.18 | 0.17 | 0.17 | 0.17 | 0.17 |
| round1: W_i | 1.04 | 1.07 | 1.05 | 1.05 | 1.05 | 1.06 |
| round1: encode_B | 4.02 | 4.08 | 4.01 | 3.99 | 4.02 | 4.11 |
| round1: sigma prove | 8.46 | 8.65 | 8.47 | 8.35 | 8.46 | 8.52 |
| round2: verify pi_j | 11.38 | 22.93 | 34.13 | 45.40 | 57.06 | 68.59 |
| round2: decode mu/nu | 20.06 | 40.28 | 60.01 | 79.94 | 100.06 | 120.59 |
| round2: W,(e,phi),U,tr | 5.39 | 5.27 | 5.37 | 5.55 | 5.76 | 6.09 |
| round2: masks | 0.09 | 0.18 | 0.26 | 0.34 | 0.43 | 0.51 |
| round2: u_i,S_i | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| combine: aggregate | 0.14 | 0.09 | 0.07 | 0.06 | 0.05 | 0.04 |
| combine: bbs verify | 2.97 | 2.00 | 1.49 | 1.20 | 0.99 | 0.85 |

### Fitted `a + b t` for single base + short exp (t = number of signers, ms per signer)

| quantity | a (ms) | b (ms / signer) | R^2 |
|---|---:|---:|---:|
| 1. generating presigning message | 5.23 | 0.009 | 0.0892 |
| 2. generating presigning proof | 8.54 | -0.011 | 0.0461 |
| 3. verifying each peer's presigning proof | -11.48 | 11.421 | 1.0000 |
| 4. NIM decoding with each peer | -20.09 | 20.055 | 1.0000 |
| 5. finalizing online signing message | 4.82 | 0.233 | 0.9128 |
| 6. signature combination | 3.53 | -0.417 | 0.8814 |
| total (six stages) | -9.45 | 31.289 | 0.9998 |
| phase: setup | 0.00 | 0.000 | 1.0000 |
| phase: keygen | 0.00 | 0.000 | 1.0000 |
| phase: round1: hashvrf | 0.18 | -0.001 | 0.2820 |
| phase: round1: W_i | 1.05 | 0.001 | 0.0659 |
| phase: round1: encode_B | 4.00 | 0.008 | 0.1006 |
| phase: round1: sigma prove | 8.54 | -0.011 | 0.0461 |
| phase: wire encode/decode | 0.00 | 0.000 | 1.0000 |
| phase: round2: verify pi_j | -11.48 | 11.421 | 1.0000 |
| phase: round2: decode mu/nu | -20.09 | 20.055 | 1.0000 |
| phase: round2: W,(e,phi),U,tr | 4.90 | 0.148 | 0.8122 |
| phase: round2: masks | -0.08 | 0.084 | 0.9999 |
| phase: round2: u_i,S_i | 0.00 | -0.000 | 0.1040 |
| phase: combine: aggregate | 0.16 | -0.019 | 0.8840 |
| phase: combine: bbs verify | 3.38 | -0.399 | 0.8812 |

## Other schemes (coarse)

Stages are read from each crate's own meter; only the dominant ones are shown.

| scheme | t | stages (ms per signer) | total |
|---|---:|---|---:|
| clkem-tbbs (3 rounds, CL-KEM) | 2 | sign r1: commit, phi^gamma 49.2; sign r2: open (e_i, s_i) 20.2; sign r3: R_i, pd_i 17.6; sign: BBS+ verify 5.9; sign: combine 6.3 | 99.2 |
| clkem-tbbs (3 rounds, CL-KEM) | 3 | sign r1: commit, phi^gamma 50.4; sign r2: open (e_i, s_i) 40.8; sign r3: R_i, pd_i 18.2; sign: BBS+ verify 6.1; sign: combine 6.4 | 122.0 |
| clkem-tbbs (3 rounds, CL-KEM) | 4 | sign r1: commit, phi^gamma 49.4; sign r2: open (e_i, s_i) 61.1; sign r3: R_i, pd_i 17.9; sign: BBS+ verify 6.0; sign: combine 6.4 | 140.8 |
| clkem-tbbs (3 rounds, CL-KEM) | 5 | sign r1: commit, phi^gamma 49.6; sign r2: open (e_i, s_i) 80.6; sign r3: R_i, pd_i 18.2; sign: BBS+ verify 6.0; sign: combine 6.4 | 160.8 |
| clkem-tbbs (3 rounds, CL-KEM) | 6 | sign r1: commit, phi^gamma 49.0; sign r2: open (e_i, s_i) 100.0; sign r3: R_i, pd_i 18.4; sign: BBS+ verify 6.0; sign: combine 6.4 | 179.8 |
| clkem-tbbs (3 rounds, CL-KEM) | 7 | sign r1: commit, phi^gamma 48.9; sign r2: open (e_i, s_i) 120.5; sign r3: R_i, pd_i 18.6; sign: BBS+ verify 6.0; sign: combine 6.5 | 200.5 |
| robot-bbs (2 rounds) | 2 | sign output 83.9; sign r1 82.5; sign r2 167.3 | 333.7 |
| robot-bbs (2 rounds) | 3 | sign output 122.2; sign r1 80.8; sign r2 225.0 | 428.1 |
| robot-bbs (2 rounds) | 4 | sign output 161.5; sign r1 81.4; sign r2 282.1 | 525.0 |
| robot-bbs (2 rounds) | 5 | sign output 204.4; sign r1 82.1; sign r2 343.5 | 630.0 |
| robot-bbs (2 rounds) | 6 | sign output 244.6; sign r1 81.9; sign r2 400.8 | 727.3 |
| robot-bbs (2 rounds) | 7 | sign output 286.5; sign r1 81.8; sign r2 458.3 | 826.5 |
| twopass-bbs (2 passes, 2 parties) | 2 | sign output (verify, decrypt) 35.4; sign pass 1 (beta1) 0.0; sign pass 2 (VRF, C, D, R_CL-Lin) 37.8 | 73.2 |
| tx25-bbs (2 offline + 1 online) | 2 | offline output 148.0; offline r1 55.1; offline r2 187.0; online 3.2; output 9.7 | 402.9 |
| tx25-bbs (2 offline + 1 online) | 3 | offline output 246.8; offline r1 55.0; offline r2 261.0; online 3.2; output 10.0 | 576.0 |
| tx25-bbs (2 offline + 1 online) | 4 | offline output 366.0; offline r1 54.9; offline r2 337.4; online 3.2; output 10.3 | 771.8 |
| tx25-bbs (2 offline + 1 online) | 5 | offline output 499.4; offline r1 54.6; offline r2 409.5; online 3.2; output 10.7 | 977.3 |
| tx25-bbs (2 offline + 1 online) | 6 | offline output 659.3; offline r1 55.7; offline r2 493.0; online 3.2; output 11.2 | 1222.4 |
| tx25-bbs (2 offline + 1 online) | 7 | offline output 822.1; offline r1 55.0; offline r2 561.3; online 3.2; output 11.4 | 1453.0 |
| wmc24-bbs (4 rounds) | 2 | sign output 78.3; sign r1 110.7; sign r2 230.0; sign r3 198.4; sign r4 82.1 | 699.4 |
| wmc24-bbs (4 rounds) | 3 | sign output 117.7; sign r1 110.7; sign r2 298.4; sign r3 273.3; sign r4 100.5 | 900.6 |
| wmc24-bbs (4 rounds) | 4 | sign output 157.5; sign r1 110.2; sign r2 366.8; sign r3 351.5; sign r4 117.9 | 1103.8 |
| wmc24-bbs (4 rounds) | 5 | sign output 196.3; sign r1 110.0; sign r2 433.3; sign r3 427.1; sign r4 136.1 | 1302.6 |
| wmc24-bbs (4 rounds) | 6 | sign output 238.4; sign r1 110.5; sign r2 502.9; sign r3 506.2; sign r4 153.3 | 1511.2 |
| wmc24-bbs (4 rounds) | 7 | sign output 278.6; sign r1 110.3; sign r2 571.3; sign r3 586.1; sign r4 171.4 | 1717.7 |

