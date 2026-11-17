# Signing runtime

ell = 10, 10 repetitions per point, mean over repetitions, milliseconds per signer.
Setup and DKG excluded. `n = t`, quorum = all signers.

## two-base (main): the six logical stages

Mean over 10 repetitions; the total row also shows one standard deviation.

| stage | t=2 | t=3 | t=4 | t=5 | t=6 | t=7 |
|---|---:|---:|---:|---:|---:|---:|
| 1. generating presigning message | 27.64 | 27.39 | 27.24 | 26.88 | 26.34 | 26.46 |
| 2. generating presigning proof | 33.41 | 33.22 | 33.10 | 32.72 | 31.93 | 32.10 |
| 3. verifying each peer's presigning proof | 38.56 | 76.21 | 113.79 | 149.42 | 183.28 | 221.06 |
| 4. NIM decoding with each peer | 33.72 | 66.25 | 99.55 | 129.62 | 159.59 | 191.92 |
| 5. finalizing online signing message | 5.66 | 5.59 | 5.70 | 5.90 | 6.19 | 6.59 |
| 6. signature combination | 6.38 | 6.32 | 6.38 | 6.22 | 6.23 | 6.19 |
| **total** | **145.37 ± 1.33** | **214.98 ± 2.21** | **285.77 ± 2.83** | **350.77 ± 5.28** | **413.57 ± 1.03** | **484.32 ± 1.60** |

## two-base (main): internal phases

| internal phase | t=2 | t=3 | t=4 | t=5 | t=6 | t=7 |
|---|---:|---:|---:|---:|---:|---:|
| round1: hashvrf | 0.18 | 0.18 | 0.18 | 0.18 | 0.17 | 0.17 |
| round1: W_i | 1.07 | 1.06 | 1.06 | 1.06 | 1.04 | 1.05 |
| round1: encode_B | 26.40 | 26.15 | 26.01 | 25.64 | 25.12 | 25.24 |
| round1: sigma prove | 33.41 | 33.22 | 33.10 | 32.72 | 31.93 | 32.10 |
| round2: verify pi_j | 38.56 | 76.21 | 113.79 | 149.42 | 183.28 | 221.06 |
| round2: decode mu/nu | 33.72 | 66.25 | 99.55 | 129.62 | 159.59 | 191.92 |
| round2: W,(e,phi),U,tr | 5.57 | 5.40 | 5.44 | 5.56 | 5.77 | 6.08 |
| round2: masks | 0.09 | 0.18 | 0.26 | 0.34 | 0.42 | 0.51 |
| round2: u_i,S_i | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| combine: aggregate | 0.27 | 0.28 | 0.28 | 0.27 | 0.27 | 0.27 |
| combine: bbs verify | 6.11 | 6.05 | 6.10 | 5.95 | 5.96 | 5.92 |

### Fitted `a + b t` for two-base (main) (t = number of signers, ms per signer)

| quantity | a (ms) | b (ms / signer) | R^2 |
|---|---:|---:|---:|
| 1. generating presigning message | 28.21 | -0.270 | 0.9283 |
| 2. generating presigning proof | 34.13 | -0.308 | 0.8898 |
| 3. verifying each peer's presigning proof | -32.82 | 36.268 | 0.9997 |
| 4. NIM decoding with each peer | -28.13 | 31.461 | 0.9997 |
| 5. finalizing online signing message | 5.08 | 0.190 | 0.8492 |
| 6. signature combination | 6.47 | -0.040 | 0.7692 |
| total (six stages) | 12.94 | 67.301 | 0.9996 |
| phase: setup | 0.00 | 0.000 | 1.0000 |
| phase: keygen | 0.00 | 0.000 | 1.0000 |
| phase: round1: hashvrf | 0.19 | -0.002 | 0.7941 |
| phase: round1: W_i | 1.08 | -0.005 | 0.8605 |
| phase: round1: encode_B | 26.94 | -0.263 | 0.9293 |
| phase: round1: sigma prove | 34.13 | -0.308 | 0.8898 |
| phase: wire encode/decode | 0.00 | 0.000 | 1.0000 |
| phase: round2: verify pi_j | -32.82 | 36.268 | 0.9997 |
| phase: round2: decode mu/nu | -28.13 | 31.461 | 0.9997 |
| phase: round2: W,(e,phi),U,tr | 5.15 | 0.108 | 0.6396 |
| phase: round2: masks | -0.07 | 0.082 | 0.9997 |
| phase: round2: u_i,S_i | 0.00 | 0.000 | 0.0000 |
| phase: combine: aggregate | 0.28 | -0.001 | 0.1810 |
| phase: combine: bbs verify | 6.19 | -0.039 | 0.7989 |

## single base: the six logical stages

Mean over 10 repetitions; the total row also shows one standard deviation.

| stage | t=2 | t=3 | t=4 | t=5 | t=6 | t=7 |
|---|---:|---:|---:|---:|---:|---:|
| 1. generating presigning message | 14.20 | 14.10 | 14.22 | 14.22 | 14.26 | 14.26 |
| 2. generating presigning proof | 17.37 | 17.24 | 17.34 | 17.37 | 17.49 | 17.41 |
| 3. verifying each peer's presigning proof | 20.25 | 40.08 | 60.47 | 81.34 | 101.72 | 121.84 |
| 4. NIM decoding with each peer | 28.97 | 57.25 | 86.24 | 116.40 | 144.71 | 173.68 |
| 5. finalizing online signing message | 5.52 | 5.44 | 5.60 | 5.93 | 6.24 | 6.62 |
| 6. signature combination | 6.27 | 6.21 | 6.24 | 6.32 | 6.24 | 6.20 |
| **total** | **92.59 ± 0.78** | **140.32 ± 0.64** | **190.11 ± 1.46** | **241.59 ± 3.44** | **290.66 ± 1.28** | **339.99 ± 1.42** |

## single base: internal phases

| internal phase | t=2 | t=3 | t=4 | t=5 | t=6 | t=7 |
|---|---:|---:|---:|---:|---:|---:|
| round1: hashvrf | 0.17 | 0.17 | 0.17 | 0.17 | 0.17 | 0.17 |
| round1: W_i | 1.05 | 1.04 | 1.04 | 1.05 | 1.05 | 1.05 |
| round1: encode_B | 12.98 | 12.88 | 13.01 | 12.99 | 13.04 | 13.04 |
| round1: sigma prove | 17.37 | 17.24 | 17.34 | 17.37 | 17.49 | 17.41 |
| round2: verify pi_j | 20.25 | 40.08 | 60.47 | 81.34 | 101.72 | 121.84 |
| round2: decode mu/nu | 28.97 | 57.25 | 86.24 | 116.40 | 144.71 | 173.68 |
| round2: W,(e,phi),U,tr | 5.43 | 5.26 | 5.34 | 5.59 | 5.82 | 6.11 |
| round2: masks | 0.09 | 0.17 | 0.26 | 0.35 | 0.42 | 0.51 |
| round2: u_i,S_i | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| combine: aggregate | 0.28 | 0.28 | 0.27 | 0.27 | 0.27 | 0.27 |
| combine: bbs verify | 5.99 | 5.94 | 5.97 | 6.05 | 5.97 | 5.93 |

### Fitted `a + b t` for single base (t = number of signers, ms per signer)

| quantity | a (ms) | b (ms / signer) | R^2 |
|---|---:|---:|---:|
| 1. generating presigning message | 14.11 | 0.022 | 0.4878 |
| 2. generating presigning proof | 17.25 | 0.027 | 0.3885 |
| 3. verifying each peer's presigning proof | -20.81 | 20.392 | 1.0000 |
| 4. NIM decoding with each peer | -29.42 | 29.029 | 0.9999 |
| 5. finalizing online signing message | 4.83 | 0.235 | 0.8937 |
| 6. signature combination | 6.27 | -0.005 | 0.0457 |
| total (six stages) | -7.78 | 49.701 | 0.9999 |
| phase: setup | 0.00 | 0.000 | 1.0000 |
| phase: keygen | 0.00 | 0.000 | 1.0000 |
| phase: round1: hashvrf | 0.17 | 0.001 | 0.5540 |
| phase: round1: W_i | 1.04 | 0.001 | 0.0581 |
| phase: round1: encode_B | 12.90 | 0.021 | 0.4693 |
| phase: round1: sigma prove | 17.25 | 0.027 | 0.3885 |
| phase: wire encode/decode | 0.00 | 0.000 | 1.0000 |
| phase: round2: verify pi_j | -20.81 | 20.392 | 1.0000 |
| phase: round2: decode mu/nu | -29.42 | 29.029 | 0.9999 |
| phase: round2: W,(e,phi),U,tr | 4.91 | 0.151 | 0.7769 |
| phase: round2: masks | -0.08 | 0.084 | 0.9998 |
| phase: round2: u_i,S_i | 0.00 | 0.000 | 0.2664 |
| phase: combine: aggregate | 0.28 | -0.001 | 0.6524 |
| phase: combine: bbs verify | 5.99 | -0.004 | 0.0269 |

## single base + short exp: the six logical stages

Mean over 10 repetitions; the total row also shows one standard deviation.

| stage | t=2 | t=3 | t=4 | t=5 | t=6 | t=7 |
|---|---:|---:|---:|---:|---:|---:|
| 1. generating presigning message | 5.18 | 5.19 | 5.21 | 5.21 | 5.20 | 5.21 |
| 2. generating presigning proof | 8.37 | 8.36 | 8.40 | 8.36 | 8.41 | 8.44 |
| 3. verifying each peer's presigning proof | 11.41 | 22.60 | 33.87 | 45.19 | 56.59 | 68.24 |
| 4. NIM decoding with each peer | 19.85 | 39.70 | 59.49 | 79.96 | 99.62 | 120.56 |
| 5. finalizing online signing message | 5.50 | 5.43 | 5.61 | 5.87 | 6.22 | 6.63 |
| 6. signature combination | 6.26 | 6.22 | 6.21 | 6.21 | 6.23 | 6.26 |
| **total** | **56.58 ± 0.81** | **87.51 ± 0.52** | **118.79 ± 0.32** | **150.81 ± 2.30** | **182.27 ± 1.22** | **215.34 ± 4.15** |

## single base + short exp: internal phases

| internal phase | t=2 | t=3 | t=4 | t=5 | t=6 | t=7 |
|---|---:|---:|---:|---:|---:|---:|
| round1: hashvrf | 0.17 | 0.17 | 0.17 | 0.17 | 0.17 | 0.17 |
| round1: W_i | 1.04 | 1.05 | 1.05 | 1.04 | 1.05 | 1.04 |
| round1: encode_B | 3.97 | 3.98 | 3.99 | 3.99 | 3.98 | 4.00 |
| round1: sigma prove | 8.37 | 8.36 | 8.40 | 8.36 | 8.41 | 8.44 |
| round2: verify pi_j | 11.41 | 22.60 | 33.87 | 45.19 | 56.59 | 68.24 |
| round2: decode mu/nu | 19.85 | 39.70 | 59.49 | 79.96 | 99.62 | 120.56 |
| round2: W,(e,phi),U,tr | 5.41 | 5.26 | 5.35 | 5.53 | 5.80 | 6.12 |
| round2: masks | 0.09 | 0.17 | 0.26 | 0.34 | 0.42 | 0.51 |
| round2: u_i,S_i | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| combine: aggregate | 0.28 | 0.28 | 0.27 | 0.27 | 0.28 | 0.28 |
| combine: bbs verify | 5.99 | 5.94 | 5.94 | 5.94 | 5.95 | 5.98 |

### Fitted `a + b t` for single base + short exp (t = number of signers, ms per signer)

| quantity | a (ms) | b (ms / signer) | R^2 |
|---|---:|---:|---:|
| 1. generating presigning message | 5.18 | 0.005 | 0.6660 |
| 2. generating presigning proof | 8.33 | 0.013 | 0.5648 |
| 3. verifying each peer's presigning proof | -11.45 | 11.355 | 1.0000 |
| 4. NIM decoding with each peer | -20.62 | 20.108 | 0.9999 |
| 5. finalizing online signing message | 4.81 | 0.237 | 0.8933 |
| 6. signature combination | 6.23 | 0.000 | 0.0001 |
| total (six stages) | -7.52 | 31.718 | 0.9999 |
| phase: setup | 0.00 | 0.000 | 1.0000 |
| phase: keygen | 0.00 | 0.000 | 1.0000 |
| phase: round1: hashvrf | 0.17 | 0.001 | 0.5855 |
| phase: round1: W_i | 1.04 | 0.000 | 0.1196 |
| phase: round1: encode_B | 3.97 | 0.004 | 0.6325 |
| phase: round1: sigma prove | 8.33 | 0.013 | 0.5648 |
| phase: wire encode/decode | 0.00 | 0.000 | 1.0000 |
| phase: round2: verify pi_j | -11.45 | 11.355 | 1.0000 |
| phase: round2: decode mu/nu | -20.62 | 20.108 | 0.9999 |
| phase: round2: W,(e,phi),U,tr | 4.89 | 0.153 | 0.7769 |
| phase: round2: masks | -0.08 | 0.084 | 0.9999 |
| phase: round2: u_i,S_i | 0.00 | 0.000 | 0.1210 |
| phase: combine: aggregate | 0.28 | -0.000 | 0.0092 |
| phase: combine: bbs verify | 5.96 | 0.000 | 0.0006 |

