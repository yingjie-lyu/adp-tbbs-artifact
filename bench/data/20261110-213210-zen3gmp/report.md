# Signing runtime

ell = 10, 5 repetitions per point, mean over repetitions, milliseconds per signer.
Setup and DKG excluded. `n = t`, quorum = all signers.

## two-base (main): the six logical stages

Mean over 5 repetitions; the total row also shows one standard deviation.

| stage | t=2 | t=3 | t=4 | t=5 | t=6 | t=7 |
|---|---:|---:|---:|---:|---:|---:|
| 1. generating presigning message | 25.82 | 26.11 | 25.60 | 26.84 | 27.42 | 27.78 |
| 2. generating presigning proof | 31.15 | 31.38 | 31.08 | 32.53 | 33.41 | 33.48 |
| 3. verifying each peer's presigning proof | 35.83 | 71.42 | 107.45 | 148.92 | 191.85 | 231.11 |
| 4. NIM decoding with each peer | 31.30 | 62.27 | 93.66 | 131.19 | 167.02 | 201.48 |
| 5. finalizing online signing message | 5.31 | 5.36 | 5.46 | 6.06 | 6.50 | 6.86 |
| 6. signature combination | 6.07 | 6.25 | 6.03 | 6.24 | 6.36 | 6.30 |
| **total** | **135.48 ± 1.47** | **202.79 ± 1.80** | **269.28 ± 5.12** | **351.79 ± 17.00** | **432.55 ± 0.70** | **507.02 ± 2.64** |

## two-base (main): internal phases

| internal phase | t=2 | t=3 | t=4 | t=5 | t=6 | t=7 |
|---|---:|---:|---:|---:|---:|---:|
| round1: hashvrf | 0.16 | 0.17 | 0.17 | 0.19 | 0.18 | 0.18 |
| round1: W_i | 1.02 | 1.03 | 1.01 | 1.05 | 1.08 | 1.06 |
| round1: encode_B | 24.63 | 24.91 | 24.42 | 25.60 | 26.16 | 26.54 |
| round1: sigma prove | 31.15 | 31.38 | 31.08 | 32.53 | 33.41 | 33.48 |
| round2: verify pi_j | 35.83 | 71.42 | 107.45 | 148.92 | 191.85 | 231.11 |
| round2: decode mu/nu | 31.30 | 62.27 | 93.66 | 131.19 | 167.02 | 201.48 |
| round2: W,(e,phi),U,tr | 5.22 | 5.19 | 5.21 | 5.72 | 6.05 | 6.33 |
| round2: masks | 0.09 | 0.17 | 0.25 | 0.34 | 0.45 | 0.53 |
| round2: u_i,S_i | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| combine: aggregate | 0.26 | 0.28 | 0.26 | 0.28 | 0.27 | 0.28 |
| combine: bbs verify | 5.81 | 5.97 | 5.77 | 5.97 | 6.08 | 6.02 |

### Fitted `a + b t` for two-base (main) (t = number of signers, ms per signer)

| quantity | a (ms) | b (ms / signer) | R^2 |
|---|---:|---:|---:|
| 1. generating presigning message | 24.67 | 0.428 | 0.8069 |
| 2. generating presigning proof | 29.71 | 0.547 | 0.8436 |
| 3. verifying each peer's presigning proof | -46.22 | 39.404 | 0.9987 |
| 4. NIM decoding with each peer | -40.14 | 34.362 | 0.9989 |
| 5. finalizing online signing message | 4.41 | 0.337 | 0.9266 |
| 6. signature combination | 5.99 | 0.049 | 0.4965 |
| total (six stages) | -21.59 | 75.127 | 0.9983 |
| phase: setup | 0.00 | 0.000 | 1.0000 |
| phase: keygen | 0.00 | 0.000 | 1.0000 |
| phase: round1: hashvrf | 0.16 | 0.004 | 0.6185 |
| phase: round1: W_i | 0.99 | 0.011 | 0.6271 |
| phase: round1: encode_B | 23.52 | 0.412 | 0.8088 |
| phase: round1: sigma prove | 29.71 | 0.547 | 0.8436 |
| phase: wire encode/decode | 0.00 | 0.000 | 1.0000 |
| phase: round2: verify pi_j | -46.22 | 39.404 | 0.9987 |
| phase: round2: decode mu/nu | -40.14 | 34.362 | 0.9989 |
| phase: round2: W,(e,phi),U,tr | 4.51 | 0.247 | 0.8796 |
| phase: round2: masks | -0.10 | 0.089 | 0.9981 |
| phase: round2: u_i,S_i | -0.00 | 0.000 | 0.6309 |
| phase: combine: aggregate | 0.26 | 0.003 | 0.3986 |
| phase: combine: bbs verify | 5.73 | 0.047 | 0.4919 |

## single base: the six logical stages

Mean over 5 repetitions; the total row also shows one standard deviation.

| stage | t=2 | t=3 | t=4 | t=5 | t=6 | t=7 |
|---|---:|---:|---:|---:|---:|---:|
| 1. generating presigning message | 15.38 | 14.91 | 14.79 | 15.07 | 14.50 | 15.02 |
| 2. generating presigning proof | 18.54 | 17.86 | 18.01 | 18.69 | 17.82 | 18.34 |
| 3. verifying each peer's presigning proof | 21.30 | 41.88 | 63.61 | 86.06 | 105.26 | 128.23 |
| 4. NIM decoding with each peer | 29.96 | 59.91 | 90.48 | 121.05 | 151.81 | 183.64 |
| 5. finalizing online signing message | 5.60 | 5.61 | 5.84 | 6.19 | 6.38 | 6.93 |
| 6. signature combination | 6.33 | 6.32 | 6.36 | 6.27 | 6.66 | 6.32 |
| **total** | **97.09 ± 2.55** | **146.49 ± 0.56** | **199.09 ± 1.58** | **253.32 ± 6.60** | **302.43 ± 14.42** | **358.48 ± 2.99** |

## single base: internal phases

| internal phase | t=2 | t=3 | t=4 | t=5 | t=6 | t=7 |
|---|---:|---:|---:|---:|---:|---:|
| round1: hashvrf | 0.19 | 0.18 | 0.19 | 0.18 | 0.18 | 0.20 |
| round1: W_i | 1.16 | 1.06 | 1.07 | 1.07 | 1.07 | 1.08 |
| round1: encode_B | 14.02 | 13.67 | 13.53 | 13.82 | 13.25 | 13.74 |
| round1: sigma prove | 18.54 | 17.86 | 18.01 | 18.69 | 17.82 | 18.34 |
| round2: verify pi_j | 21.30 | 41.88 | 63.61 | 86.06 | 105.26 | 128.23 |
| round2: decode mu/nu | 29.96 | 59.91 | 90.48 | 121.05 | 151.81 | 183.64 |
| round2: W,(e,phi),U,tr | 5.50 | 5.42 | 5.56 | 5.84 | 5.94 | 6.41 |
| round2: masks | 0.10 | 0.18 | 0.28 | 0.35 | 0.44 | 0.52 |
| round2: u_i,S_i | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| combine: aggregate | 0.27 | 0.27 | 0.28 | 0.27 | 0.29 | 0.27 |
| combine: bbs verify | 6.05 | 6.04 | 6.08 | 6.00 | 6.37 | 6.04 |

### Fitted `a + b t` for single base (t = number of signers, ms per signer)

| quantity | a (ms) | b (ms / signer) | R^2 |
|---|---:|---:|---:|
| 1. generating presigning message | 15.29 | -0.078 | 0.2463 |
| 2. generating presigning proof | 18.26 | -0.012 | 0.0037 |
| 3. verifying each peer's presigning proof | -21.68 | 21.349 | 0.9996 |
| 4. NIM decoding with each peer | -32.03 | 30.705 | 0.9999 |
| 5. finalizing online signing message | 4.89 | 0.266 | 0.9298 |
| 6. signature combination | 6.26 | 0.026 | 0.1139 |
| total (six stages) | -9.00 | 52.256 | 0.9997 |
| phase: setup | 0.00 | 0.000 | 1.0000 |
| phase: keygen | 0.00 | 0.000 | 1.0000 |
| phase: round1: hashvrf | 0.18 | 0.001 | 0.0343 |
| phase: round1: W_i | 1.13 | -0.010 | 0.2581 |
| phase: round1: encode_B | 13.98 | -0.068 | 0.2339 |
| phase: round1: sigma prove | 18.26 | -0.012 | 0.0037 |
| phase: wire encode/decode | 0.00 | 0.000 | 1.0000 |
| phase: round2: verify pi_j | -21.68 | 21.349 | 0.9996 |
| phase: round2: decode mu/nu | -32.03 | 30.705 | 0.9999 |
| phase: round2: W,(e,phi),U,tr | 4.96 | 0.182 | 0.8551 |
| phase: round2: masks | -0.07 | 0.084 | 0.9985 |
| phase: round2: u_i,S_i | 0.00 | 0.000 | 0.0160 |
| phase: combine: aggregate | 0.27 | 0.001 | 0.0729 |
| phase: combine: bbs verify | 5.99 | 0.025 | 0.1142 |

## single base + short exp: the six logical stages

Mean over 5 repetitions; the total row also shows one standard deviation.

| stage | t=2 | t=3 | t=4 | t=5 | t=6 | t=7 |
|---|---:|---:|---:|---:|---:|---:|
| 1. generating presigning message | 5.54 | 5.42 | 5.46 | 5.54 | 5.56 | 5.58 |
| 2. generating presigning proof | 8.66 | 8.85 | 8.86 | 8.97 | 8.83 | 8.90 |
| 3. verifying each peer's presigning proof | 12.05 | 24.06 | 35.75 | 47.57 | 60.24 | 72.52 |
| 4. NIM decoding with each peer | 21.38 | 42.15 | 63.29 | 83.51 | 105.65 | 128.36 |
| 5. finalizing online signing message | 5.71 | 5.62 | 5.94 | 6.08 | 6.47 | 6.94 |
| 6. signature combination | 6.56 | 6.40 | 6.38 | 6.48 | 6.39 | 6.43 |
| **total** | **59.90 ± 0.77** | **92.52 ± 1.59** | **125.66 ± 0.60** | **158.16 ± 0.94** | **193.13 ± 3.33** | **228.74 ± 5.68** |

## single base + short exp: internal phases

| internal phase | t=2 | t=3 | t=4 | t=5 | t=6 | t=7 |
|---|---:|---:|---:|---:|---:|---:|
| round1: hashvrf | 0.18 | 0.18 | 0.18 | 0.18 | 0.18 | 0.18 |
| round1: W_i | 1.07 | 1.09 | 1.08 | 1.09 | 1.10 | 1.08 |
| round1: encode_B | 4.29 | 4.15 | 4.20 | 4.27 | 4.28 | 4.31 |
| round1: sigma prove | 8.66 | 8.85 | 8.86 | 8.97 | 8.83 | 8.90 |
| round2: verify pi_j | 12.05 | 24.06 | 35.75 | 47.57 | 60.24 | 72.52 |
| round2: decode mu/nu | 21.38 | 42.15 | 63.29 | 83.51 | 105.65 | 128.36 |
| round2: W,(e,phi),U,tr | 5.61 | 5.43 | 5.67 | 5.71 | 6.02 | 6.42 |
| round2: masks | 0.10 | 0.19 | 0.27 | 0.36 | 0.45 | 0.52 |
| round2: u_i,S_i | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| combine: aggregate | 0.27 | 0.28 | 0.28 | 0.28 | 0.27 | 0.28 |
| combine: bbs verify | 6.29 | 6.13 | 6.10 | 6.21 | 6.12 | 6.15 |

### Fitted `a + b t` for single base + short exp (t = number of signers, ms per signer)

| quantity | a (ms) | b (ms / signer) | R^2 |
|---|---:|---:|---:|
| 1. generating presigning message | 5.43 | 0.019 | 0.3389 |
| 2. generating presigning proof | 8.68 | 0.036 | 0.4039 |
| 3. verifying each peer's presigning proof | -12.32 | 12.078 | 0.9998 |
| 4. NIM decoding with each peer | -21.80 | 21.302 | 0.9996 |
| 5. finalizing online signing message | 4.99 | 0.252 | 0.8942 |
| 6. signature combination | 6.52 | -0.017 | 0.2025 |
| total (six stages) | -8.50 | 33.671 | 0.9997 |
| phase: setup | 0.00 | 0.000 | 1.0000 |
| phase: keygen | 0.00 | 0.000 | 1.0000 |
| phase: round1: hashvrf | 0.18 | 0.001 | 0.5275 |
| phase: round1: W_i | 1.08 | 0.002 | 0.1618 |
| phase: round1: encode_B | 4.18 | 0.016 | 0.2437 |
| phase: round1: sigma prove | 8.68 | 0.036 | 0.4039 |
| phase: wire encode/decode | 0.00 | 0.000 | 1.0000 |
| phase: round2: verify pi_j | -12.32 | 12.078 | 0.9998 |
| phase: round2: decode mu/nu | -21.80 | 21.302 | 0.9996 |
| phase: round2: W,(e,phi),U,tr | 5.06 | 0.168 | 0.7815 |
| phase: round2: masks | -0.07 | 0.085 | 0.9990 |
| phase: round2: u_i,S_i | 0.00 | 0.000 | 0.0484 |
| phase: combine: aggregate | 0.27 | 0.001 | 0.2247 |
| phase: combine: bbs verify | 6.24 | -0.018 | 0.2131 |

