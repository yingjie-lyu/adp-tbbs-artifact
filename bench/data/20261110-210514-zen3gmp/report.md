# Signing runtime

ell = 10, 5 repetitions per point, mean over repetitions, milliseconds per signer.
Setup and DKG excluded. `n = t`, quorum = all signers.

## two-base (main): the six logical stages

Mean over 5 repetitions; the total row also shows one standard deviation.

| stage | t=2 | t=3 | t=4 | t=5 | t=6 | t=7 |
|---|---:|---:|---:|---:|---:|---:|
| 1. generating presigning message | 27.71 | 27.89 | 27.74 | 27.75 | 27.76 | 27.30 |
| 2. generating presigning proof | 33.80 | 34.07 | 33.67 | 33.70 | 33.57 | 32.69 |
| 3. verifying each peer's presigning proof | 38.34 | 77.05 | 116.22 | 154.12 | 192.82 | 223.69 |
| 4. NIM decoding with each peer | 33.33 | 66.72 | 101.61 | 134.11 | 168.23 | 194.73 |
| 5. finalizing online signing message | 5.74 | 5.62 | 5.84 | 6.15 | 6.39 | 6.63 |
| 6. signature combination | 6.49 | 6.39 | 6.40 | 6.35 | 6.35 | 6.13 |
| **total** | **145.43 ± 1.17** | **217.75 ± 1.79** | **291.48 ± 1.90** | **362.18 ± 3.57** | **435.13 ± 1.89** | **491.16 ± 31.36** |

## two-base (main): internal phases

| internal phase | t=2 | t=3 | t=4 | t=5 | t=6 | t=7 |
|---|---:|---:|---:|---:|---:|---:|
| round1: hashvrf | 0.18 | 0.18 | 0.18 | 0.18 | 0.18 | 0.17 |
| round1: W_i | 1.07 | 1.07 | 1.07 | 1.09 | 1.06 | 1.05 |
| round1: encode_B | 26.46 | 26.65 | 26.49 | 26.47 | 26.52 | 26.08 |
| round1: sigma prove | 33.80 | 34.07 | 33.67 | 33.70 | 33.57 | 32.69 |
| round2: verify pi_j | 38.34 | 77.05 | 116.22 | 154.12 | 192.82 | 223.69 |
| round2: decode mu/nu | 33.33 | 66.72 | 101.61 | 134.11 | 168.23 | 194.73 |
| round2: W,(e,phi),U,tr | 5.65 | 5.44 | 5.57 | 5.79 | 5.96 | 6.12 |
| round2: masks | 0.09 | 0.18 | 0.27 | 0.35 | 0.43 | 0.51 |
| round2: u_i,S_i | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| combine: aggregate | 0.28 | 0.28 | 0.28 | 0.32 | 0.28 | 0.27 |
| combine: bbs verify | 6.22 | 6.12 | 6.12 | 6.02 | 6.08 | 5.86 |

### Fitted `a + b t` for two-base (main) (t = number of signers, ms per signer)

| quantity | a (ms) | b (ms / signer) | R^2 |
|---|---:|---:|---:|
| 1. generating presigning message | 28.01 | -0.070 | 0.4181 |
| 2. generating presigning proof | 34.49 | -0.201 | 0.6372 |
| 3. verifying each peer's presigning proof | -34.97 | 37.484 | 0.9988 |
| 4. NIM decoding with each peer | -30.63 | 32.686 | 0.9986 |
| 5. finalizing online signing message | 5.15 | 0.202 | 0.9074 |
| 6. signature combination | 6.61 | -0.057 | 0.7671 |
| total (six stages) | 8.66 | 70.044 | 0.9985 |
| phase: setup | 0.00 | 0.000 | 1.0000 |
| phase: keygen | 0.00 | 0.000 | 1.0000 |
| phase: round1: hashvrf | 0.18 | -0.000 | 0.0500 |
| phase: round1: W_i | 1.08 | -0.003 | 0.1339 |
| phase: round1: encode_B | 26.74 | -0.066 | 0.4222 |
| phase: round1: sigma prove | 34.49 | -0.201 | 0.6372 |
| phase: wire encode/decode | 0.00 | 0.000 | 1.0000 |
| phase: round2: verify pi_j | -34.97 | 37.484 | 0.9988 |
| phase: round2: decode mu/nu | -30.63 | 32.686 | 0.9986 |
| phase: round2: W,(e,phi),U,tr | 5.22 | 0.119 | 0.7619 |
| phase: round2: masks | -0.07 | 0.083 | 0.9984 |
| phase: round2: u_i,S_i | 0.00 | -0.000 | 0.0055 |
| phase: combine: aggregate | 0.28 | 0.000 | 0.0008 |
| phase: combine: bbs verify | 6.33 | -0.057 | 0.7799 |

## single base: the six logical stages

Mean over 5 repetitions; the total row also shows one standard deviation.

| stage | t=2 | t=3 | t=4 | t=5 | t=6 | t=7 |
|---|---:|---:|---:|---:|---:|---:|
| 1. generating presigning message | 13.68 | 13.73 | 13.69 | 13.65 | 14.14 | 14.97 |
| 2. generating presigning proof | 16.75 | 16.78 | 16.76 | 16.73 | 17.37 | 18.43 |
| 3. verifying each peer's presigning proof | 19.50 | 39.09 | 58.24 | 77.79 | 101.34 | 126.67 |
| 4. NIM decoding with each peer | 27.86 | 55.95 | 83.26 | 111.16 | 146.68 | 181.86 |
| 5. finalizing online signing message | 5.29 | 5.29 | 5.41 | 5.69 | 6.21 | 6.75 |
| 6. signature combination | 6.01 | 6.00 | 6.02 | 6.01 | 6.18 | 6.38 |
| **total** | **89.09 ± 0.30** | **136.85 ± 0.88** | **183.39 ± 0.31** | **231.02 ± 0.34** | **291.92 ± 12.48** | **355.05 ± 6.71** |

## single base: internal phases

| internal phase | t=2 | t=3 | t=4 | t=5 | t=6 | t=7 |
|---|---:|---:|---:|---:|---:|---:|
| round1: hashvrf | 0.16 | 0.16 | 0.16 | 0.16 | 0.17 | 0.18 |
| round1: W_i | 1.01 | 1.01 | 1.01 | 1.01 | 1.04 | 1.08 |
| round1: encode_B | 12.51 | 12.56 | 12.51 | 12.48 | 12.92 | 13.71 |
| round1: sigma prove | 16.75 | 16.78 | 16.76 | 16.73 | 17.37 | 18.43 |
| round2: verify pi_j | 19.50 | 39.09 | 58.24 | 77.79 | 101.34 | 126.67 |
| round2: decode mu/nu | 27.86 | 55.95 | 83.26 | 111.16 | 146.68 | 181.86 |
| round2: W,(e,phi),U,tr | 5.21 | 5.12 | 5.16 | 5.36 | 5.78 | 6.22 |
| round2: masks | 0.08 | 0.17 | 0.25 | 0.33 | 0.43 | 0.52 |
| round2: u_i,S_i | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| combine: aggregate | 0.26 | 0.26 | 0.26 | 0.26 | 0.27 | 0.28 |
| combine: bbs verify | 5.75 | 5.74 | 5.76 | 5.74 | 5.91 | 6.11 |

### Fitted `a + b t` for single base (t = number of signers, ms per signer)

| quantity | a (ms) | b (ms / signer) | R^2 |
|---|---:|---:|---:|
| 1. generating presigning message | 12.99 | 0.218 | 0.6155 |
| 2. generating presigning proof | 15.83 | 0.289 | 0.6354 |
| 3. verifying each peer's presigning proof | -24.98 | 21.203 | 0.9964 |
| 4. NIM decoding with each peer | -36.46 | 30.574 | 0.9961 |
| 5. finalizing online signing message | 4.45 | 0.294 | 0.8715 |
| 6. signature combination | 5.80 | 0.068 | 0.6844 |
| total (six stages) | -22.36 | 52.647 | 0.9950 |
| phase: setup | 0.00 | 0.000 | 1.0000 |
| phase: keygen | 0.00 | 0.000 | 1.0000 |
| phase: round1: hashvrf | 0.15 | 0.003 | 0.6050 |
| phase: round1: W_i | 0.97 | 0.013 | 0.6952 |
| phase: round1: encode_B | 11.87 | 0.202 | 0.6103 |
| phase: round1: sigma prove | 15.83 | 0.289 | 0.6354 |
| phase: wire encode/decode | 0.00 | 0.000 | 1.0000 |
| phase: round2: verify pi_j | -24.98 | 21.203 | 0.9964 |
| phase: round2: decode mu/nu | -36.46 | 30.574 | 0.9961 |
| phase: round2: W,(e,phi),U,tr | 4.55 | 0.207 | 0.7793 |
| phase: round2: masks | -0.10 | 0.087 | 0.9989 |
| phase: round2: u_i,S_i | 0.00 | 0.000 | 0.6077 |
| phase: combine: aggregate | 0.25 | 0.003 | 0.8170 |
| phase: combine: bbs verify | 5.54 | 0.065 | 0.6786 |

## single base + short exp: the six logical stages

Mean over 5 repetitions; the total row also shows one standard deviation.

| stage | t=2 | t=3 | t=4 | t=5 | t=6 | t=7 |
|---|---:|---:|---:|---:|---:|---:|
| 1. generating presigning message | 5.49 | 5.76 | 5.49 | 5.45 | 5.58 | 5.28 |
| 2. generating presigning proof | 9.39 | 9.18 | 8.97 | 8.87 | 9.07 | 8.48 |
| 3. verifying each peer's presigning proof | 11.69 | 24.35 | 36.87 | 47.81 | 60.60 | 69.27 |
| 4. NIM decoding with each peer | 20.53 | 42.65 | 64.76 | 84.45 | 107.01 | 122.37 |
| 5. finalizing online signing message | 5.57 | 5.72 | 5.99 | 6.15 | 6.50 | 6.74 |
| 6. signature combination | 6.35 | 6.36 | 6.47 | 6.37 | 6.77 | 6.22 |
| **total** | **59.03 ± 0.61** | **94.01 ± 2.04** | **128.55 ± 3.27** | **159.10 ± 2.89** | **195.52 ± 5.68** | **218.36 ± 2.98** |

## single base + short exp: internal phases

| internal phase | t=2 | t=3 | t=4 | t=5 | t=6 | t=7 |
|---|---:|---:|---:|---:|---:|---:|
| round1: hashvrf | 0.18 | 0.20 | 0.19 | 0.17 | 0.18 | 0.17 |
| round1: W_i | 1.07 | 1.11 | 1.07 | 1.08 | 1.08 | 1.06 |
| round1: encode_B | 4.24 | 4.45 | 4.23 | 4.20 | 4.31 | 4.05 |
| round1: sigma prove | 9.39 | 9.18 | 8.97 | 8.87 | 9.07 | 8.48 |
| round2: verify pi_j | 11.69 | 24.35 | 36.87 | 47.81 | 60.60 | 69.27 |
| round2: decode mu/nu | 20.53 | 42.65 | 64.76 | 84.45 | 107.01 | 122.37 |
| round2: W,(e,phi),U,tr | 5.48 | 5.53 | 5.72 | 5.78 | 6.06 | 6.22 |
| round2: masks | 0.10 | 0.18 | 0.27 | 0.37 | 0.44 | 0.52 |
| round2: u_i,S_i | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| combine: aggregate | 0.29 | 0.27 | 0.30 | 0.28 | 0.28 | 0.27 |
| combine: bbs verify | 6.06 | 6.08 | 6.17 | 6.08 | 6.48 | 5.95 |

### Fitted `a + b t` for single base + short exp (t = number of signers, ms per signer)

| quantity | a (ms) | b (ms / signer) | R^2 |
|---|---:|---:|---:|
| 1. generating presigning message | 5.71 | -0.046 | 0.3084 |
| 2. generating presigning proof | 9.64 | -0.143 | 0.7406 |
| 3. verifying each peer's presigning proof | -10.64 | 11.646 | 0.9974 |
| 4. NIM decoding with each peer | -19.20 | 20.628 | 0.9975 |
| 5. finalizing online signing message | 5.04 | 0.239 | 0.9875 |
| 6. signature combination | 6.37 | 0.013 | 0.0159 |
| total (six stages) | -3.09 | 32.337 | 0.9969 |
| phase: setup | 0.00 | 0.000 | 1.0000 |
| phase: keygen | 0.00 | 0.000 | 1.0000 |
| phase: round1: hashvrf | 0.19 | -0.002 | 0.1670 |
| phase: round1: W_i | 1.09 | -0.003 | 0.1137 |
| phase: round1: encode_B | 4.43 | -0.041 | 0.3396 |
| phase: round1: sigma prove | 9.64 | -0.143 | 0.7406 |
| phase: wire encode/decode | 0.00 | 0.000 | 1.0000 |
| phase: round2: verify pi_j | -10.64 | 11.646 | 0.9974 |
| phase: round2: decode mu/nu | -19.20 | 20.628 | 0.9975 |
| phase: round2: W,(e,phi),U,tr | 5.11 | 0.154 | 0.9630 |
| phase: round2: masks | -0.07 | 0.085 | 0.9982 |
| phase: round2: u_i,S_i | 0.00 | 0.000 | 0.2703 |
| phase: combine: aggregate | 0.29 | -0.002 | 0.1181 |
| phase: combine: bbs verify | 6.07 | 0.015 | 0.0225 |

