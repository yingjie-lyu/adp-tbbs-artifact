# Signing runtime

ell = 10, 10 repetitions per point, mean over repetitions, milliseconds per signer.
Setup and DKG excluded. `n = t`, quorum = all signers.

## Other schemes (coarse)

Stages are read from each crate's own meter; only the dominant ones are shown.

| scheme | t | stages (ms per signer) | total |
|---|---:|---|---:|
| tx25-bbs (2 offline + 1 online) | 2 | offline output 150.1; offline r1 55.6; offline r2 189.8; online 3.2; output 9.9 | 408.5 |
| tx25-bbs (2 offline + 1 online) | 3 | offline output 251.1; offline r1 55.7; offline r2 265.6; online 3.2; output 10.2 | 585.7 |
| tx25-bbs (2 offline + 1 online) | 4 | offline output 365.0; offline r1 55.2; offline r2 338.1; online 3.2; output 10.4 | 771.9 |
| tx25-bbs (2 offline + 1 online) | 5 | offline output 499.8; offline r1 55.2; offline r2 413.3; online 3.2; output 10.8 | 982.3 |
| wmc24-bbs (4 rounds) | 2 | sign output 77.0; sign r1 109.4; sign r2 225.7; sign r3 195.4; sign r4 81.2 | 688.8 |
| wmc24-bbs (4 rounds) | 3 | sign output 116.4; sign r1 110.5; sign r2 296.0; sign r3 271.6; sign r4 99.0 | 893.5 |
| wmc24-bbs (4 rounds) | 4 | sign output 156.7; sign r1 110.9; sign r2 367.0; sign r3 348.6; sign r4 117.5 | 1100.8 |
| wmc24-bbs (4 rounds) | 5 | sign output 196.5; sign r1 110.2; sign r2 434.1; sign r3 425.9; sign r4 134.8 | 1301.5 |

