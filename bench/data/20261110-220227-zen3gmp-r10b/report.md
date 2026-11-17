# Signing runtime

ell = 10, 10 repetitions per point, mean over repetitions, milliseconds per signer.
Setup and DKG excluded. `n = t`, quorum = all signers.

## Other schemes (coarse)

Stages are read from each crate's own meter; only the dominant ones are shown.

| scheme | t | stages (ms per signer) | total |
|---|---:|---|---:|
| tx25-bbs (2 offline + 1 online) | 6 | offline output 655.4; offline r1 55.5; offline r2 490.3; online 3.2; output 11.1 | 1215.5 |
| tx25-bbs (2 offline + 1 online) | 7 | offline output 833.4; offline r1 55.7; offline r2 570.6; online 3.2; output 11.5 | 1474.3 |
| wmc24-bbs (4 rounds) | 6 | sign output 238.0; sign r1 110.9; sign r2 506.2; sign r3 505.8; sign r4 153.7 | 1514.8 |
| wmc24-bbs (4 rounds) | 7 | sign output 287.3; sign r1 113.5; sign r2 593.5; sign r3 598.8; sign r4 174.3 | 1767.4 |

