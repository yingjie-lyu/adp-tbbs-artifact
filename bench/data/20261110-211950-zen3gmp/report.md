# Signing runtime

ell = 10, 5 repetitions per point, mean over repetitions, milliseconds per signer.
Setup and DKG excluded. `n = t`, quorum = all signers.

## Other schemes (coarse)

Stages are read from each crate's own meter; only the dominant ones are shown.

| scheme | t | stages (ms per signer) | total |
|---|---:|---|---:|
| clkem-tbbs (3 rounds, CL-KEM) | 2 | sign r1: commit, phi^gamma 51.4; sign r2: open (e_i, s_i) 21.4; sign r3: R_i, pd_i 18.6; sign: BBS+ verify 6.3; sign: combine 6.6 | 104.3 |
| clkem-tbbs (3 rounds, CL-KEM) | 3 | sign r1: commit, phi^gamma 51.4; sign r2: open (e_i, s_i) 42.1; sign r3: R_i, pd_i 18.4; sign: BBS+ verify 6.2; sign: combine 6.6 | 124.6 |
| clkem-tbbs (3 rounds, CL-KEM) | 4 | sign r1: commit, phi^gamma 51.0; sign r2: open (e_i, s_i) 62.5; sign r3: R_i, pd_i 18.4; sign: BBS+ verify 6.2; sign: combine 6.6 | 144.7 |
| clkem-tbbs (3 rounds, CL-KEM) | 5 | sign r1: commit, phi^gamma 51.0; sign r2: open (e_i, s_i) 83.9; sign r3: R_i, pd_i 18.6; sign: BBS+ verify 6.1; sign: combine 6.5 | 166.1 |
| clkem-tbbs (3 rounds, CL-KEM) | 6 | sign r1: commit, phi^gamma 50.6; sign r2: open (e_i, s_i) 104.2; sign r3: R_i, pd_i 19.0; sign: BBS+ verify 6.2; sign: combine 6.6 | 186.5 |
| clkem-tbbs (3 rounds, CL-KEM) | 7 | sign r1: commit, phi^gamma 51.2; sign r2: open (e_i, s_i) 125.3; sign r3: R_i, pd_i 19.2; sign: BBS+ verify 6.2; sign: combine 6.6 | 208.4 |
| robot-bbs (2 rounds) | 2 | sign output 86.4; sign r1 86.5; sign r2 174.0 | 346.9 |
| robot-bbs (2 rounds) | 3 | sign output 127.8; sign r1 84.7; sign r2 234.6 | 447.1 |
| robot-bbs (2 rounds) | 4 | sign output 170.2; sign r1 84.4; sign r2 294.6 | 549.2 |
| robot-bbs (2 rounds) | 5 | sign output 209.1; sign r1 84.2; sign r2 353.7 | 647.0 |
| robot-bbs (2 rounds) | 6 | sign output 248.3; sign r1 82.8; sign r2 411.8 | 742.9 |
| robot-bbs (2 rounds) | 7 | sign output 285.3; sign r1 81.3; sign r2 456.1 | 822.6 |
| twopass-bbs (2 passes, 2 parties) | 2 | sign output (verify, decrypt) 37.3; sign pass 1 (beta1) 0.0; sign pass 2 (VRF, C, D, R_CL-Lin) 39.2 | 76.4 |
| tx25-bbs (2 offline + 1 online) | 2 | offline output 142.3; offline r1 52.7; offline r2 179.2; online 3.1; output 9.4 | 386.6 |
| tx25-bbs (2 offline + 1 online) | 3 | offline output 236.3; offline r1 52.6; offline r2 251.7; online 3.1; output 9.7 | 553.4 |
| tx25-bbs (2 offline + 1 online) | 4 | offline output 352.5; offline r1 52.9; offline r2 322.2; online 3.1; output 10.2 | 740.9 |
| tx25-bbs (2 offline + 1 online) | 5 | offline output 497.8; offline r1 55.8; offline r2 415.8; online 3.2; output 10.7 | 983.2 |
| tx25-bbs (2 offline + 1 online) | 6 | offline output 648.5; offline r1 54.6; offline r2 482.4; online 3.1; output 11.0 | 1199.6 |
| tx25-bbs (2 offline + 1 online) | 7 | offline output 843.6; offline r1 56.9; offline r2 577.6; online 3.2; output 11.5 | 1492.8 |
| wmc24-bbs (4 rounds) | 2 | sign output 77.6; sign r1 109.5; sign r2 227.2; sign r3 197.0; sign r4 81.6 | 692.9 |
| wmc24-bbs (4 rounds) | 3 | sign output 118.6; sign r1 110.1; sign r2 296.2; sign r3 272.5; sign r4 99.5 | 896.8 |
| wmc24-bbs (4 rounds) | 4 | sign output 159.8; sign r1 111.8; sign r2 384.9; sign r3 362.7; sign r4 121.6 | 1140.8 |
| wmc24-bbs (4 rounds) | 5 | sign output 204.0; sign r1 111.1; sign r2 440.7; sign r3 435.4; sign r4 137.2 | 1328.4 |
| wmc24-bbs (4 rounds) | 6 | sign output 236.2; sign r1 109.1; sign r2 498.8; sign r3 497.5; sign r4 151.8 | 1493.3 |
| wmc24-bbs (4 rounds) | 7 | sign output 264.7; sign r1 104.8; sign r2 544.1; sign r3 555.6; sign r4 161.6 | 1630.7 |

