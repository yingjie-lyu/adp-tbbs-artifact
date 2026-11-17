# Signing runtime

ell = 10, 10 repetitions per point, mean over repetitions, milliseconds per signer.
Setup and DKG excluded. `n = t`, quorum = all signers.

## Other schemes (coarse)

Stages are read from each crate's own meter; only the dominant ones are shown.

| scheme | t | stages (ms per signer) | total |
|---|---:|---|---:|
| clkem-tbbs (3 rounds, CL-KEM) | 2 | sign r1: commit, phi^gamma 49.2; sign r2: open (e_i, s_i) 19.9; sign r3: R_i, pd_i 17.5; sign: BBS+ verify 6.0; sign: combine 6.3 | 98.9 |
| clkem-tbbs (3 rounds, CL-KEM) | 3 | sign r1: commit, phi^gamma 49.2; sign r2: open (e_i, s_i) 40.1; sign r3: R_i, pd_i 17.7; sign: BBS+ verify 6.0; sign: combine 6.4 | 119.3 |
| clkem-tbbs (3 rounds, CL-KEM) | 4 | sign r1: commit, phi^gamma 49.3; sign r2: open (e_i, s_i) 60.2; sign r3: R_i, pd_i 17.9; sign: BBS+ verify 6.0; sign: combine 6.4 | 139.8 |
| clkem-tbbs (3 rounds, CL-KEM) | 5 | sign r1: commit, phi^gamma 49.2; sign r2: open (e_i, s_i) 80.8; sign r3: R_i, pd_i 18.1; sign: BBS+ verify 6.0; sign: combine 6.4 | 160.4 |
| clkem-tbbs (3 rounds, CL-KEM) | 6 | sign r1: commit, phi^gamma 49.2; sign r2: open (e_i, s_i) 100.3; sign r3: R_i, pd_i 18.2; sign: BBS+ verify 6.0; sign: combine 6.4 | 180.0 |
| clkem-tbbs (3 rounds, CL-KEM) | 7 | sign r1: commit, phi^gamma 49.1; sign r2: open (e_i, s_i) 120.3; sign r3: R_i, pd_i 18.5; sign: BBS+ verify 6.0; sign: combine 6.4 | 200.3 |
| robot-bbs (2 rounds) | 2 | sign output 83.6; sign r1 80.8; sign r2 166.6 | 331.0 |
| robot-bbs (2 rounds) | 3 | sign output 122.8; sign r1 81.2; sign r2 226.3 | 430.2 |
| robot-bbs (2 rounds) | 4 | sign output 162.3; sign r1 81.2; sign r2 283.4 | 526.8 |
| robot-bbs (2 rounds) | 5 | sign output 201.8; sign r1 80.8; sign r2 338.6 | 621.2 |
| robot-bbs (2 rounds) | 6 | sign output 243.0; sign r1 81.2; sign r2 397.1 | 721.3 |
| robot-bbs (2 rounds) | 7 | sign output 283.0; sign r1 80.9; sign r2 454.0 | 817.9 |
| twopass-bbs (2 passes, 2 parties) | 2 | sign output (verify, decrypt) 35.5; sign pass 1 (beta1) 0.0; sign pass 2 (VRF, C, D, R_CL-Lin) 38.0 | 73.5 |

