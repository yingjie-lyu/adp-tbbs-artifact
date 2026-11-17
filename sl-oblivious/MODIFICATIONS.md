# Modifications (local, not redistributed)

Vendored copy of `sl-oblivious 1.0.0-beta` (Silence Laboratories Non-Commercial Licence),
patched so that the SoftSpokenOT batch matches the DKLs18 `pi_Mul` of the DKLST baseline:

| constant | upstream | here | why |
|---|---|---|---|
| `consts::L` | `KAPPA + 2 * LAMBDA_S` (=512) | `3 * KAPPA` (=768) | pi_Mul needs `2*kappa + 2*s = 672` OTs, so one batch must hold at least 672; 768 is a multiple of `S = 128` |
| `consts::L_BATCH` | 2 | 1 | `OT_WIDTH = L_BATCH + RHO = 2`, i.e. 2*kappa = 512 bits per OT, matching the `F_COTe` payload (alpha, alpha_hat) |

`SOFT_SPOKEN_K` (4), `RHO` (1), `S` (128) and everything else are untouched.
Only `src/params.rs` changed (two lines). 
