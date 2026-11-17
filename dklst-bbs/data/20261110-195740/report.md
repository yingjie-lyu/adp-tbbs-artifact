# DKLST baseline

`ell = 10` messages, `5` repetitions, one `pi_Mul` costs 672 OTs.

| backend | t | mults / signer | sign ms / signer | sign KiB / signer | setup ms | setup KiB / party |
|---|---:|---:|---:|---:|---:|---:|
| sl-oblivious | 2 | 2 | 6.49 | 116.0 | 197.5 | 33.0 |
| sl-oblivious | 3 | 4 | 10.43 | 232.1 | 586.0 | 99.0 |
| sl-oblivious | 4 | 6 | 12.70 | 348.1 | 1173.3 | 198.0 |
| sl-oblivious | 5 | 8 | 15.88 | 464.2 | 1934.2 | 330.0 |
| sl-oblivious | 6 | 10 | 18.85 | 580.2 | 2940.6 | 495.0 |
| sl-oblivious | 7 | 12 | 21.30 | 696.3 | 4069.6 | 693.0 |
| libOTe | 2 | 2 | 4.32 | 129.1 | 15.8 | 4.1 |
| libOTe | 3 | 4 | 4.93 | 258.2 | 29.1 | 12.4 |
| libOTe | 4 | 6 | 5.72 | 387.3 | 61.8 | 24.8 |
| libOTe | 5 | 8 | 6.39 | 516.4 | 99.7 | 41.4 |
| libOTe | 6 | 10 | 7.26 | 645.5 | 150.9 | 62.1 |
| libOTe | 7 | 12 | 8.05 | 774.6 | 210.3 | 86.9 |
