# DKLST baseline

`ell = 10` messages, `5` repetitions, one `pi_Mul` costs 672 OTs.

| backend | t | mults / signer | sign ms / signer | sign KiB / signer | setup ms | setup KiB / party |
|---|---:|---:|---:|---:|---:|---:|
| sl-oblivious | 2 | 2 | 8.81 | 116.0 | 198.1 | 33.0 |
| sl-oblivious | 3 | 4 | 14.72 | 232.1 | 567.6 | 99.0 |
| sl-oblivious | 4 | 6 | 20.57 | 348.1 | 1138.5 | 198.0 |
| sl-oblivious | 5 | 8 | 26.14 | 464.2 | 1936.0 | 330.0 |
| sl-oblivious | 6 | 10 | 31.86 | 580.2 | 2857.0 | 495.0 |
| sl-oblivious | 7 | 12 | 37.09 | 696.3 | 4030.3 | 693.0 |
| libOTe | 2 | 2 | 4.13 | 129.1 | 14.3 | 4.1 |
| libOTe | 3 | 4 | 4.73 | 258.2 | 27.8 | 12.4 |
| libOTe | 4 | 6 | 5.50 | 387.3 | 56.5 | 24.8 |
| libOTe | 5 | 8 | 6.30 | 516.4 | 94.9 | 41.4 |
| libOTe | 6 | 10 | 6.82 | 645.5 | 142.6 | 62.1 |
| libOTe | 7 | 12 | 7.74 | 774.6 | 205.4 | 86.9 |
