# DKLST baseline

`ell = 10` messages, `10` repetitions, `672` OTs per multiplication, `lambda = 128`, `kappa = 256`.

DKLST Section 6 closed forms: `MulCost` = **308576** bits/party, `SignCost` = `(t-1)*618176` + response.

| backend / variant | t | mults / signer | sign ms / signer | sign KiB / signer | sign bits / signer | DKLST `SignCost` | setup ms | setup KiB / party |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| sl-oblivious/correction | 2 | 2 | 12.70 | 74.1 | 607360 | 618176 | 187.9 | 33.0 |
| sl-oblivious/correction | 3 | 4 | 14.90 | 148.3 | 1214720 | 1236352 | 545.0 | 99.0 |
| sl-oblivious/correction | 4 | 6 | 17.67 | 222.4 | 1822080 | 1854528 | 1088.2 | 198.0 |
| sl-oblivious/correction | 5 | 8 | 20.45 | 296.6 | 2429440 | 2472704 | 1815.8 | 330.0 |
| sl-oblivious/correction | 6 | 10 | 22.82 | 370.7 | 3036800 | 3090880 | 2732.3 | 495.0 |
| sl-oblivious/correction | 7 | 12 | 25.24 | 444.8 | 3644160 | 3709056 | 3808.9 | 693.0 |
| libOTe/k=4/correction | 2 | 2 | 10.13 | 74.4 | 609640 | 618176 | 9.4 | 4.1 |
| libOTe/k=4/correction | 3 | 4 | 10.53 | 148.8 | 1219280 | 1236352 | 27.9 | 12.4 |
| libOTe/k=4/correction | 4 | 6 | 11.10 | 223.3 | 1828920 | 1854528 | 56.6 | 24.8 |
| libOTe/k=4/correction | 5 | 8 | 11.59 | 297.7 | 2438560 | 2472704 | 93.6 | 41.4 |
| libOTe/k=4/correction | 6 | 10 | 12.10 | 372.1 | 3048200 | 3090880 | 140.1 | 62.1 |
| libOTe/k=4/correction | 7 | 12 | 12.59 | 446.5 | 3657840 | 3709056 | 199.3 | 86.9 |

The DKLST column is `(t-1)*618176` bits, i.e. the peer-to-peer term of `SignCost`; it excludes the response to the client (`3*kappa + |G2| + |G1|*(ell+2) + t*log2 n` = 6150 bits).
