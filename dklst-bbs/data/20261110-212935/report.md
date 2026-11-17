# DKLST baseline

`ell = 10` messages, `5` repetitions, `672` OTs per multiplication, `lambda = 128`, `kappa = 256`.

DKLST Section 6 closed forms: `MulCost` = **308576** bits/party, `SignCost` = `(t-1)*618176` + response.

| backend / variant | t | mults / signer | sign ms / signer | sign KiB / signer | sign bits / signer | DKLST `SignCost` | setup ms | setup KiB / party |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| sl-oblivious/correction | 2 | 2 | 13.43 | 74.1 | 607360 | 618176 | 202.9 | 33.0 |
| sl-oblivious/correction | 3 | 4 | 15.71 | 148.3 | 1214720 | 1236352 | 572.0 | 99.0 |
| sl-oblivious/correction | 4 | 6 | 18.48 | 222.4 | 1822080 | 1854528 | 1134.1 | 198.0 |
| sl-oblivious/correction | 5 | 8 | 21.91 | 296.6 | 2429440 | 2472704 | 1917.4 | 330.0 |
| sl-oblivious/correction | 6 | 10 | 23.84 | 370.7 | 3036800 | 3090880 | 2880.8 | 495.0 |
| sl-oblivious/correction | 7 | 12 | 27.78 | 444.8 | 3644160 | 3709056 | 3960.0 | 693.0 |
| libOTe/k=4/correction | 2 | 2 | 10.66 | 74.4 | 609640 | 618176 | 9.9 | 4.1 |
| libOTe/k=4/correction | 3 | 4 | 11.24 | 148.8 | 1219280 | 1236352 | 29.5 | 12.4 |
| libOTe/k=4/correction | 4 | 6 | 11.38 | 223.3 | 1828920 | 1854528 | 59.6 | 24.8 |
| libOTe/k=4/correction | 5 | 8 | 12.38 | 297.7 | 2438560 | 2472704 | 99.9 | 41.4 |
| libOTe/k=4/correction | 6 | 10 | 13.04 | 372.1 | 3048200 | 3090880 | 154.4 | 62.1 |
| libOTe/k=4/correction | 7 | 12 | 13.44 | 446.5 | 3657840 | 3709056 | 211.0 | 86.9 |

The DKLST column is `(t-1)*618176` bits, i.e. the peer-to-peer term of `SignCost`; it excludes the response to the client (`3*kappa + |G2| + |G1|*(ell+2) + t*log2 n` = 6150 bits).
