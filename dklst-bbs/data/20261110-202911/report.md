# DKLST baseline

`ell = 10` messages, `5` repetitions, `672` OTs per multiplication, `lambda = 128`, `kappa = 256`.

DKLST Section 6 closed forms: `MulCost` = **308576** bits/party, `SignCost` = `(t-1)*618176` + response.

| backend / variant | t | mults / signer | sign ms / signer | sign KiB / signer | sign bits / signer | DKLST `SignCost` | setup ms | setup KiB / party |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| sl-oblivious/correction | 2 | 2 | 9.31 | 74.1 | 607360 | 618176 | 196.5 | 33.0 |
| sl-oblivious/correction | 3 | 4 | 14.25 | 148.3 | 1214720 | 1236352 | 576.6 | 99.0 |
| sl-oblivious/correction | 4 | 6 | 20.45 | 222.4 | 1822080 | 1854528 | 1174.2 | 198.0 |
| sl-oblivious/correction | 5 | 8 | 26.01 | 296.6 | 2429440 | 2472704 | 1962.3 | 330.0 |
| sl-oblivious/correction | 6 | 10 | 30.83 | 370.7 | 3036800 | 3090880 | 2991.8 | 495.0 |
| sl-oblivious/correction | 7 | 12 | 35.97 | 444.8 | 3644160 | 3709056 | 4030.8 | 693.0 |
| libOTe/k=4/correction | 2 | 2 | 3.97 | 74.4 | 609640 | 618176 | 9.5 | 4.1 |
| libOTe/k=4/correction | 3 | 4 | 4.46 | 148.8 | 1219280 | 1236352 | 28.9 | 12.4 |
| libOTe/k=4/correction | 4 | 6 | 5.23 | 223.3 | 1828920 | 1854528 | 58.8 | 24.8 |
| libOTe/k=4/correction | 5 | 8 | 5.37 | 297.7 | 2438560 | 2472704 | 95.0 | 41.4 |
| libOTe/k=4/correction | 6 | 10 | 6.01 | 372.1 | 3048200 | 3090880 | 148.1 | 62.1 |
| libOTe/k=4/correction | 7 | 12 | 6.74 | 446.5 | 3657840 | 3709056 | 199.9 | 86.9 |

The DKLST column is `(t-1)*618176` bits, i.e. the peer-to-peer term of `SignCost`; it excludes the response to the client (`3*kappa + |G2| + |G1|*(ell+2) + t*log2 n` = 6150 bits).
