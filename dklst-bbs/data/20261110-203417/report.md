# DKLST baseline

`ell = 10` messages, `5` repetitions, `672` OTs per multiplication, `lambda = 128`, `kappa = 256`.

DKLST Section 6 closed forms: `MulCost` = **308576** bits/party, `SignCost` = `(t-1)*618176` + response.

| backend / variant | t | mults / signer | sign ms / signer | sign KiB / signer | sign bits / signer | DKLST `SignCost` | setup ms | setup KiB / party |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| sl-oblivious/correction | 2 | 2 | 9.43 | 74.1 | 607360 | 618176 | 193.7 | 33.0 |
| sl-oblivious/correction | 3 | 4 | 10.90 | 148.3 | 1214720 | 1236352 | 559.7 | 99.0 |
| sl-oblivious/correction | 4 | 6 | 13.24 | 222.4 | 1822080 | 1854528 | 1152.7 | 198.0 |
| sl-oblivious/correction | 5 | 8 | 16.50 | 296.6 | 2429440 | 2472704 | 1926.1 | 330.0 |
| sl-oblivious/correction | 6 | 10 | 18.07 | 370.7 | 3036800 | 3090880 | 2845.7 | 495.0 |
| sl-oblivious/correction | 7 | 12 | 20.60 | 444.8 | 3644160 | 3709056 | 3978.3 | 693.0 |
| libOTe/k=4/correction | 2 | 2 | 7.44 | 74.4 | 609640 | 618176 | 9.7 | 4.1 |
| libOTe/k=4/correction | 3 | 4 | 6.73 | 148.8 | 1219280 | 1236352 | 28.3 | 12.4 |
| libOTe/k=4/correction | 4 | 6 | 6.53 | 223.3 | 1828920 | 1854528 | 57.7 | 24.8 |
| libOTe/k=4/correction | 5 | 8 | 6.95 | 297.7 | 2438560 | 2472704 | 96.9 | 41.4 |
| libOTe/k=4/correction | 6 | 10 | 7.11 | 372.1 | 3048200 | 3090880 | 146.4 | 62.1 |
| libOTe/k=4/correction | 7 | 12 | 7.57 | 446.5 | 3657840 | 3709056 | 199.9 | 86.9 |

The DKLST column is `(t-1)*618176` bits, i.e. the peer-to-peer term of `SignCost`; it excludes the response to the client (`3*kappa + |G2| + |G1|*(ell+2) + t*log2 n` = 6150 bits).
