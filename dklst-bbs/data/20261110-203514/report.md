# DKLST baseline

`ell = 10` messages, `5` repetitions, `672` OTs per multiplication, `lambda = 128`, `kappa = 256`.

DKLST Section 6 closed forms: `MulCost` = **308576** bits/party, `SignCost` = `(t-1)*618176` + response.

| backend / variant | t | mults / signer | sign ms / signer | sign KiB / signer | sign bits / signer | DKLST `SignCost` | setup ms | setup KiB / party |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| sl-oblivious/correction | 2 | 2 | 12.20 | 74.1 | 607360 | 618176 | 195.6 | 33.0 |
| sl-oblivious/correction | 3 | 4 | 16.38 | 148.3 | 1214720 | 1236352 | 570.8 | 99.0 |
| sl-oblivious/correction | 4 | 6 | 21.21 | 222.4 | 1822080 | 1854528 | 1178.8 | 198.0 |
| sl-oblivious/correction | 5 | 8 | 26.92 | 296.6 | 2429440 | 2472704 | 1943.3 | 330.0 |
| sl-oblivious/correction | 6 | 10 | 32.24 | 370.7 | 3036800 | 3090880 | 2926.1 | 495.0 |
| sl-oblivious/correction | 7 | 12 | 36.62 | 444.8 | 3644160 | 3709056 | 4034.1 | 693.0 |

The DKLST column is `(t-1)*618176` bits, i.e. the peer-to-peer term of `SignCost`; it excludes the response to the client (`3*kappa + |G2| + |G1|*(ell+2) + t*log2 n` = 6150 bits).
