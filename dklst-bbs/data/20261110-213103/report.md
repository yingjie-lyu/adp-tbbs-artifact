# DKLST baseline

`ell = 10` messages, `5` repetitions, `672` OTs per multiplication, `lambda = 128`, `kappa = 256`.

DKLST Section 6 closed forms: `MulCost` = **308576** bits/party, `SignCost` = `(t-1)*618176` + response.

| backend / variant | t | mults / signer | sign ms / signer | sign KiB / signer | sign bits / signer | DKLST `SignCost` | setup ms | setup KiB / party |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| sl-oblivious/correction | 2 | 2 | 17.13 | 74.1 | 607360 | 618176 | 180.0 | 33.0 |
| sl-oblivious/correction | 3 | 4 | 23.62 | 148.3 | 1214720 | 1236352 | 532.9 | 99.0 |
| sl-oblivious/correction | 4 | 6 | 31.06 | 222.4 | 1822080 | 1854528 | 1069.8 | 198.0 |
| sl-oblivious/correction | 5 | 8 | 38.28 | 296.6 | 2429440 | 2472704 | 1786.1 | 330.0 |
| sl-oblivious/correction | 6 | 10 | 45.84 | 370.7 | 3036800 | 3090880 | 2681.1 | 495.0 |
| sl-oblivious/correction | 7 | 12 | 52.46 | 444.8 | 3644160 | 3709056 | 3722.5 | 693.0 |

The DKLST column is `(t-1)*618176` bits, i.e. the peer-to-peer term of `SignCost`; it excludes the response to the client (`3*kappa + |G2| + |G1|*(ell+2) + t*log2 n` = 6150 bits).
