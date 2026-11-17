# DKLST baseline

`ell = 10` messages, `5` repetitions, `672` OTs per multiplication, `lambda = 128`, `kappa = 256`.

DKLST Section 6 closed forms: `MulCost` = **308576** bits/party, `SignCost` = `(t-1)*618176` + response.

| backend / variant | t | mults / signer | sign ms / signer | sign KiB / signer | sign bits / signer | DKLST `SignCost` | setup ms | setup KiB / party |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| sl-oblivious/correction | 2 | 2 | 6.77 | 74.1 | 607360 | 618176 | 187.1 | 33.0 |
| sl-oblivious/correction | 3 | 4 | 8.42 | 148.3 | 1214720 | 1236352 | 562.7 | 99.0 |
| sl-oblivious/correction | 4 | 6 | 11.48 | 222.4 | 1822080 | 1854528 | 1103.4 | 198.0 |
| sl-oblivious/correction | 5 | 8 | 14.11 | 296.6 | 2429440 | 2472704 | 1785.4 | 330.0 |
| sl-oblivious/correction | 6 | 10 | 17.09 | 370.7 | 3036800 | 3090880 | 2969.6 | 495.0 |
| sl-oblivious/correction | 7 | 12 | 19.18 | 444.8 | 3644160 | 3709056 | 3984.8 | 693.0 |
| sl-oblivious/masked | 2 | 2 | 5.88 | 116.1 | 951424 | 618176 | 185.2 | 33.0 |
| sl-oblivious/masked | 3 | 4 | 8.54 | 232.3 | 1902848 | 1236352 | 551.8 | 99.0 |
| sl-oblivious/masked | 4 | 6 | 12.24 | 348.4 | 2854272 | 1854528 | 1095.3 | 198.0 |
| sl-oblivious/masked | 5 | 8 | 15.63 | 464.6 | 3805696 | 2472704 | 1990.5 | 330.0 |
| sl-oblivious/masked | 6 | 10 | 17.63 | 580.7 | 4757120 | 3090880 | 2901.9 | 495.0 |
| sl-oblivious/masked | 7 | 12 | 19.91 | 696.8 | 5708544 | 3709056 | 3803.0 | 693.0 |
| libOTe/correction | 2 | 2 | 3.77 | 87.2 | 714305 | 618176 | 9.1 | 4.1 |
| libOTe/correction | 3 | 4 | 4.38 | 174.4 | 1428611 | 1236352 | 26.9 | 12.4 |
| libOTe/correction | 4 | 6 | 5.28 | 261.6 | 2142916 | 1854528 | 53.8 | 24.8 |
| libOTe/correction | 5 | 8 | 5.24 | 348.8 | 2857222 | 2472704 | 92.8 | 41.4 |
| libOTe/correction | 6 | 10 | 6.14 | 436.0 | 3571528 | 3090880 | 136.2 | 62.1 |
| libOTe/correction | 7 | 12 | 6.43 | 523.2 | 4285833 | 3709056 | 195.6 | 86.9 |
| libOTe/masked | 2 | 2 | 3.79 | 129.2 | 1058369 | 618176 | 9.0 | 4.1 |
| libOTe/masked | 3 | 4 | 4.67 | 258.4 | 2116739 | 1236352 | 26.8 | 12.4 |
| libOTe/masked | 4 | 6 | 5.27 | 387.6 | 3175108 | 1854528 | 54.5 | 24.8 |
| libOTe/masked | 5 | 8 | 6.08 | 516.8 | 4233478 | 2472704 | 95.0 | 41.4 |
| libOTe/masked | 6 | 10 | 6.69 | 646.0 | 5291848 | 3090880 | 137.6 | 62.1 |
| libOTe/masked | 7 | 12 | 7.43 | 775.2 | 6350217 | 3709056 | 196.9 | 86.9 |

The DKLST column is `(t-1)*618176` bits, i.e. the peer-to-peer term of `SignCost`; it excludes the response to the client (`3*kappa + |G2| + |G1|*(ell+2) + t*log2 n` = 6150 bits).
