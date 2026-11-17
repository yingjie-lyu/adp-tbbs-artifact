# DKLST baseline

`ell = 10` messages, `5` repetitions, `672` OTs per multiplication, `lambda = 128`, `kappa = 256`.

DKLST Section 6 closed forms: `MulCost` = **308576** bits/party, `SignCost` = `(t-1)*618176` + response.

| backend / variant | t | mults / signer | sign ms / signer | sign KiB / signer | sign bits / signer | DKLST `SignCost` | setup ms | setup KiB / party |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| sl-oblivious/correction | 2 | 2 | 6.37 | 74.1 | 607360 | 618176 | 190.0 | 33.0 |
| sl-oblivious/correction | 3 | 4 | 8.31 | 148.3 | 1214720 | 1236352 | 545.6 | 99.0 |
| sl-oblivious/correction | 4 | 6 | 11.22 | 222.4 | 1822080 | 1854528 | 1089.7 | 198.0 |
| sl-oblivious/correction | 5 | 8 | 13.63 | 296.6 | 2429440 | 2472704 | 1802.6 | 330.0 |
| sl-oblivious/correction | 6 | 10 | 15.97 | 370.7 | 3036800 | 3090880 | 2729.5 | 495.0 |
| sl-oblivious/correction | 7 | 12 | 18.23 | 444.8 | 3644160 | 3709056 | 3714.0 | 693.0 |
| libOTe/k=2/correction | 2 | 2 | 3.64 | 85.6 | 701032 | 618176 | 8.9 | 4.1 |
| libOTe/k=2/correction | 3 | 4 | 4.06 | 171.2 | 1402064 | 1236352 | 28.8 | 12.4 |
| libOTe/k=2/correction | 4 | 6 | 4.61 | 256.7 | 2103096 | 1854528 | 53.6 | 24.8 |
| libOTe/k=2/correction | 5 | 8 | 5.07 | 342.3 | 2804128 | 2472704 | 89.9 | 41.4 |
| libOTe/k=2/correction | 6 | 10 | 5.65 | 427.9 | 3505160 | 3090880 | 135.1 | 62.1 |
| libOTe/k=2/correction | 7 | 12 | 6.15 | 513.5 | 4206192 | 3709056 | 188.9 | 86.9 |
| libOTe/k=4/correction | 2 | 2 | 3.58 | 74.4 | 609640 | 618176 | 8.9 | 4.1 |
| libOTe/k=4/correction | 3 | 4 | 4.11 | 148.8 | 1219280 | 1236352 | 26.6 | 12.4 |
| libOTe/k=4/correction | 4 | 6 | 4.59 | 223.3 | 1828920 | 1854528 | 54.0 | 24.8 |
| libOTe/k=4/correction | 5 | 8 | 5.14 | 297.7 | 2438560 | 2472704 | 90.4 | 41.4 |
| libOTe/k=4/correction | 6 | 10 | 5.60 | 372.1 | 3048200 | 3090880 | 133.3 | 62.1 |
| libOTe/k=4/correction | 7 | 12 | 6.23 | 446.5 | 3657840 | 3709056 | 187.9 | 86.9 |
| libOTe/k=8/correction | 2 | 2 | 3.79 | 68.8 | 563944 | 618176 | 8.9 | 4.1 |
| libOTe/k=8/correction | 3 | 4 | 4.61 | 137.7 | 1127888 | 1236352 | 26.9 | 12.4 |
| libOTe/k=8/correction | 4 | 6 | 5.31 | 206.5 | 1691832 | 1854528 | 53.1 | 24.8 |
| libOTe/k=8/correction | 5 | 8 | 5.99 | 275.4 | 2255776 | 2472704 | 88.7 | 41.4 |
| libOTe/k=8/correction | 6 | 10 | 6.57 | 344.2 | 2819720 | 3090880 | 135.1 | 62.1 |
| libOTe/k=8/correction | 7 | 12 | 7.36 | 413.0 | 3383664 | 3709056 | 192.3 | 86.9 |

The DKLST column is `(t-1)*618176` bits, i.e. the peer-to-peer term of `SignCost`; it excludes the response to the client (`3*kappa + |G2| + |G1|*(ell+2) + t*log2 n` = 6150 bits).
