#pragma once
#include "bicycl.h"
namespace BICYCL {
inline RandGen clone_rng(const RandGen& r) { return r.copy(); }
inline void seed_rng(RandGen& r, const Mpz& s) { r.set_seed(s); }
inline void random_mpz(RandGen& r, Mpz& out, const Mpz& b) { out = r.random_mpz(b); }
inline void compose(const ClassGroup& g, QFI& out, const QFI& a, const QFI& b) { g.nucomp(out,a,b); }
inline void exponentiate(const ClassGroup& g, QFI& out, const QFI& a, const Mpz& n) { g.nupow(out,a,n); }
inline QFI public_key_element(const CL_HSMqk::PublicKey& p) { return p.elt(); }
inline QFI public_key_power(const CL_HSMqk& c, const CL_HSMqk::PublicKey& p, const Mpz& n) { QFI r; p.exponentiation(c,r,n); return r; }
inline CL_HSMqk::CipherText ciphertext_new(const QFI& a,const QFI& b) { return CL_HSMqk::CipherText(a,b); }
inline QFI ciphertext_get_first(const CL_HSMqk::CipherText& c) { return c.c1(); }
inline QFI ciphertext_get_second(const CL_HSMqk::CipherText& c) { return c.c2(); }
inline bool ciphertext_equal(const CL_HSMqk::CipherText& a,const CL_HSMqk::CipherText& b) { return a.is_equal(b); }

/* DGS compressed representation of a reduced form: eprint 2020/196, algorithms 2 and 3.
 * The four integers plus a sign bit take about 3/4 log2|Delta| bits instead of log2|Delta|. */
inline int qfi_compressed(const QFI& f, Mpz& ap, Mpz& g, Mpz& tp, Mpz& b0)
{
    QFICompressedRepresentation c = f.compressed_repr();
    ap = c.ap;
    g = c.g;
    tp = c.tp;
    b0 = c.b0;
    return c.is_neg ? 1 : 0;
}

inline void qfi_from_compressed(QFI& out, const Mpz& ap, const Mpz& g, const Mpz& tp,
                                const Mpz& b0, int is_neg, const Mpz& disc)
{
    QFICompressedRepresentation c (ap, g, tp, b0, is_neg != 0);
    out = QFI (c, disc);
}

inline size_t qfi_compressed_nbits(const QFI& f) { return f.compressed_repr().nbits(); }
}
