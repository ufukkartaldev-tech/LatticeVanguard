#ifndef DILITHIUM_H
#define DILITHIUM_H

#include <stdint.h>
#include <stddef.h>
#include "dilithium_params.h"

#include "workspace.h"

namespace PQC {
namespace DSA {

using Memory::CryptoWorkspace;

typedef struct {
    int32_t coeffs[256];
} poly;

typedef struct {
    poly vec[DILITHIUM2_K];
} polyveck;

typedef struct {
    poly vec[DILITHIUM2_L];
} polyvecl;

// Compact (Packed) Types - RAM Armor
typedef struct {
    uint8_t bits[768]; // 256 * 24 bit (3 bytes per coeff) = 768 bytes
} packed_poly;

typedef struct {
    packed_poly vec[DILITHIUM2_K];
} packed_polyveck;

typedef struct {
    packed_poly vec[DILITHIUM2_L];
} packed_polyvecl;

class Dilithium2 {
public:
    // API
    static int keypair(CryptoWorkspace* ws, uint8_t *pk, uint8_t *sk);
    static int sign(CryptoWorkspace* ws, uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk);
    static int verify(CryptoWorkspace* ws, const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);

private:
    // Dahili matematiksel fonksiyonlar (Modular architecture)
    static void poly_ntt(poly *a);
    static void poly_invntt(poly *a);
    static void polyvecl_ntt(polyvecl *v);
    static void polyvecl_invntt(polyvecl *v);
    static void polyveck_ntt(polyveck *v);
    static void polyveck_invntt(polyveck *v);
    
    // Yardımcılar
    static void challenge(poly *c, const uint8_t seed[DILITHIUM_SEEDBYTES]);
    static int unpack_pk(uint8_t rho[DILITHIUM_SEEDBYTES], polyveck *t1, const uint8_t *pk);
    static int unpack_sig(uint8_t c[DILITHIUM_SEEDBYTES], polyvecl *z, polyveck *h, const uint8_t *sig);
    static void compute_w1_row(poly *w1_row, const uint8_t rho[DILITHIUM_SEEDBYTES], uint16_t i, const polyvecl *z, const poly *cp, const poly *t1_row);
    static void calculate_mu(uint8_t mu[64], const uint8_t *pk, const uint8_t *m, size_t mlen);
    static void calculate_challenge(uint8_t c2[DILITHIUM_SEEDBYTES], const uint8_t mu[64], const polyveck *w1);
    static void polyveck_use_hint(polyveck *w1, const polyveck *v, const polyveck *h);
    static int32_t use_hint(int32_t a, uint8_t hint);
};

} // namespace DSA
} // namespace PQC

#endif
