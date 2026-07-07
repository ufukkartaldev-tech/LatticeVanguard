#ifndef DILITHIUM_PARAMS_H
#define DILITHIUM_PARAMS_H

#include <stdint.h>

#define DILITHIUM_N 256
#define DILITHIUM_Q 8380417
#define DILITHIUM_D 13
#define DILITHIUM_ROOT_OF_UNITY 1753

// Dilithium2 (NIST Level 2)
#define DILITHIUM2_K 4
#define DILITHIUM2_L 4
#define DILITHIUM2_ETA 2
#define DILITHIUM2_TAU 39
#define DILITHIUM2_BETA 78
#define DILITHIUM2_GAMMA1 (1 << 17)
#define DILITHIUM2_GAMMA2 ((DILITHIUM_Q - 1) / 88)
#define DILITHIUM2_OMEGA 80

#define DILITHIUM_SEEDBYTES 32
#define DILITHIUM_CRHBYTES 64
#define DILITHIUM_TRBYTES 32
#define DILITHIUM_RHO_PRIME_BYTES 64

#define DILITHIUM2_PUBLICKEYBYTES (DILITHIUM_SEEDBYTES + DILITHIUM2_K * 320)
#define DILITHIUM2_SECRETKEYBYTES (3 * DILITHIUM_SEEDBYTES + DILITHIUM_TRBYTES + DILITHIUM2_L * 128 + DILITHIUM2_K * 128 + DILITHIUM2_K * 416)
#define DILITHIUM2_SIGNBYTES (DILITHIUM_SEEDBYTES + DILITHIUM2_L * 576 + (DILITHIUM2_OMEGA + DILITHIUM2_K))

namespace PQC {
namespace DSA {

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

} // namespace DSA
} // namespace PQC

#endif
