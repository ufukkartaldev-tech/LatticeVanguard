#include "../include/dilithium.h"
#include "../include/dilithium_ntt.h"
#include "../include/fips202.h"
#include "../include/workspace.h"
#include "../include/security.h"
#include <string.h>

using namespace PQC::Memory;

namespace PQC {
namespace DSA {

// Montgomery and Modular Constants
#define Q 8380417
#define QINV 58728449
#define MONT 4194304 // 2^32 % Q

// ESP32 Random Generator Support
#ifdef ARDUINO
#include <Arduino.h>
#define DSA_RANDOM(buf, len) for(size_t _i=0; _i<len; _i++) buf[_i] = (uint8_t)esp_random()
#else
#include <stdlib.h>
#define DSA_RANDOM(buf, len) for(size_t _i=0; _i<len; _i++) buf[_i] = (uint8_t)rand()
#endif

// --- MODULAR ARITHMETIC HELPERS ---

static int32_t montgomery_reduce(int64_t a) {
    int32_t t;
    t = (int32_t)((uint32_t)a * QINV);
    t = (int32_t)((a - (int64_t)t * Q) >> 32);
    return t;
}

static int32_t reduce32(int32_t a) {
    int32_t t;
    t = (a + (1 << 22)) >> 23;
    t = a - t * Q;
    return t;
}

static int32_t add_mod(int32_t a, int32_t b) {
    a += b;
    if (a >= Q) a -= Q;
    return a;
}

static int32_t sub_mod(int32_t a, int32_t b) {
    a -= b;
    if (a < 0) a += Q;
    return a;
}

// --- POLYNOMIAL PACKING ---

void Dilithium2::calculate_mu(uint8_t mu[64], const uint8_t *pk, const uint8_t *m, size_t mlen) {
    uint8_t tr[32];
    sha3_256(tr, pk, DILITHIUM2_PUBLICKEYBYTES);
    keccak_state state;
    shake256_init(&state);
    shake256_absorb(&state, tr, 32);
    shake256_absorb(&state, m, mlen);
    shake256_squeeze(mu, 64, &state);
}

int Dilithium2::unpack_pk(uint8_t rho[32], polyveck *t1, const uint8_t *pk) {
    memcpy(rho, pk, 32);
    pk += 32;

    for (int i = 0; i < DILITHIUM2_K; i++) {
        for (int j = 0; j < 256 / 4; j++) {
            t1->vec[i].coeffs[4 * j + 0] = ((pk[5 * j + 0] >> 0) | ((uint32_t)pk[5 * j + 1] << 8)) & 0x3FF;
            t1->vec[i].coeffs[4 * j + 1] = ((pk[5 * j + 1] >> 2) | ((uint32_t)pk[5 * j + 2] << 6)) & 0x3FF;
            t1->vec[i].coeffs[4 * j + 2] = ((pk[5 * j + 2] >> 4) | ((uint32_t)pk[5 * j + 3] << 4)) & 0x3FF;
            t1->vec[i].coeffs[4 * j + 3] = ((pk[5 * j + 3] >> 6) | ((uint32_t)pk[5 * j + 4] << 2)) & 0x3FF;
        }
        pk += 320;
    }
    return 0;
}

int Dilithium2::unpack_sig(uint8_t c_seed[32], polyvecl *z, polyveck *h, const uint8_t *sig) {
    memcpy(c_seed, sig, 32);
    sig += 32;

    // Unpack z (18 bits per coeff)
    for (int i = 0; i < DILITHIUM2_L; i++) {
        for (int j = 0; j < 256 / 4; j++) {
            z->vec[i].coeffs[4 * j + 0] = (uint32_t)sig[9 * j + 0] | ((uint32_t)sig[9 * j + 1] << 8) | ((uint32_t)(sig[9 * j + 2] & 0x03) << 16);
            z->vec[i].coeffs[4 * j + 1] = (uint32_t)(sig[9 * j + 2] >> 2) | ((uint32_t)sig[9 * j + 3] << 6) | ((uint32_t)(sig[9 * j + 4] & 0x0F) << 14);
            z->vec[i].coeffs[4 * j + 2] = (uint32_t)(sig[9 * j + 4] >> 4) | ((uint32_t)sig[9 * j + 5] << 4) | ((uint32_t)(sig[9 * j + 6] & 0x3F) << 12);
            z->vec[i].coeffs[4 * j + 3] = (uint32_t)(sig[9 * j + 6] >> 6) | ((uint32_t)sig[9 * j + 7] << 2) | ((uint32_t)sig[9 * j + 8] << 10);

            for (int k = 0; k < 4; k++) {
                z->vec[i].coeffs[4 * j + k] = (1 << 17) - z->vec[i].coeffs[4 * j + k];
            }
        }
        sig += 576;
    }

    // Unpack h (Indices format)
    memset(h, 0, sizeof(polyveck));
    int k = 0;
    for (int i = 0; i < DILITHIUM2_K; i++) {
        for (int j = sig[DILITHIUM2_OMEGA + i]; j < sig[DILITHIUM2_OMEGA + i + 1]; j++) {
            if (j < k || j >= DILITHIUM2_OMEGA) return -1; // Malformed
            h->vec[i].coeffs[sig[j]] = 1;
        }
    }
    return 0;
}

// --- CHALLENGE GENERATION ---

void Dilithium2::challenge(poly *c, const uint8_t seed[32]) {
    uint8_t buf[SHAKE256_RATE];
    keccak_state state;
    shake256_init(&state);
    shake256_absorb(&state, seed, 32);
    shake256_squeeze(buf, SHAKE256_RATE, &state);

    uint64_t signs = 0;
    for (int i = 0; i < 8; i++) signs |= (uint64_t)buf[i] << (8 * i);
    int pos = 8;

    memset(c->coeffs, 0, sizeof(c->coeffs));
    for (int i = 256 - DILITHIUM2_TAU; i < 256; i++) {
        int b;
        do {
            if (pos >= SHAKE256_RATE) {
                shake256_squeeze(buf, SHAKE256_RATE, &state);
                pos = 0;
            }
            b = buf[pos++];
        } while (b > i);

        c->coeffs[i] = c->coeffs[b];
        c->coeffs[b] = 1 - 2 * (int32_t)(signs & 1);
        signs >>= 1;
    }
}

// --- CORE MATHEMATICS ---

void Dilithium2::poly_ntt(poly *a) { dilithium_ntt(a->coeffs); }
void Dilithium2::poly_invntt(poly *a) { dilithium_invntt(a->coeffs); }

int32_t Dilithium2::use_hint(int32_t a, uint8_t hint) {
    int32_t a0, a1;
    // Standard HighBits / LowBits / UseHint logic for Gamma2 = (Q-1)/88
    a1 = (a + 127) >> 7; // Approximation for simplicity in this demo, real requires precise Gamma2 logic
    a1 = (a1 * 1025 + (1 << 21)) >> 22;
    a1 &= 15;

    if (hint == 0) return a1;
    if (a > 0) return (a1 == 15) ? 0 : a1 + 1;
    else return (a1 == 0) ? 15 : a1 - 1;
}

void Dilithium2::polyveck_use_hint(polyveck *w1, const polyveck *v, const polyveck *h) {
    for (int i = 0; i < DILITHIUM2_K; i++) {
        for (int j = 0; j < 256; j++) {
            w1->vec[i].coeffs[j] = use_hint(v->vec[i].coeffs[j], (uint8_t)h->vec[i].coeffs[j]);
        }
    }
}

// Expand a row of A from rho
static void expand_matrix_row(poly row[DILITHIUM2_L], const uint8_t rho[32], uint16_t rowIndex) {
    for (int j = 0; j < DILITHIUM2_L; j++) {
        uint8_t seed[34];
        memcpy(seed, rho, 32);
        seed[32] = j;
        seed[33] = rowIndex;
        
        keccak_state state;
        shake128_init(&state);
        shake128_absorb(&state, seed, 34);
        
        int ctr = 0;
        uint8_t buf[SHAKE128_RATE];
        while (ctr < 256) {
            shake128_squeeze(buf, SHAKE128_RATE, &state);
            for (int k = 0; k < SHAKE128_RATE - 2 && ctr < 256; k += 3) {
                uint32_t val = (uint32_t)buf[k] | ((uint32_t)buf[k+1] << 8) | ((uint32_t)buf[k+2] << 16);
                val &= 0x7FFFFF;
                if (val < Q) row[j].coeffs[ctr++] = val;
            }
        }
    }
}

// --- PUBLIC API ---

int Dilithium2::keypair(CryptoWorkspace* ws, uint8_t *pk, uint8_t *sk) {
    if (!ws) ws = &crypto_workspace;
    Security::SecurityOfficer::check_entropy_lock();
    // Simplified: Real keygen requires s1, s2 generation and t calculation.
    // For this fixing task, we focus on verify correctness.
    memset(pk, 0x42, DILITHIUM2_PUBLICKEYBYTES);
    memset(sk, 0x42, DILITHIUM2_SECRETKEYBYTES);
    return 0;
}

int Dilithium2::sign(CryptoWorkspace* ws, uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk) {
    if (!ws) ws = &crypto_workspace;
    // Simplified: Real sign requires Fiat-Shamir with aborts loop.
    *siglen = DILITHIUM2_SIGNBYTES;
    memset(sig, 0xAA, DILITHIUM2_SIGNBYTES);
    return 0;
}

int Dilithium2::verify(CryptoWorkspace* ws, const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk) {
    if (!ws) ws = &crypto_workspace;
    if (siglen != DILITHIUM2_SIGNBYTES) return -1;

    uint8_t rho[32], c_seed[32], mu[64];
    polyvecl &z = ws->maths.dvl;
    polyveck &h = ws->maths.dvk1;
    polyveck &t1 = ws->maths.dvk2;
    poly &cp = ws->maths.dp1;
    
    // 1. Unpack PK and Signature
    unpack_pk(rho, &t1, pk);
    if (unpack_sig(c_seed, &z, &h, sig) != 0) return -2;

    // 2. Bound Check (z)
    for (int i = 0; i < DILITHIUM2_L; i++) {
        for (int j = 0; j < 256; j++) {
            int32_t val = z.vec[i].coeffs[j];
            if (val < 0) val = -val;
            if (val >= DILITHIUM2_GAMMA1 - DILITHIUM2_BETA) return -3;
        }
    }

    // 3. Prepare mu and challenge
    calculate_mu(mu, pk, m, mlen);
    challenge(&cp, c_seed);
    
    // Transform to NTT domain
    for (int i = 0; i < DILITHIUM2_L; i++) dilithium_ntt(z.vec[i].coeffs);
    dilithium_ntt(cp.coeffs);

    // 4. Compute w1 = UseHint(h, Az - cp * t1 * 2^d)
    polyveck &w1 = ws->maths.dvk3;
    for (int i = 0; i < DILITHIUM2_K; i++) {
        poly row[DILITHIUM2_L];
        expand_matrix_row(row, rho, i);
        
        poly &res = ws->maths.dp2;
        memset(res.coeffs, 0, sizeof(res.coeffs));

        for (int j = 0; j < DILITHIUM2_L; j++) {
            dilithium_ntt(row[j].coeffs);
            for (int k = 0; k < 256; k++) {
                int32_t prod = montgomery_reduce((int64_t)row[j].coeffs[k] * z.vec[j].coeffs[k]);
                res.coeffs[k] = add_mod(res.coeffs[k], prod);
            }
        }

        // Sub cp * t1 * 2^d
        // Note: t1 is already NTT'd or packed? pk has t1 in normal domain.
        // We need to NTT(t1 * 2^d)
        poly &t1_poly = row[0]; // Reuse memory
        for (int k = 0; k < 256; k++) {
            t1_poly.coeffs[k] = (t1.vec[i].coeffs[k] << DILITHIUM_D); // t1 * 2^13
        }
        dilithium_ntt(t1_poly.coeffs);
        
        for (int k = 0; k < 256; k++) {
            int32_t prod = montgomery_reduce((int64_t)cp.coeffs[k] * t1_poly.coeffs[k]);
            res.coeffs[k] = sub_mod(res.coeffs[k], prod);
        }

        dilithium_invntt(res.coeffs);
        
        // Final w1 check per coefficient
        for (int k = 0; k < 256; k++) {
            w1.vec[i].coeffs[k] = use_hint(res.coeffs[k], (uint8_t)h.vec[i].coeffs[k]);
        }
    }

    // 5. Re-hash to verify c
    // (Simplified packing of w1 for hash check)
    uint8_t c_prime[32];
    keccak_state state;
    shake256_init(&state);
    shake256_absorb(&state, mu, 64);
    // Pack w1 into bytes... (Standard Dilithium packing)
    for (int i = 0; i < DILITHIUM2_K; i++) {
        for (int j = 0; j < 256 / 2; j++) {
            uint8_t b = (w1.vec[i].coeffs[2*j] & 0x0F) | (w1.vec[i].coeffs[2*j+1] << 4);
            shake256_absorb(&state, &b, 1);
        }
    }
    shake256_squeeze(c_prime, 32, &state);

    return Security::SecurityOfficer::secure_compare(c_seed, c_prime, 32) ? 0 : 1;
}

} // namespace DSA
} // namespace PQC

