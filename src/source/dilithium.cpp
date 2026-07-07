#include "../include/dilithium.h"
#include "../include/dilithium_ntt.h"
#include "../include/fips202.h"
#include "../include/workspace.h"
#include "../include/security.h"
#include "../include/csprng.h"
#include <string.h>

using namespace PQC::Memory;

namespace PQC {
namespace DSA {

// --- FIPS 204 CONSTANTS ---
#define Q 8380417
#define QINV 58728449
#define GAMMA1 (1 << 17)
#define GAMMA2 ((Q-1)/88)
#define ETA 2
#define TAU 39
#define BETA 78
#define OMEGA 80

#define SECURE_WIPE(ptr, size) do { \
    volatile uint8_t *_p = (volatile uint8_t *)(ptr); \
    for (size_t _w = 0; _w < (size); _w++) _p[_w] = 0; \
} while (0)

// Generate secure random entropy using MbedTLS HMAC_DRBG
#define DSA_RANDOM(buf, len) PQC::System::CSPRNG::randombytes((uint8_t*)(buf), (size_t)(len))

// --- ARITHMETIC UTILITIES ---

static int32_t montgomery_reduce(int64_t a) {
    int32_t t = (int32_t)((uint32_t)a * QINV);
    t = (int32_t)((a - (int64_t)t * Q) >> 32);
    return t;
}

static int32_t caddq(int32_t a) { a += (a >> 31) & Q; return a; }
static int32_t add_mod(int32_t a, int32_t b) { return caddq(a + b - Q); }
static int32_t sub_mod(int32_t a, int32_t b) { return caddq(a - b); }

static void power2round(int32_t a, int32_t *a0, int32_t *a1) {
    int32_t t1 = (a + (1 << (DILITHIUM_D - 1)) - 1) >> DILITHIUM_D;
    int32_t t0 = a - (t1 << DILITHIUM_D);
    *a1 = t1; *a0 = t0;
}

static int32_t decompose(int32_t a, int32_t *a0) {
    int32_t a1 = (a + 127) >> 7;
    a1 = (a1 * 1025 + (1 << 21)) >> 22;
    a1 &= 15;
    *a0 = a - a1 * 2 * GAMMA2;
    *a0 -= (((GAMMA2 - 1) - *a0) >> 31) & Q;
    return a1;
}

static int32_t make_hint(int32_t a, int32_t b) {
    (void)b;
    // Constant-time / Branchless check for: if (a <= GAMMA2 && a > -GAMMA2) return 0; else return 1;
    // Converts to: a + GAMMA2 - 1 >= 0 AND GAMMA2 - a >= 0
    uint32_t u1 = (uint32_t)(a + GAMMA2 - 1);
    uint32_t u2 = (uint32_t)(GAMMA2 - a);
    return ((u1 >> 31) | (u2 >> 31));
}

int32_t Dilithium2::use_hint(int32_t a, uint8_t hint) {
    int32_t a0, a1;
    a1 = decompose(a, &a0);
    if (hint == 0) return a1;
    if (a0 > 0) return (a1 == 15) ? 0 : a1 + 1;
    return (a1 == 0) ? 15 : a1 - 1;
}

// --- PACKING ROUTINES ---

static void unpack_eta(poly *p, const uint8_t *r) {
    for (int i = 0; i < 256 / 8; i++) {
        p->coeffs[8 * i + 0] = (r[3 * i + 0] >> 0) & 7;
        p->coeffs[8 * i + 1] = (r[3 * i + 0] >> 3) & 7;
        p->coeffs[8 * i + 2] = ((r[3 * i + 0] >> 6) | (r[3 * i + 1] << 2)) & 7;
        p->coeffs[8 * i + 3] = (r[3 * i + 1] >> 1) & 7;
        p->coeffs[8 * i + 4] = (r[3 * i + 1] >> 4) & 7;
        p->coeffs[8 * i + 5] = ((r[3 * i + 1] >> 7) | (r[3 * i + 2] << 1)) & 7;
        p->coeffs[8 * i + 6] = (r[3 * i + 2] >> 2) & 7;
        p->coeffs[8 * i + 7] = (r[3 * i + 2] >> 5) & 7;
        for (int k = 0; k < 8; k++) p->coeffs[8 * i + k] = ETA - p->coeffs[8 * i + k];
    }
}

static void unpack_t0(polyveck *t0, const uint8_t *r) {
    for (int i = 0; i < DILITHIUM2_K; i++) {
        for (int j = 0; j < 256 / 8; j++) {
            const uint8_t *p = r + 416 * i + 13 * j;
            t0->vec[i].coeffs[8 * j + 0] = (p[0] | (p[1] << 8)) & 0x1FFF;
            t0->vec[i].coeffs[8 * j + 1] = ((p[1] >> 5) | (p[2] << 3) | (p[3] << 11)) & 0x1FFF;
            t0->vec[i].coeffs[8 * j + 2] = ((p[3] >> 2) | (p[4] << 6)) & 0x1FFF;
            t0->vec[i].coeffs[8 * j + 3] = ((p[4] >> 7) | (p[5] << 1) | (p[6] << 9)) & 0x1FFF;
            t0->vec[i].coeffs[8 * j + 4] = ((p[6] >> 4) | (p[7] << 4) | (p[8] << 12)) & 0x1FFF;
            t0->vec[i].coeffs[8 * j + 5] = ((p[8] >> 1) | (p[9] << 7)) & 0x1FFF;
            t0->vec[i].coeffs[8 * j + 6] = ((p[9] >> 6) | (p[10] << 2) | (p[11] << 10)) & 0x1FFF;
            t0->vec[i].coeffs[8 * j + 7] = ((p[11] >> 3) | (p[12] << 5)) & 0x1FFF;
            for (int k = 0; k < 8; k++) t0->vec[i].coeffs[8 * j + k] = 4096 - t0->vec[i].coeffs[8 * j + k];
        }
    }
}

static void pack_eta(uint8_t *r, const poly *p) {
    for (int i = 0; i < 256 / 8; i++) {
        uint8_t t[8]; for (int k = 0; k < 8; k++) t[k] = (uint8_t)(ETA - p->coeffs[8 * i + k]);
        r[3 * i + 0] = t[0] | (t[1] << 3) | (t[2] << 6);
        r[3 * i + 1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
        r[3 * i + 2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
    }
}

static void pack_t1(uint8_t *r, const polyveck *t1) {
    for (int i = 0; i < DILITHIUM2_K; i++) {
        for (int j = 0; j < 256 / 4; j++) {
            r[320 * i + 5 * j + 0] = (uint8_t)(t1->vec[i].coeffs[4 * j + 0] >> 0);
            r[320 * i + 5 * j + 1] = (uint8_t)(t1->vec[i].coeffs[4 * j + 0] >> 8) | (uint8_t)(t1->vec[i].coeffs[4 * j + 1] << 2);
            r[320 * i + 5 * j + 2] = (uint8_t)(t1->vec[i].coeffs[4 * j + 1] >> 6) | (uint8_t)(t1->vec[i].coeffs[4 * j + 2] << 4);
            r[320 * i + 5 * j + 3] = (uint8_t)(t1->vec[i].coeffs[4 * j + 2] >> 4) | (uint8_t)(t1->vec[i].coeffs[4 * j + 3] << 6);
            r[320 * i + 5 * j + 4] = (uint8_t)(t1->vec[i].coeffs[4 * j + 3] >> 2);
        }
    }
}

static void pack_t0(uint8_t *r, const polyveck *t0) {
    for (int i = 0; i < DILITHIUM2_K; i++) {
        for (int j = 0; j < 256 / 8; j++) {
            uint32_t t[8]; for (int k = 0; k < 8; k++) t[k] = (uint32_t)(4096 - t0->vec[i].coeffs[8 * j + k]);
            uint8_t *p = r + 416 * i + 13 * j;
            p[0] = (uint8_t)t[0]; p[1] = (t[0] >> 8) | (t[1] << 5); p[2] = (uint8_t)(t[1] >> 3);
            p[3] = (t[1] >> 11) | (t[2] << 2); p[4] = (t[2] >> 6) | (t[3] << 7); p[5] = (uint8_t)(t[3] >> 1);
            p[6] = (t[3] >> 9) | (t[4] << 4); p[7] = (uint8_t)(t[4] >> 4); p[8] = (t[4] >> 12) | (t[5] << 1);
            p[9] = (t[5] >> 7) | (t[6] << 6); p[10] = (uint8_t)(t[6] >> 2); p[11] = (t[6] >> 10) | (t[7] << 3);
            p[12] = (uint8_t)(t[7] >> 5);
        }
    }
}

static void pack_z(uint8_t *r, const polyvecl *z) {
    for (int i = 0; i < DILITHIUM2_L; i++) {
        for (int j = 0; j < 256 / 4; j++) {
            uint32_t t[4]; for (int k = 0; k < 4; k++) t[k] = (uint32_t)(GAMMA1 - z->vec[i].coeffs[4 * j + k]);
            uint8_t *p = r + 576 * i + 9 * j;
            p[0] = (uint8_t)t[0]; p[1] = (uint8_t)(t[0] >> 8); p[2] = (t[0] >> 16) | (t[1] << 2);
            p[3] = (uint8_t)(t[1] >> 6); p[4] = (t[1] >> 14) | (t[2] << 4); p[5] = (uint8_t)(t[2] >> 4);
            p[6] = (t[2] >> 12) | (t[3] << 6); p[7] = (uint8_t)(t[3] >> 2); p[8] = (uint8_t)(t[3] >> 10);
        }
    }
}

// --- MATRIX & MASK EXPANSION ---

static void expand_A(poly *row, const uint8_t rho[32], uint16_t row_idx) {
    for (int j = 0; j < DILITHIUM2_L; j++) {
        uint8_t seed[34]; memcpy(seed, rho, 32); seed[32] = (uint8_t)j; seed[33] = (uint8_t)row_idx;
        keccak_state st; shake128_init(&st); shake128_absorb(&st, seed, 34);
        int ctr = 0; uint8_t b[SHAKE128_RATE];
        while (ctr < 256) {
            shake128_squeeze(b, SHAKE128_RATE, &st);
            for (int k = 0; k < SHAKE128_RATE - 2 && ctr < 256; k += 3) {
                uint32_t val = (uint32_t)b[k] | ((uint32_t)b[k + 1] << 8) | ((uint32_t)b[k + 2] << 16);
                val &= 0x7FFFFF; if (val < Q) row[j].coeffs[ctr++] = val;
            }
        }
    }
}

static void expand_mask(poly *p, const uint8_t seed[64], uint16_t nonce) {
    uint8_t s[66]; memcpy(s, seed, 64); s[64] = (uint8_t)nonce; s[65] = (uint8_t)(nonce >> 8);
    keccak_state st; shake256_init(&st); shake256_absorb(&st, s, 66);
    int ctr = 0; uint8_t b[SHAKE256_RATE];
    while (ctr < 256) {
        shake256_squeeze(b, SHAKE256_RATE, &st);
        for (int k = 0; k < SHAKE256_RATE - 2 && ctr < 256; k += 3) {
            uint32_t val = (uint32_t)b[k] | ((uint32_t)b[k + 1] << 8) | ((uint32_t)b[k + 2] << 16);
            val &= 0x3FFFF; if (val < 2 * GAMMA1 - 1) p->coeffs[ctr++] = (int32_t)(GAMMA1 - 1) - (int32_t)val;
        }
    }
}

// --- PUBLIC PQC METHODS ---

int Dilithium2::keypair(CryptoWorkspace* ws, uint8_t *pk, uint8_t *sk) {
    Memory::ScopedWorkspace local_ws;
    if (!ws) { if (!local_ws.ws) return -1; ws = local_ws.ws; }
    Security::SecurityOfficer::check_entropy_lock();
    uint8_t entropy[32]; DSA_RANDOM(entropy, 32);
    uint8_t rho[32], rhoprime[64], key[32];
    keccak_state st; shake256_init(&st); shake256_absorb(&st, entropy, 32);
    shake256_squeeze(rho, 32, &st); shake256_squeeze(rhoprime, 64, &st); shake256_squeeze(key, 32, &st);

    polyvecl &s1 = ws->maths.dvl; polyveck &s2 = ws->maths.dvk1;
    for (int i = 0; i < DILITHIUM2_L + DILITHIUM2_K; i++) {
        uint8_t s[66]; memcpy(s, rhoprime, 64); s[64] = i; s[65] = 0;
        shake256_init(&st); shake256_absorb(&st, s, 66);
        poly *p = (i < DILITHIUM2_L) ? &s1.vec[i] : &s2.vec[i - DILITHIUM2_L];
        int ctr = 0; uint8_t b[SHAKE256_RATE];
        while (ctr < 256) {
            shake256_squeeze(b, SHAKE256_RATE, &st);
            for (int k = 0; k < SHAKE256_RATE && ctr < 256; k++) {
                uint8_t t = b[k] & 0x0F; if (t <= 2 * ETA) p->coeffs[ctr++] = ETA - t;
            }
        }
    }

    polyveck &t1 = ws->maths.dvk2, &t0 = ws->maths.dvk3;
    for (int i = 0; i < DILITHIUM2_K; i++) {
        poly row[DILITHIUM2_L]; expand_A(row, rho, i);
        memset(t1.vec[i].coeffs, 0, sizeof(poly));
        for (int j = 0; j < DILITHIUM2_L; j++) {
            dilithium_ntt(row[j].coeffs); poly s1_ntt = s1.vec[j]; dilithium_ntt(s1_ntt.coeffs);
            for (int k = 0; k < 256; k++) {
                int32_t prod = montgomery_reduce((int64_t)row[j].coeffs[k] * s1_ntt.coeffs[k]);
                t1.vec[i].coeffs[k] = add_mod(t1.vec[i].coeffs[k], prod);
            }
        }
        dilithium_invntt(t1.vec[i].coeffs);
        for (int k = 0; k < 256; k++) {
            int32_t val = add_mod(t1.vec[i].coeffs[k], s2.vec[i].coeffs[k]);
            power2round(val, &t0.vec[i].coeffs[k], &t1.vec[i].coeffs[k]);
        }
    }

    memcpy(pk, rho, 32); pack_t1(pk + 32, &t1);
    uint8_t tr[32]; sha3_256(tr, pk, DILITHIUM2_PUBLICKEYBYTES);
    memcpy(sk, rho, 32); memcpy(sk + 32, key, 32); memcpy(sk + 64, tr, 32);
    uint8_t *skp = sk + 96;
    for (int i = 0; i < DILITHIUM2_L; i++) { pack_eta(skp, &s1.vec[i]); skp += 96; }
    for (int i = 0; i < DILITHIUM2_K; i++) { pack_eta(skp, &s2.vec[i]); skp += 96; }
    pack_t0(skp, &t0);
    SECURE_WIPE(entropy, 32); SECURE_WIPE(rhoprime, 64); SECURE_WIPE(key, 32); return 0;
}

int Dilithium2::sign(CryptoWorkspace* ws, uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk) {
    Memory::ScopedWorkspace local_ws;
    if (!ws) { if (!local_ws.ws) return -1; ws = local_ws.ws; }
    uint8_t rho[32], key[32], tr[32], rhoprime[64], mu[64];
    memcpy(rho, sk, 32); memcpy(key, sk + 32, 32); memcpy(tr, sk + 64, 32);
    keccak_state st; shake256_init(&st); shake256_absorb(&st, tr, 32); shake256_absorb(&st, m, mlen); shake256_squeeze(mu, 64, &st);
    shake256_init(&st); shake256_absorb(&st, key, 32); shake256_absorb(&st, mu, 64); shake256_squeeze(rhoprime, 64, &st);

    // --- Stack Overflow Fix: Tüm büyük vektörler workspace'te ---
    // Eski hali: polyvecl s1(4KB), polyveck s2(4KB), t0(4KB) + döngüde y(4KB), w0(4KB) = ~20KB stack
    // Yeni hali: Hepsi CryptoWorkspace struct içinde, stack ~0.5KB
    polyvecl &s1 = ws->maths.dvl2;   // Persistent: gizli anahtar bileşeni
    polyveck &s2 = ws->maths.dvk3;   // Persistent: gizli anahtar bileşeni
    polyveck &t0 = ws->maths.dvk4;   // Persistent: gizli anahtar bileşeni

    const uint8_t *skp = sk + 96;
    for (int i = 0; i < DILITHIUM2_L; i++) { unpack_eta(&s1.vec[i], skp); skp += 96; }
    for (int i = 0; i < DILITHIUM2_K; i++) { unpack_eta(&s2.vec[i], skp); skp += 96; }
    unpack_t0(&t0, skp);

    uint16_t nonce = 0;
    while (true) {
        // y workspace'te yaşar, sonra in-place z'ye dönüşür
        polyvecl &y = ws->maths.dvl;
        for (int i = 0; i < DILITHIUM2_L; i++) expand_mask(&y.vec[i], rhoprime, nonce++);

        // w = A * y (A satır satır üretilip atılır, row[] hâlâ stack'te ama döngü scope'unda)
        polyveck &w = ws->maths.dvk1;
        for (int i = 0; i < DILITHIUM2_K; i++) {
            memset(w.vec[i].coeffs, 0, sizeof(poly));
            for (int j = 0; j < DILITHIUM2_L; j++) {
                // A[i][j]'yi tek tek üret → dp1, y[j]'nin NTT kopyası → dp2
                poly &a_ij = ws->maths.dp1;
                {
                    uint8_t seed[34]; memcpy(seed, rho, 32);
                    seed[32] = (uint8_t)j; seed[33] = (uint8_t)i;
                    keccak_state ast; shake128_init(&ast); shake128_absorb(&ast, seed, 34);
                    int ctr = 0; uint8_t ab[SHAKE128_RATE];
                    while (ctr < 256) {
                        shake128_squeeze(ab, SHAKE128_RATE, &ast);
                        for (int k2 = 0; k2 < SHAKE128_RATE - 2 && ctr < 256; k2 += 3) {
                            uint32_t val = (uint32_t)ab[k2] | ((uint32_t)ab[k2+1] << 8) | ((uint32_t)ab[k2+2] << 16);
                            val &= 0x7FFFFF; if (val < Q) a_ij.coeffs[ctr++] = val;
                        }
                    }
                }
                dilithium_ntt(a_ij.coeffs);
                poly &y_ntt = ws->maths.dp2;
                y_ntt = y.vec[j]; dilithium_ntt(y_ntt.coeffs);
                for (int k = 0; k < 256; k++) {
                    int32_t prod = montgomery_reduce((int64_t)a_ij.coeffs[k] * y_ntt.coeffs[k]);
                    w.vec[i].coeffs[k] = add_mod(w.vec[i].coeffs[k], prod);
                }
            }
            dilithium_invntt(w.vec[i].coeffs);
        }

        // w1 = HighBits(w), w0 tamamen atılıyor (zaten sonra yeniden hesaplanıyor)
        polyveck &w1 = ws->maths.dvk2;
        for (int i = 0; i < DILITHIUM2_K; i++)
            for (int j = 0; j < 256; j++) {
                int32_t w0_discard;
                w1.vec[i].coeffs[j] = decompose(w.vec[i].coeffs[j], &w0_discard);
            }

        shake256_init(&st); shake256_absorb(&st, mu, 64);
        for (int i = 0; i < DILITHIUM2_K; i++) for (int j = 0; j < 128; j++) {
            uint8_t b = (uint8_t)w1.vec[i].coeffs[2*j] | (uint8_t)(w1.vec[i].coeffs[2*j+1] << 4);
            shake256_absorb(&st, &b, 1);
        }
        uint8_t c_seed[32]; shake256_squeeze(c_seed, 32, &st);
        poly cp; challenge(&cp, c_seed);
        poly cp_ntt = cp; dilithium_ntt(cp_ntt.coeffs);

        // z = c*s1 + y (y in-place olarak z'ye dönüşür, dp1 scratch olarak kullanılır)
        bool rejected = false;
        for (int i = 0; i < DILITHIUM2_L; i++) {
            poly &tmp = ws->maths.dp1;
            tmp = s1.vec[i]; dilithium_ntt(tmp.coeffs);
            for (int k = 0; k < 256; k++)
                tmp.coeffs[k] = montgomery_reduce((int64_t)cp_ntt.coeffs[k] * tmp.coeffs[k]);
            dilithium_invntt(tmp.coeffs);
            for (int k = 0; k < 256; k++) {
                y.vec[i].coeffs[k] = add_mod(y.vec[i].coeffs[k], tmp.coeffs[k]);
                int32_t val = y.vec[i].coeffs[k]; if (val > (int32_t)Q / 2) val -= Q; if (val < 0) val = -val;
                if (val >= GAMMA1 - BETA) { rejected = true; break; }
            }
            if (rejected) break;
        }
        if (rejected) continue;
        // y artık z'yi içeriyor
        polyvecl &z = y;

        // r0 sınır kontrolü (s2 check)
        for (int i = 0; i < DILITHIUM2_K; i++) {
            poly &tmp = ws->maths.dp1;
            tmp = s2.vec[i]; dilithium_ntt(tmp.coeffs);
            for (int k = 0; k < 256; k++)
                tmp.coeffs[k] = montgomery_reduce((int64_t)cp_ntt.coeffs[k] * tmp.coeffs[k]);
            dilithium_invntt(tmp.coeffs);
            for (int k = 0; k < 256; k++) {
                int32_t r0; decompose(sub_mod(w.vec[i].coeffs[k], tmp.coeffs[k]), &r0);
                int32_t val = r0; if (val > (int32_t)Q / 2) val -= Q; if (val < 0) val = -val;
                if (val >= GAMMA2 - BETA) { rejected = true; break; }
            }
            if (rejected) break;
        }
        if (rejected) continue;

        // Hint generation (omega check) — dp1 ve dp2 scratch olarak kullanılır
        uint8_t h_bytes[OMEGA + DILITHIUM2_K]; memset(h_bytes, 0, sizeof(h_bytes));
        int hints = 0;
        for (int i = 0; i < DILITHIUM2_K; i++) {
            // ct0 = c * t0[i]
            poly &ct0 = ws->maths.dp1;
            ct0 = t0.vec[i]; dilithium_ntt(ct0.coeffs);
            for (int k = 0; k < 256; k++)
                ct0.coeffs[k] = montgomery_reduce((int64_t)cp_ntt.coeffs[k] * ct0.coeffs[k]);
            dilithium_invntt(ct0.coeffs);
            // cs2 = c * s2[i]
            poly &cs2 = ws->maths.dp2;
            cs2 = s2.vec[i]; dilithium_ntt(cs2.coeffs);
            for (int k = 0; k < 256; k++)
                cs2.coeffs[k] = montgomery_reduce((int64_t)cp_ntt.coeffs[k] * cs2.coeffs[k]);
            dilithium_invntt(cs2.coeffs);
            for (int k = 0; k < 256; k++) {
                int32_t rem0; decompose(sub_mod(sub_mod(w.vec[i].coeffs[k], cs2.coeffs[k]), ct0.coeffs[k]), &rem0);
                if (make_hint(rem0, ct0.coeffs[k])) { if (hints >= OMEGA) { rejected = true; break; } h_bytes[hints++] = (uint8_t)k; }
            }
            h_bytes[OMEGA + i] = (uint8_t)hints; if (rejected) break;
        }
        if (rejected) continue;

        memcpy(sig, c_seed, 32); pack_z(sig + 32, &z); memcpy(sig + 32 + 576 * DILITHIUM2_L, h_bytes, OMEGA + DILITHIUM2_K);
        *siglen = DILITHIUM2_SIGNBYTES; break;
    }
    return 0;
}

int Dilithium2::verify(CryptoWorkspace* ws, const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk) {
    Memory::ScopedWorkspace local_ws;
    if (!ws) { if (!local_ws.ws) return -1; ws = local_ws.ws; }
    if (siglen != DILITHIUM2_SIGNBYTES) return -1;
    uint8_t rho[32], c_seed[32], mu[64]; polyvecl &z = ws->maths.dvl; polyveck &h = ws->maths.dvk1, &t1 = ws->maths.dvk2;
    unpack_pk(rho, &t1, pk); unpack_sig(c_seed, &z, &h, sig);
    calculate_mu(mu, pk, m, mlen); poly cp; challenge(&cp, c_seed); poly cp_ntt = cp; dilithium_ntt(cp_ntt.coeffs);
    for (int i = 0; i < DILITHIUM2_L; i++) dilithium_ntt(z.vec[i].coeffs);

    polyveck &w1 = ws->maths.dvk3;
    for (int i = 0; i < DILITHIUM2_K; i++) {
        poly row[DILITHIUM2_L]; expand_A(row, rho, i); poly &res = ws->maths.dp2; memset(res.coeffs, 0, sizeof(res.coeffs));
        for (int j = 0; j < DILITHIUM2_L; j++) {
            dilithium_ntt(row[j].coeffs);
            for (int k = 0; k < 256; k++) {
                int32_t prod = montgomery_reduce((int64_t)row[j].coeffs[k] * z.vec[j].coeffs[k]);
                res.coeffs[k] = add_mod(res.coeffs[k], prod);
            }
        }
        poly t1p = row[0]; for (int k = 0; k < 256; k++) t1p.coeffs[k] = (t1.vec[i].coeffs[k] << DILITHIUM_D);
        dilithium_ntt(t1p.coeffs);
        for (int k = 0; k < 256; k++) {
            int32_t prod = montgomery_reduce((int64_t)cp_ntt.coeffs[k] * t1p.coeffs[k]);
            res.coeffs[k] = sub_mod(res.coeffs[k], prod);
        }
        dilithium_invntt(res.coeffs);
        for (int k = 0; k < 256; k++) w1.vec[i].coeffs[k] = use_hint(res.coeffs[k], (uint8_t)h.vec[i].coeffs[k]);
    }
    uint8_t c_prime[32]; keccak_state st; shake256_init(&st); shake256_absorb(&st, mu, 64);
    for (int i = 0; i < DILITHIUM2_K; i++) for (int j = 0; j < 128; j++) {
        uint8_t b = (uint8_t)w1.vec[i].coeffs[2*j] | (uint8_t)(w1.vec[i].coeffs[2*j+1] << 4);
        shake256_absorb(&st, &b, 1);
    }
    shake256_squeeze(c_prime, 32, &st);
    return Security::SecurityOfficer::secure_compare(c_seed, c_prime, 32) ? 0 : 1;
}

void Dilithium2::challenge(poly *c, const uint8_t seed[32]) {
    uint8_t b[SHAKE256_RATE]; keccak_state st; shake256_init(&st); shake256_absorb(&st, seed, 32); shake256_squeeze(b, SHAKE256_RATE, &st);
    uint64_t s = 0; for (int i = 0; i < 8; i++) s |= (uint64_t)b[i] << (8 * i);
    int pos = 8; memset(c->coeffs, 0, sizeof(c->coeffs));
    for (int i = 256 - TAU; i < 256; i++) {
        int r; do { if (pos >= SHAKE256_RATE) { shake256_squeeze(b, SHAKE256_RATE, &st); pos = 0; } r = b[pos++]; } while (r > i);
        c->coeffs[i] = c->coeffs[r]; c->coeffs[r] = 1 - 2 * (int32_t)(s & 1); s >>= 1;
    }
}

int Dilithium2::unpack_pk(uint8_t rho[32], polyveck *t1, const uint8_t *pk) {
    memcpy(rho, pk, 32); pk += 32;
    for (int i = 0; i < DILITHIUM2_K; i++) {
        for (int j = 0; j < 64; j++) {
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
    memcpy(c_seed, sig, 32); sig += 32;
    for (int i = 0; i < DILITHIUM2_L; i++) {
        for (int j = 0; j < 64; j++) {
            uint32_t t[4];
            t[0] = (uint32_t)sig[9 * j + 0] | ((uint32_t)sig[9 * j + 1] << 8) | ((uint32_t)(sig[9 * j + 2] & 0x03) << 16);
            t[1] = (uint32_t)(sig[9 * j + 2] >> 2) | ((uint32_t)sig[9 * j + 3] << 6) | ((uint32_t)(sig[9 * j + 4] & 0x0F) << 14);
            t[2] = (uint32_t)(sig[9 * j + 4] >> 4) | ((uint32_t)sig[9 * j + 5] << 4) | ((uint32_t)(sig[9 * j + 6] & 0x3F) << 12);
            t[3] = (uint32_t)(sig[9 * j + 6] >> 6) | ((uint32_t)sig[9 * j + 7] << 2) | ((uint32_t)sig[9 * j + 8] << 10);
            for (int k = 0; k < 4; k++) z->vec[i].coeffs[4 * j + k] = (int32_t)GAMMA1 - (int32_t)t[k];
        }
        sig += 576;
    }
    memset(h, 0, sizeof(polyveck)); size_t k_sig = 0;
    for (size_t i = 0; i < DILITHIUM2_K; i++) {
        size_t limit = sig[OMEGA + i];
        // Sıkı Boundary Check (Sınır Kontrolü)
        if (limit < k_sig || limit > OMEGA) {
            return -1;
        }
        for (size_t j = k_sig; j < limit; j++) {
            // Indexlerin sıralı (öngörülebilir) olduğunun tespiti ve sınır kontrolü
            if (j > k_sig && sig[j] <= sig[j - 1]) return -1;
            h->vec[i].coeffs[sig[j]] = 1;
        }
        k_sig = limit;
    }
    
    // Geriye kalan alanların sahte veri taşımadığından emin olma
    for (size_t j = k_sig; j < OMEGA; j++) {
        if (sig[j] != 0) return -1;
    }
    return 0;
}

void Dilithium2::calculate_mu(uint8_t mu[64], const uint8_t *pk, const uint8_t *m, size_t mlen) {
    uint8_t tr[32]; sha3_256(tr, pk, DILITHIUM2_PUBLICKEYBYTES);
    keccak_state st; shake256_init(&st); shake256_absorb(&st, tr, 32); shake256_absorb(&st, m, mlen); shake256_squeeze(mu, 64, &st);
}

} // namespace DSA
} // namespace PQC
