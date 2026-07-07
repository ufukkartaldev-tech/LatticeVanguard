#include "../include/poly.h"
#include "../include/ntt.h"
#include "../include/fips202.h"
#include <string.h>

// Centered Binomial Distribution (CBD)
// Bu fonksiyon, "gürültü" (noise) oluşturur. Kyber'ın güvenliği, Hata ile Öğrenme (Learning With Errors) 
// problemine dayanır. Bu problemde, sonucun üzerine küçük bir gürültü eklenir ki sistem çözülemez hale gelsin.
static void load32(uint32_t *r, const uint8_t x[4]) {
    *r = (uint32_t)x[0] | ((uint32_t)x[1] << 8) | ((uint32_t)x[2] << 16) | ((uint32_t)x[3] << 24);
}

static void cbd(poly *r, const uint8_t *buf, int eta) {
    uint32_t t, d;
    int a, b;
    int i, j;

    if (eta == 2) {
        // Eta = 2 için CBD (Kyber-768 ve 1024'te kullanılır)
        for (i = 0; i < 256 / 8; i++) {
            load32(&t, buf + 4 * i);
            d = t & 0x55555555;
            d += (t >> 1) & 0x55555555;
            for (j = 0; j < 8; j++) {
                a = (d >> (4 * j)) & 0x3;
                b = (d >> (4 * j + 2)) & 0x3;
                r->coeffs[8 * i + j] = a - b;
            }
        }
    } else if (eta == 3) {
        // Eta = 3 için CBD (Kyber-512'de kullanılır)
        // Burada 3 bitlik bloklar kullanılır: a = bit1+bit2+bit3, b = bit4+bit5+bit6. Sonuç = a - b.
        for (i = 0; i < 256 / 4; i++) {
            uint64_t t_64 = 0;
            for(int k=0; k<6; k++) t_64 |= ((uint64_t)buf[6*i+k] << (8*k));
            
            d = t_64 & 0x00249249;
            d += (t_64 >> 1) & 0x00249249;
            d += (t_64 >> 2) & 0x00249249;

            for (j = 0; j < 4; j++) {
                a = (d >> (6 * j)) & 0x7;
                b = (d >> (6 * j + 3)) & 0x7;
                r->coeffs[4 * i + j] = a - b;
            }
        }
    }
}

void poly_getnoise_eta1(poly *r, const uint8_t seed[32], uint8_t nonce, int k) {
    uint8_t buf[KYBER_N * 3 / 4]; // Max eta=3 için (3*256/8 = 96 byte)
    keccak_state state;
    uint8_t extseed[33];
    memcpy(extseed, seed, 32);
    extseed[32] = nonce;
    
    int eta = (k == 2) ? 3 : 2; // Kyber-512(k=2) için eta1=3, diğerleri 2.
    
    shake256_init(&state);
    shake256_absorb(&state, extseed, 33);
    shake256_squeeze(buf, 64 * eta, &state);
    cbd(r, buf, eta);
}

void poly_getnoise_eta2(poly *r, const uint8_t seed[32], uint8_t nonce) {
    uint8_t buf[KYBER_N/2]; // Eta=2 için 128 byte
    keccak_state state;
    uint8_t extseed[33];
    memcpy(extseed, seed, 32);
    extseed[32] = nonce;
    
    shake256_init(&state);
    shake256_absorb(&state, extseed, 33);
    shake256_squeeze(buf, 128, &state); // eta2 her zaman 2'dir
    cbd(r, buf, 2);
}

// Rejection Sampling: Rastgele byte dizisinden geçerli polinom katsayıları üretir.
// Kyber'da katsayılar 0-3328 arasında olmalıdır. Eğer üretilen sayı 3329'dan büyükse atılır (rejection).
void poly_uniform(poly *a, const uint8_t seed[32], uint8_t nonce) {
    unsigned int ctr = 0;
    uint16_t val0, val1;
    keccak_state state;
    uint8_t extseed[33];
    uint8_t buf[SHAKE128_RATE];

    memcpy(extseed, seed, 32);
    extseed[32] = nonce;

    shake128_init(&state);
    shake128_absorb(&state, extseed, 33);
    
    while (ctr < 256) {
        shake128_squeeze(buf, SHAKE128_RATE, &state);
        for (int i = 0; i < SHAKE128_RATE - 3 && ctr < 256; i += 3) {
            val0 = ((uint16_t)buf[i+0] | ((uint16_t)buf[i+1] << 8)) & 0xFFF;
            val1 = ((uint16_t)buf[i+1] >> 4 | ((uint16_t)buf[i+2] << 4)) & 0xFFF;

            if (val0 < KYBER_Q) a->coeffs[ctr++] = val0;
            if (ctr < 256 && val1 < KYBER_Q) a->coeffs[ctr++] = val1;
        }
    }
}

void poly_ntt(poly *r) {
    ntt(r->coeffs);
}

void poly_invntt_tomont(poly *r) {
    invntt(r->coeffs);
}

void poly_basemul_montgomery(poly *r, const poly *a, const poly *b) {
    for (int i = 0; i < 64; i++) {
        basemul(&r->coeffs[4 * i], &a->coeffs[4 * i], &b->coeffs[4 * i], zetas[64 + i]);
        basemul(&r->coeffs[4 * i + 2], &a->coeffs[4 * i + 2], &b->coeffs[4 * i + 2], -zetas[64 + i]);
    }
}

// Polinomu Montgomery alanına taşır. (Katsayıları r * 2^16 mod q ile çarpar)
void poly_tomont(poly *r) {
  for (int i = 0; i < 256; i++)
    r->coeffs[i] = montgomery_reduce((int32_t)r->coeffs[i] * 1353); // 1353 = 2^32 % 3329
}

void poly_add(poly *r, const poly *a, const poly *b) {
    for (int i = 0; i < 256; i++)
        r->coeffs[i] = a->coeffs[i] + b->coeffs[i];
}

void poly_sub(poly *r, const poly *a, const poly *b) {
    for (int i = 0; i < 256; i++)
        r->coeffs[i] = a->coeffs[i] - b->coeffs[i];
}

void poly_reduce(poly *r) {
    for (int i = 0; i < 256; i++) {
        r->coeffs[i] = barrett_reduce(r->coeffs[i]);
    }
}

// Polinomları byte dizisine çevirme (Compression/Bit packing)
// Kyber'da katsayılar 0-3329 (12 bit) arasındadır.
void poly_tobytes(uint8_t *r, const poly *a) {
    int i;
    uint16_t t0, t1;
    for (i = 0; i < 256 / 2; i++) {
        // Katsayıyı pozitif aralığa al [0, 3328]
        t0 = (a->coeffs[2 * i] % KYBER_Q + KYBER_Q) % KYBER_Q;
        t1 = (a->coeffs[2 * i + 1] % KYBER_Q + KYBER_Q) % KYBER_Q;
        r[3 * i + 0] = (uint8_t)(t0 & 0xFF);
        r[3 * i + 1] = (uint8_t)((t0 >> 8) | ((t1 & 0x0F) << 4));
        r[3 * i + 2] = (uint8_t)((t1 >> 4));
    }
}

void poly_frombytes(poly *r, const uint8_t *a) {
    int i;
    for (i = 0; i < 256 / 2; i++) {
        r->coeffs[2 * i]     = ((a[3 * i + 0] >> 0) | ((uint16_t)a[3 * i + 1] << 8)) & 0xFFF;
        r->coeffs[2 * i + 1] = ((a[3 * i + 1] >> 4) | ((uint16_t)a[3 * i + 2] << 4)) & 0xFFF;
    }
}

// 32 byte'lık mesajı polinoma (bitlere) çevirme
void poly_frommsg(poly *r, const uint8_t msg[32]) {
    int i, j;
    uint16_t mask;
    for (i = 0; i < 32; i++) {
        for (j = 0; j < 8; j++) {
            mask = -(uint16_t)((msg[i] >> j) & 1);
            r->coeffs[8 * i + j] = mask & ((KYBER_Q + 1) / 2);
        }
    }
}

void poly_tomsg(uint8_t msg[32], const poly *r) {
    int i, j;
    uint32_t t;
    for (i = 0; i < 32; i++) {
        msg[i] = 0;
        for (j = 0; j < 8; j++) {
            // Constant-Time Division: (x * 2 + 1664) / 3329
            uint32_t v = r->coeffs[8 * i + j];
            v += ((int32_t)v >> 31) & KYBER_Q; // Map to [0, Q-1]
            t = (((v << 1) + 1664) * 20159 + (1 << 25)) >> 26;
            msg[i] |= (uint8_t)((t & 1) << j);
        }
    }
}

// Sıkıştırma (Compression): Katsayıların hassasiyetini düşürerek ciphertext boyutunu azaltır.
void poly_compress(uint8_t *r, const poly *a, int du) {
    int i, j;
    uint32_t t;
    if (du == 10) {
        for (i = 0; i < 256 / 4; i++) {
            uint32_t c[4];
            for(j=0; j<4; j++) {
                t = a->coeffs[4*i+j];
                t += ((int32_t)t >> 31) & KYBER_Q;
                // Constant-time compression: (t * 1024 + 1664) / 3329
                c[j] = (((t << 10) + 1664) * 20159 + (1 << 25)) >> 26;
                c[j] &= 0x3FF;
            }
            r[5*i+0] = c[0] & 0xFF;
            r[5*i+1] = (c[0] >> 8) | ((c[1] & 0x3F) << 2);
            r[5*i+2] = (c[1] >> 6) | ((c[2] & 0x0F) << 4);
            r[5*i+3] = (c[2] >> 4) | ((c[3] & 0x03) << 6);
            r[5*i+4] = (c[3] >> 2);
        }
    } else if (du == 4) {
         for (i = 0; i < 256 / 2; i++) {
            uint8_t c[2];
            for(j=0; j<2; j++) {
                t = a->coeffs[2*i+j];
                t += ((int32_t)t >> 31) & KYBER_Q;
                // Constant-time compression: (t * 16 + 1664) / 3329
                c[j] = (((t << 4) + 1664) * 20159 + (1 << 25)) >> 26;
                c[j] &= 0xF;
            }
            r[i] = c[0] | (c[1] << 4);
         }
    }
}

void poly_decompress(poly *r, const uint8_t *a, int du) {
    int i;
    if (du == 10) {
        for (i = 0; i < 256 / 4; i++) {
            uint32_t c[4];
            c[0] = a[5*i+0] | ((uint32_t)(a[5*i+1] & 0x03) << 8);
            c[1] = (a[5*i+1] >> 2) | ((uint32_t)(a[5*i+2] & 0x0F) << 6);
            c[2] = (a[5*i+2] >> 4) | ((uint32_t)(a[5*i+3] & 0x3F) << 4);
            c[3] = (a[5*i+3] >> 6) | ((uint32_t)a[5*i+4] << 2);
            for(int j=0; j<4; j++)
                r->coeffs[4*i+j] = ((c[j] * KYBER_Q) + 512) >> 10;
        }
    } else if (du == 4) {
        for (i = 0; i < 256 / 2; i++) {
            r->coeffs[2*i+0] = (((a[i] & 0xF) * KYBER_Q) + 8) >> 4;
            r->coeffs[2*i+1] = (((a[i] >> 4) * KYBER_Q) + 8) >> 4;
        }
    }
}

// Vektör Fonksiyonları
void polyvec_ntt(polyvec *r, int k) {
    for (int i = 0; i < k; i++) poly_ntt(&r->vec[i]);
}

void polyvec_invntt_tomont(polyvec *r, int k) {
    for (int i = 0; i < k; i++) poly_invntt_tomont(&r->vec[i]);
}

void polyvec_add(polyvec *r, const polyvec *a, const polyvec *b, int k) {
    for (int i = 0; i < k; i++) poly_add(&r->vec[i], &a->vec[i], &b->vec[i]);
}

// Matris-Vektör çarpımında kullanılan akumülasyon: r = a * b
// In-place mantığıyla, geçici 'poly' buffer'ı kullanmadan doğrudan r üzerine ekleme yapar.
void polyvec_basemul_acc_montgomery(poly *r, const polyvec *a, const polyvec *b, int k) {
    int16_t t[2];
    memset(r->coeffs, 0, sizeof(r->coeffs));
    
    for (int i = 0; i < k; i++) {
        for (int j = 0; j < 64; j++) {
            basemul(t, &a->vec[i].coeffs[4 * j], &b->vec[i].coeffs[4 * j], zetas[64 + j]);
            r->coeffs[4 * j] += t[0];
            r->coeffs[4 * j + 1] += t[1];
            basemul(t, &a->vec[i].coeffs[4 * j + 2], &b->vec[i].coeffs[4 * j + 2], -zetas[64 + j]);
            r->coeffs[4 * j + 2] += t[0];
            r->coeffs[4 * j + 3] += t[1];
        }
    }
    poly_reduce(r);
}
