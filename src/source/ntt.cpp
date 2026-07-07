#include "../include/ntt.h"
#include "../include/pqc_config.h"
#include <stdint.h>

// Kyber için önceden hesaplanmış zeta (roots of unity) değerleri
// Bu değerler Montgomery alanındadır (scaled by 2^16 mod 3329)
PQC_FLASH_STORAGE const int16_t zetas[128] = {
    -1044,  -758,  -359, -1517,  1493,  1422,   287,   202,
    -171,   622,  1577,   182,   962, -1202, -1474,  1468,
     573, -1325,   264,   383,  -829,  1458, -1602,  -130,
    -681,  1017,   732,   608, -1542,   411,  -205, -1571,
    1223,   652,  -552,  1015, -1293,  1491,  -282, -1544,
     516,    -8,  -320,  -666, -1618, -1162,   126,  1469,
    -853,   -90,  -271,   830,   107, -1421,  -247,  -951,
    -398,   961, -1508,  -725,   448, -1065,   677, -1275,
   -1103,   430,   555,   843, -1251,   871,  1550,   105,
     422,   587,   177,  -235,  -291,  -460,  1574,  1653,
    -246,   778,  1159,  -147,  -777,  1483,  -602,  1119,
   -1590,   644,  -872,   349,   418,   329,  -156,   -75,
     817,  1097,   603,   610,  1322, -1285, -1465,   384,
   -1215,  -136,  1218, -1335,  -874,   220, -1187, -1659,
   -1185, -1530, -1278,   794, -1510,  -854,  -870,   478,
    -108,  -308,   996,   991,   958, -1460,  1522,  1628
};

// Montgomery Reduction: a * 2^-16 mod 3329
// Bu işlem, bilgisayarın zorlandığı 'modül' (bölme) işlemini, 
// çok daha hızlı olan 'kaydırma' (shift) ve 'çarpma' işlemlerine dönüştürür.
int16_t montgomery_reduce(int32_t a) {
    int32_t t;
    int16_t u;
    u = (int16_t)(a * QINV);
    t = (int32_t)u * KYBER_Q;
    t = a - t;
    t >>= 16;
    return (int16_t)t;
}

// Barrett Reduction: a mod 3329
// Sayıyı her zaman [0, 3328] arasına hapseder.
int16_t barrett_reduce(int16_t a) {
    int32_t t;
    const int16_t v = (1 << 26) / KYBER_Q + 1;
    t = v * a;
    t >>= 26;
    t *= KYBER_Q;
    return a - (int16_t)t;
}

static int16_t fqmul(int16_t a, int16_t b) {
    return montgomery_reduce((int32_t)a * b);
}

// Forward NTT (Sayı Teorik Dönüşümü)
// Bu fonksiyon, polinom dünyasının 'Süper Gücü'dür. 
// Normalde iki polinomu çarpmak çok uzun sürerken (Lise matematiği gibi), 
// bu dönüşümle sayıları frekans alanına taşıyıp sadece karşılıklı elemanları çarparak 
// devasa hız kazanıyoruz (O(n log n)).
void ntt(int16_t r[256]) {
    unsigned int len, start, j, k;
    int16_t zeta;

    k = 1;
    for (len = 128; len >= 2; len >>= 1) {
        for (start = 0; start < 256; start = j + len) {
            zeta = zetas[k++];
            for (j = start; j < start + len; j++) {
                // Kelebek (Butterfly) operasyonu: Sayıları birbirine karıştırıp frekansa taşıyoruz.
                int16_t t = fqmul(zeta, r[j + len]);
                r[j + len] = r[j] - t;
                r[j] = r[j] + t;
            }
        }
    }
}

// Inverse NTT
// Frekans alanındaki polinomu tekrar zaman (katsayı) alanına döndürür.
void invntt(int16_t r[256]) {
    unsigned int len, start, j, k;
    int16_t zeta;

    k = 127;
    for (len = 2; len <= 128; len <<= 1) {
        for (start = 0; start < 256; start = j + len) {
            zeta = zetas[k--];
            for (j = start; j < start + len; j++) {
                int16_t t = r[j];
                r[j] = barrett_reduce(t + r[j + len]);
                r[j + len] = r[j + len] - t;
                r[j + len] = fqmul(zeta, r[j + len]);
            }
        }
    }

    // Normalizasyon: her katsayıyı 2^-16 * f mod 3329 ile çarpıyoruz
    // f = 1441 (n^-1 mod q'nun Montgomery temsilcisi)
    for (j = 0; j < 256; j++) {
        r[j] = fqmul(r[j], 1441);
    }
}

// Base multiplication in NTT domain
// x^2 - zeta için çarpım
void basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta) {
    r[0]  = fqmul(a[1], b[1]);
    r[0]  = fqmul(r[0], zeta);
    r[0] += fqmul(a[0], b[0]);
    r[1]  = fqmul(a[0], b[1]);
    r[1] += fqmul(a[1], b[0]);
}
