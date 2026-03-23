#include "../include/kyber.h"
#include "../include/poly.h"
#include "../include/fips202.h"
#include "../include/security.h"
#include <string.h>

using namespace PQC::Memory;

#include "../include/csprng.h"

// Generate secure random entropy using MbedTLS HMAC_DRBG
#define GET_RANDOM(ptr, len) PQC::System::CSPRNG::randombytes((uint8_t*)(ptr), (size_t)(len))

// Matrix generation (Row-by-Row to save RAM)
static void gen_matrix_row(polyvec *a_row, const uint8_t seed[32], int row_idx, int k, int transposed) {
    for (int j = 0; j < k; j++) {
        if (transposed)
            poly_uniform(&a_row->vec[j], seed, (uint8_t)((row_idx << 4) + j));
        else
            poly_uniform(&a_row->vec[j], seed, (uint8_t)((j << 4) + row_idx));
    }
}

// IND-CPA Key Generation
static void indcpa_keypair(CryptoWorkspace* ws, uint8_t *pk, uint8_t *sk, int k) {
    uint8_t buf[64];
    uint8_t public_seed[32], noise_seed[32];
    polyvec &a_row = ws->maths.kv1; 
    polyvec &skpv = ws->maths.kv2;
    polyvec &e = ws->maths.kv3;
    polyvec &pkpv = ws->maths.kv4;
    uint8_t nonce = 0;

    memset(&skpv, 0, sizeof(skpv));
    memset(&e, 0, sizeof(e));
    memset(&pkpv, 0, sizeof(pkpv));

    GET_RANDOM(buf, 32);
    sha3_512(buf, buf, 32);
    memcpy(public_seed, buf, 32);
    memcpy(noise_seed, buf + 32, 32);

    for (int i = 0; i < k; i++)
        poly_getnoise_eta1(&skpv.vec[i], noise_seed, nonce++, k);
    for (int i = 0; i < k; i++)
        poly_getnoise_eta1(&e.vec[i], noise_seed, nonce++, k);

    polyvec_ntt(&skpv, k);
    polyvec_ntt(&e, k);

    for (int i = 0; i < k; i++) {
        gen_matrix_row(&a_row, public_seed, i, k, 0);
        polyvec_basemul_acc_montgomery(&pkpv.vec[i], &a_row, &skpv, k);
        poly_tomont(&pkpv.vec[i]);
        poly_add(&pkpv.vec[i], &pkpv.vec[i], &e.vec[i]);
        poly_reduce(&pkpv.vec[i]);
    }

    for (int i = 0; i < k; i++)
        poly_tobytes(pk + i * KYBER_POLYBYTES, &pkpv.vec[i]);
    memcpy(pk + k * KYBER_POLYBYTES, public_seed, 32);

    for (int i = 0; i < k; i++)
        poly_tobytes(sk + i * KYBER_POLYBYTES, &skpv.vec[i]);
}

// IND-CPA Encryption
static void indcpa_enc(CryptoWorkspace* ws, uint8_t *ct, const uint8_t *msg, const uint8_t *pk, const uint8_t seed[32], int k) {
    polyvec &a_row = ws->maths.kv1;
    polyvec &pkpv = ws->maths.kv2;
    polyvec &sp = ws->maths.kv3;
    polyvec &e1 = ws->maths.kv4;
    polyvec &bp = ws->maths.kv5;
    poly &v = ws->maths.kp1;
    poly &k_poly = ws->maths.kp2;
    poly &e2 = ws->maths.kp3;
    uint8_t public_seed[32];
    uint8_t nonce = 0;

    memset(&pkpv, 0, sizeof(pkpv));
    memset(&sp, 0, sizeof(sp));
    memset(&e1, 0, sizeof(e1));
    memset(&bp, 0, sizeof(bp));
    memset(&v, 0, sizeof(v));
    memset(&k_poly, 0, sizeof(k_poly));
    memset(&e2, 0, sizeof(e2));

    for (int i = 0; i < k; i++)
        poly_frombytes(&pkpv.vec[i], pk + i * KYBER_POLYBYTES);
    memcpy(public_seed, pk + k * KYBER_POLYBYTES, 32);

    for (int i = 0; i < k; i++)
        poly_getnoise_eta1(&sp.vec[i], seed, nonce++, k);
    for (int i = 0; i < k; i++)
        poly_getnoise_eta2(&e1.vec[i], seed, nonce++);
    poly_getnoise_eta2(&e2, seed, nonce++);

    polyvec_ntt(&sp, k);

    for (int i = 0; i < k; i++) {
        gen_matrix_row(&a_row, public_seed, i, k, 1); // Transposed
        polyvec_basemul_acc_montgomery(&bp.vec[i], &a_row, &sp, k);
        poly_tomont(&bp.vec[i]);
        poly_add(&bp.vec[i], &bp.vec[i], &e1.vec[i]);
        poly_reduce(&bp.vec[i]);
    }

    polyvec_basemul_acc_montgomery(&v, &pkpv, &sp, k);
    poly_tomont(&v);
    poly_add(&v, &v, &e2);
    poly_frommsg(&k_poly, msg);
    poly_add(&v, &v, &k_poly);
    poly_reduce(&v);

    for (int i = 0; i < k; i++)
        poly_compress(ct + i * 320, &bp.vec[i], 10);
    poly_compress(ct + k * 320, &v, 4);
}

// IND-CPA Decryption
static void indcpa_dec(CryptoWorkspace* ws, uint8_t *msg, const uint8_t *ct, const uint8_t *sk, int k) {
    polyvec &bp = ws->maths.kv1;
    polyvec &skpv = ws->maths.kv2;
    poly &v = ws->maths.kp1;
    poly &mp = ws->maths.kp2;

    memset(&bp, 0, sizeof(bp));
    memset(&skpv, 0, sizeof(skpv));
    memset(&v, 0, sizeof(v));
    memset(&mp, 0, sizeof(mp));

    for (int i = 0; i < k; i++)
        poly_decompress(&bp.vec[i], ct + i * 320, 10);
    poly_decompress(&v, ct + k * 320, 4);

    for (int i = 0; i < k; i++)
        poly_frombytes(&skpv.vec[i], sk + i * KYBER_POLYBYTES);

    polyvec_ntt(&bp, k);
    polyvec_basemul_acc_montgomery(&mp, &skpv, &bp, k);
    poly_invntt_tomont(&mp);
    poly_tomont(&mp); 
    poly_reduce(&mp);
    poly_sub(&mp, &v, &mp);
    poly_reduce(&mp);
    poly_tomsg(msg, &mp);
}

// CCA Safe KEM Functions
int kyber512_keypair(CryptoWorkspace* ws, uint8_t *pk, uint8_t *sk) {
    PQC::Memory::ScopedWorkspace local_ws;
    if (!ws) { if (!local_ws.ws) return -1; ws = local_ws.ws; }
    int k = 2;
    indcpa_keypair(ws, pk, sk, k);
    memcpy(sk + k * KYBER_POLYBYTES, pk, KYBER_512_PUBLICKEYBYTES);
    sha3_256(sk + KYBER_512_SECRETKEYBYTES - 2 * 32, pk, KYBER_512_PUBLICKEYBYTES);
    GET_RANDOM(sk + KYBER_512_SECRETKEYBYTES - 32, 32);
    return 0;
}

int kyber512_encaps(CryptoWorkspace* ws, uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    PQC::Memory::ScopedWorkspace local_ws;
    if (!ws) { if (!local_ws.ws) return -1; ws = local_ws.ws; }
    uint8_t buf[64], kr[64], msg[32];
    int k = 2;
    GET_RANDOM(msg, 32);
    sha3_256(msg, msg, 32);
    memcpy(buf, msg, 32);
    sha3_256(buf + 32, pk, KYBER_512_PUBLICKEYBYTES);
    sha3_512(kr, buf, 64);
    indcpa_enc(ws, ct, msg, pk, kr + 32, k);
    sha3_256(kr + 32, ct, KYBER_512_CIPHERTEXTBYTES);
    sha3_256(ss, kr, 64);
    return 0;
}

int kyber512_decaps(CryptoWorkspace* ws, uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    PQC::Memory::ScopedWorkspace local_ws;
    if (!ws) { if (!local_ws.ws) return -1; ws = local_ws.ws; }
    uint8_t buf[64], kr[64], msg[32], cmp_ct[KYBER_512_CIPHERTEXTBYTES];
    int k = 2;
    const uint8_t *pk = sk + k * KYBER_POLYBYTES;
    const uint8_t *hpk = sk + KYBER_512_SECRETKEYBYTES - 64;
    const uint8_t *z = sk + KYBER_512_SECRETKEYBYTES - 32;

    indcpa_dec(ws, msg, ct, sk, k);
    memcpy(buf, msg, 32);
    memcpy(buf + 32, hpk, 32);
    sha3_512(kr, buf, 64);
    indcpa_enc(ws, cmp_ct, msg, pk, kr + 32, k);
    
    // Constant-time check utilizing fault-injection protection
    bool fail = !Security::SecurityOfficer::secure_compare(ct, cmp_ct, KYBER_512_CIPHERTEXTBYTES);
    
    sha3_256(kr + 32, ct, KYBER_512_CIPHERTEXTBYTES);
    if (fail) {
        uint8_t reject_buf[64];
        memcpy(reject_buf, z, 32);
        memcpy(reject_buf + 32, kr + 32, 32);
        sha3_256(ss, reject_buf, 64);
    } else {
        sha3_256(ss, kr, 64);
    }
    return 0;
}

int kyber768_keypair(CryptoWorkspace* ws, uint8_t *pk, uint8_t *sk) {
    PQC::Memory::ScopedWorkspace local_ws;
    if (!ws) { if (!local_ws.ws) return -1; ws = local_ws.ws; }
    int k = 3;
    indcpa_keypair(ws, pk, sk, k);
    memcpy(sk + k * KYBER_POLYBYTES, pk, KYBER_768_PUBLICKEYBYTES);
    sha3_256(sk + KYBER_768_SECRETKEYBYTES - 2 * 32, pk, KYBER_768_PUBLICKEYBYTES);
    GET_RANDOM(sk + KYBER_768_SECRETKEYBYTES - 32, 32);
    return 0;
}

int kyber768_encaps(CryptoWorkspace* ws, uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    PQC::Memory::ScopedWorkspace local_ws;
    if (!ws) { if (!local_ws.ws) return -1; ws = local_ws.ws; }
    uint8_t buf[64], kr[64], msg[32];
    int k = 3;
    GET_RANDOM(msg, 32);
    sha3_256(msg, msg, 32);
    memcpy(buf, msg, 32);
    sha3_256(buf + 32, pk, KYBER_768_PUBLICKEYBYTES);
    sha3_512(kr, buf, 64);
    indcpa_enc(ws, ct, msg, pk, kr + 32, k);
    sha3_256(kr + 32, ct, KYBER_768_CIPHERTEXTBYTES);
    sha3_256(ss, kr, 64);
    return 0;
}

int kyber768_decaps(CryptoWorkspace* ws, uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    PQC::Memory::ScopedWorkspace local_ws;
    if (!ws) { if (!local_ws.ws) return -1; ws = local_ws.ws; }
    uint8_t buf[64], kr[64], msg[32], cmp_ct[KYBER_768_CIPHERTEXTBYTES];
    int k = 3;
    const uint8_t *pk = sk + k * KYBER_POLYBYTES;
    const uint8_t *hpk = sk + KYBER_768_SECRETKEYBYTES - 64;
    const uint8_t *z = sk + KYBER_768_SECRETKEYBYTES - 32;

    indcpa_dec(ws, msg, ct, sk, k);
    memcpy(buf, msg, 32);
    memcpy(buf + 32, hpk, 32);
    sha3_512(kr, buf, 64);
    indcpa_enc(ws, cmp_ct, msg, pk, kr + 32, k);
    
    bool fail = !Security::SecurityOfficer::secure_compare(ct, cmp_ct, KYBER_768_CIPHERTEXTBYTES);
    
    sha3_256(kr + 32, ct, KYBER_768_CIPHERTEXTBYTES);
    if (fail) {
        uint8_t reject_buf[64];
        memcpy(reject_buf, z, 32);
        memcpy(reject_buf + 32, kr + 32, 32);
        sha3_256(ss, reject_buf, 64);
    } else {
        sha3_256(ss, kr, 64);
    }
    return 0;
}
