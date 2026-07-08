#include "../include/kyber_modular.h"
#include "../include/fips202.h"
#include "../include/ntt.h"
#include "../include/workspace.h"
#include "../include/security.h"
#include "../include/csprng.h"
#include <string.h>

using namespace PQC::Memory;

namespace PQC {
namespace KEM {

// Generate secure random entropy using MbedTLS HMAC_DRBG
#define KEM_RANDOM(ptr, len) PQC::System::CSPRNG::randombytes((uint8_t*)(ptr), (size_t)(len))

void KyberBase::gen_matrix_row(polyvec *a_row, const uint8_t seed[32], int row_idx, int k, int transposed) {
    for (int j = 0; j < k; j++) {
        if (transposed)
            poly_uniform(&a_row->vec[j], seed, (uint8_t)((row_idx << 4) + j));
        else
            poly_uniform(&a_row->vec[j], seed, (uint8_t)((j << 4) + row_idx));
    }
}

// Kyber512 Implementation
int Kyber512::keypair(CryptoWorkspace* ws, uint8_t *pk, uint8_t *sk) {
    Memory::ScopedWorkspace local_ws;
    if (!ws) { if (!local_ws.ws) return -1; ws = local_ws.ws; }
    Security::SecurityOfficer::check_entropy_lock();
    uint8_t buf[64];
    uint8_t public_seed[32], noise_seed[32];
    polyvec &a_row = ws->maths.kv1;
    polyvec &skpv = ws->maths.kv2;
    polyvec &e = ws->maths.kv3;
    polyvec &pkpv = ws->maths.kv4;
    uint8_t nonce = 0;

    memset(&skpv, 0, sizeof(skpv)); memset(&e, 0, sizeof(e)); memset(&pkpv, 0, sizeof(pkpv));

    KEM_RANDOM(buf, 32);
    sha3_512(buf, buf, 32);
    memcpy(public_seed, buf, 32);
    memcpy(noise_seed, buf + 32, 32);

    for (int i = 0; i < K; i++) poly_getnoise_eta1(&skpv.vec[i], noise_seed, nonce++, K);
    for (int i = 0; i < K; i++) poly_getnoise_eta1(&e.vec[i], noise_seed, nonce++, K);

    polyvec_ntt(&skpv, K); polyvec_ntt(&e, K);

    // Matrix multiplication (Row-by-Row)
    for (int i = 0; i < K; i++) {
        gen_matrix_row(&a_row, public_seed, i, K, 0); // i. satırı üret
        polyvec_basemul_acc_montgomery(&pkpv.vec[i], &a_row, &skpv, K);
        poly_tomont(&pkpv.vec[i]);
        poly_add(&pkpv.vec[i], &pkpv.vec[i], &e.vec[i]);
        poly_reduce(&pkpv.vec[i]);
    }

    for (int i = 0; i < K; i++) poly_tobytes(pk + i * KYBER_POLYBYTES, &pkpv.vec[i]);
    memcpy(pk + K * KYBER_POLYBYTES, public_seed, 32);
    for (int i = 0; i < K; i++) poly_tobytes(sk + i * KYBER_POLYBYTES, &skpv.vec[i]);
    memcpy(sk + K * KYBER_POLYBYTES, pk, KYBER_512_PUBLICKEYBYTES);
    sha3_256(sk + KYBER_512_SECRETKEYBYTES - 64, pk, KYBER_512_PUBLICKEYBYTES);
    KEM_RANDOM(sk + KYBER_512_SECRETKEYBYTES - 32, 32);
    return 0;
}

void Kyber512::indcpa_enc(CryptoWorkspace* ws, uint8_t *ct, const uint8_t *msg, const uint8_t *pk, const uint8_t *coins) {
    polyvec &a_row = ws->maths.kv1;
    polyvec &pkpv = ws->maths.kv2;
    polyvec &sp = ws->maths.kv3;
    polyvec &e1 = ws->maths.kv4;
    polyvec &bp = ws->maths.kv5;
    poly &v = ws->maths.kp1;
    poly &k_poly = ws->maths.kp2;
    poly &e2 = ws->maths.kp3;
    uint8_t nonce = 0;

    memset(&pkpv, 0, sizeof(pkpv)); memset(&sp, 0, sizeof(sp));
    memset(&e1, 0, sizeof(e1)); memset(&bp, 0, sizeof(bp)); memset(&v, 0, sizeof(v));
    memset(&k_poly, 0, sizeof(k_poly)); memset(&e2, 0, sizeof(e2));

    for (int i = 0; i < K; i++) poly_frombytes(&pkpv.vec[i], pk + i * KYBER_POLYBYTES);

    for (int i = 0; i < K; i++) poly_getnoise_eta1(&sp.vec[i], coins, nonce++, K);
    for (int i = 0; i < K; i++) poly_getnoise_eta2(&e1.vec[i], coins, nonce++);
    poly_getnoise_eta2(&e2, coins, nonce++);

    polyvec_ntt(&sp, K);
    
    // Matrix multiplication (Row-by-Row, Transposed)
    for (int i = 0; i < K; i++) {
        gen_matrix_row(&a_row, pk + K * KYBER_POLYBYTES, i, K, 1);
        polyvec_basemul_acc_montgomery(&bp.vec[i], &a_row, &sp, K);
        poly_invntt_tomont(&bp.vec[i]); poly_add(&bp.vec[i], &bp.vec[i], &e1.vec[i]); poly_reduce(&bp.vec[i]);
    }
    
    polyvec_basemul_acc_montgomery(&v, &pkpv, &sp, K);
    poly_invntt_tomont(&v); poly_add(&v, &v, &e2);
    poly_frommsg(&k_poly, msg); poly_add(&v, &v, &k_poly); poly_reduce(&v);

    for (int i = 0; i < K; i++) poly_compress(ct + i * 320, &bp.vec[i], 10);
    poly_compress(ct + K * 320, &v, 4);
}

int Kyber512::encaps(CryptoWorkspace* ws, uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    Memory::ScopedWorkspace local_ws;
    if (!ws) { if (!local_ws.ws) return -1; ws = local_ws.ws; }
    uint8_t buf[64], kr[64], msg[32];

    KEM_RANDOM(msg, 32); sha3_256(msg, msg, 32);
    memcpy(buf, msg, 32); sha3_256(buf + 32, pk, KYBER_512_PUBLICKEYBYTES);
    sha3_512(kr, buf, 64);

    indcpa_enc(ws, ct, msg, pk, kr + 32);

    sha3_256(kr + 32, ct, KYBER_512_CIPHERTEXTBYTES);
    sha3_256(ss, kr, 64);
    return 0;
}

int Kyber512::decaps(CryptoWorkspace* ws, uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    Memory::ScopedWorkspace local_ws;
    if (!ws) { if (!local_ws.ws) return -1; ws = local_ws.ws; }
    uint8_t buf[64], kr[64], msg[32], ct_re[KYBER_512_CIPHERTEXTBYTES];
    const uint8_t *pk = sk + KYBER_512_K * KYBER_POLYBYTES;
    const uint8_t *h_pk = sk + KYBER_512_SECRETKEYBYTES - 64;
    const uint8_t *z = sk + KYBER_512_SECRETKEYBYTES - 32;

    polyvec &bp = ws->maths.kv1;
    polyvec &skpv = ws->maths.kv2;
    poly &v = ws->maths.kp1;
    poly &mp = ws->maths.kp2;

    memset(&bp, 0, sizeof(bp)); memset(&skpv, 0, sizeof(skpv)); memset(&v, 0, sizeof(v)); memset(&mp, 0, sizeof(mp));

    // 1. CPA Decrypt
    for (int i = 0; i < K; i++) poly_decompress(&bp.vec[i], ct + i * 320, 10);
    poly_decompress(&v, ct + K * 320, 4);
    for (int i = 0; i < K; i++) poly_frombytes(&skpv.vec[i], sk + i * KYBER_POLYBYTES);

    polyvec_ntt(&bp, K);
    polyvec_basemul_acc_montgomery(&mp, &skpv, &bp, K);
    poly_invntt_tomont(&mp);
    poly_reduce(&mp);
    poly_sub(&mp, &v, &mp); poly_reduce(&mp);
    poly_tomsg(msg, &mp);

    // 2. FO-TRANSFORM: Re-encrypt and Verify
    memcpy(buf, msg, 32);
    sha3_256(buf + 32, pk, KYBER_512_PUBLICKEYBYTES);
    sha3_512(kr, buf, 64); // kr[0..31] = ss, kr[32..63] = coins

    // Re-encrypt to verify ciphertext integrity
    Kyber512::indcpa_enc(ws, ct_re, msg, pk, kr + 32);

    // 3. Secure Constant-time check
    bool fail = !Security::SecurityOfficer::secure_compare(ct, ct_re, KYBER_512_CIPHERTEXTBYTES);
    
    sha3_256(kr + 32, ct, KYBER_512_CIPHERTEXTBYTES);
    
    uint8_t mask = -(uint8_t)fail;
    for (int i = 0; i < 32; i++) {
        kr[i] = (kr[i] & ~mask) | (z[i] & mask);
    }
    
    sha3_256(ss, kr, 64);

    return 0;
}

// Kyber768 Implementation
int Kyber768::keypair(CryptoWorkspace* ws, uint8_t *pk, uint8_t *sk) {
    Memory::ScopedWorkspace local_ws;
    if (!ws) { if (!local_ws.ws) return -1; ws = local_ws.ws; }
    uint8_t buf[64];
    uint8_t public_seed[32], noise_seed[32];
    polyvec &a_row = ws->maths.kv1;
    polyvec &skpv = ws->maths.kv2;
    polyvec &e = ws->maths.kv3;
    polyvec &pkpv = ws->maths.kv4;
    uint8_t nonce = 0;

    memset(&skpv, 0, sizeof(skpv)); memset(&e, 0, sizeof(e)); memset(&pkpv, 0, sizeof(pkpv));

    KEM_RANDOM(buf, 32);
    sha3_512(buf, buf, 32);
    memcpy(public_seed, buf, 32);
    memcpy(noise_seed, buf + 32, 32);

    for (int i = 0; i < K; i++) poly_getnoise_eta1(&skpv.vec[i], noise_seed, nonce++, KYBER_768_ETAl);
    for (int i = 0; i < K; i++) poly_getnoise_eta1(&e.vec[i], noise_seed, nonce++, KYBER_768_ETAl);

    polyvec_ntt(&skpv, K); polyvec_ntt(&e, K);

    for (int i = 0; i < K; i++) {
        gen_matrix_row(&a_row, public_seed, i, K, 0); 
        polyvec_basemul_acc_montgomery(&pkpv.vec[i], &a_row, &skpv, K);
        poly_tomont(&pkpv.vec[i]);
        poly_add(&pkpv.vec[i], &pkpv.vec[i], &e.vec[i]);
        poly_reduce(&pkpv.vec[i]);
    }

    for (int i = 0; i < K; i++) poly_tobytes(pk + i * KYBER_POLYBYTES, &pkpv.vec[i]);
    memcpy(pk + K * KYBER_POLYBYTES, public_seed, 32);
    for (int i = 0; i < K; i++) poly_tobytes(sk + i * KYBER_POLYBYTES, &skpv.vec[i]);
    memcpy(sk + K * KYBER_POLYBYTES, pk, KYBER_768_PUBLICKEYBYTES);
    sha3_256(sk + KYBER_768_SECRETKEYBYTES - 64, pk, KYBER_768_PUBLICKEYBYTES);
    KEM_RANDOM(sk + KYBER_768_SECRETKEYBYTES - 32, 32);
    return 0;
}

void Kyber768::indcpa_enc(CryptoWorkspace* ws, uint8_t *ct, const uint8_t *msg, const uint8_t *pk, const uint8_t *coins) {
    polyvec &a_row = ws->maths.kv1;
    polyvec &pkpv = ws->maths.kv2;
    polyvec &sp = ws->maths.kv3;
    polyvec &e1 = ws->maths.kv4;
    polyvec &bp = ws->maths.kv5;
    poly &v = ws->maths.kp1;
    poly &k_poly = ws->maths.kp2;
    poly &e2 = ws->maths.kp3;
    uint8_t nonce = 0;

    memset(&pkpv, 0, sizeof(pkpv)); memset(&sp, 0, sizeof(sp));
    memset(&e1, 0, sizeof(e1)); memset(&bp, 0, sizeof(bp)); memset(&v, 0, sizeof(v));
    memset(&k_poly, 0, sizeof(k_poly)); memset(&e2, 0, sizeof(e2));

    for (int i = 0; i < K; i++) poly_frombytes(&pkpv.vec[i], pk + i * KYBER_POLYBYTES);

    for (int i = 0; i < K; i++) poly_getnoise_eta1(&sp.vec[i], coins, nonce++, KYBER_768_ETAl);
    for (int i = 0; i < K; i++) poly_getnoise_eta2(&e1.vec[i], coins, nonce++);
    poly_getnoise_eta2(&e2, coins, nonce++);

    polyvec_ntt(&sp, K);
    
    for (int i = 0; i < K; i++) {
        gen_matrix_row(&a_row, pk + K * KYBER_POLYBYTES, i, K, 1);
        polyvec_basemul_acc_montgomery(&bp.vec[i], &a_row, &sp, K);
        poly_invntt_tomont(&bp.vec[i]); poly_add(&bp.vec[i], &bp.vec[i], &e1.vec[i]); poly_reduce(&bp.vec[i]);
    }
    
    polyvec_basemul_acc_montgomery(&v, &pkpv, &sp, K);
    poly_invntt_tomont(&v); poly_add(&v, &v, &e2);
    poly_frommsg(&k_poly, msg); poly_add(&v, &v, &k_poly); poly_reduce(&v);

    for (int i = 0; i < K; i++) poly_compress(ct + i * 320, &bp.vec[i], 10);
    poly_compress(ct + K * 320, &v, 4);
}

int Kyber768::encaps(CryptoWorkspace* ws, uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    Memory::ScopedWorkspace local_ws;
    if (!ws) { if (!local_ws.ws) return -1; ws = local_ws.ws; }
    uint8_t buf[64], kr[64], msg[32];

    KEM_RANDOM(msg, 32); sha3_256(msg, msg, 32);
    memcpy(buf, msg, 32); sha3_256(buf + 32, pk, KYBER_768_PUBLICKEYBYTES);
    sha3_512(kr, buf, 64);

    indcpa_enc(ws, ct, msg, pk, kr + 32);

    sha3_256(kr + 32, ct, KYBER_768_CIPHERTEXTBYTES);
    sha3_256(ss, kr, 64);
    return 0;
}

int Kyber768::decaps(CryptoWorkspace* ws, uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    Memory::ScopedWorkspace local_ws;
    if (!ws) { if (!local_ws.ws) return -1; ws = local_ws.ws; }
    uint8_t buf[64], kr[64], msg[32], ct_re[KYBER_768_CIPHERTEXTBYTES];
    const uint8_t *pk = sk + KYBER_768_K * KYBER_POLYBYTES;
    const uint8_t *h_pk = sk + KYBER_768_SECRETKEYBYTES - 64;
    const uint8_t *z = sk + KYBER_768_SECRETKEYBYTES - 32;

    polyvec &bp = ws->maths.kv1;
    polyvec &skpv = ws->maths.kv2;
    poly &v = ws->maths.kp1;
    poly &mp = ws->maths.kp2;

    memset(&bp, 0, sizeof(bp)); memset(&skpv, 0, sizeof(skpv)); memset(&v, 0, sizeof(v)); memset(&mp, 0, sizeof(mp));

    // 1. CPA Decrypt
    for (int i = 0; i < K; i++) poly_decompress(&bp.vec[i], ct + i * 320, 10);
    poly_decompress(&v, ct + K * 320, 4);
    for (int i = 0; i < K; i++) poly_frombytes(&skpv.vec[i], sk + i * KYBER_POLYBYTES);

    polyvec_ntt(&bp, K);
    polyvec_basemul_acc_montgomery(&mp, &skpv, &bp, K);
    poly_invntt_tomont(&mp);
    poly_reduce(&mp);
    poly_sub(&mp, &v, &mp); poly_reduce(&mp);
    poly_tomsg(msg, &mp);

    // 2. FO-TRANSFORM: Re-encrypt and Verify
    memcpy(buf, msg, 32);
    sha3_256(buf + 32, pk, KYBER_768_PUBLICKEYBYTES);
    sha3_512(kr, buf, 64);

    Kyber768::indcpa_enc(ws, ct_re, msg, pk, kr + 32);

    bool fail = !Security::SecurityOfficer::secure_compare(ct, ct_re, KYBER_768_CIPHERTEXTBYTES);
    
    sha3_256(kr + 32, ct, KYBER_768_CIPHERTEXTBYTES);
    
    uint8_t mask = -(uint8_t)fail;
    for (int i = 0; i < 32; i++) {
        kr[i] = (kr[i] & ~mask) | (z[i] & mask);
    }
    
    sha3_256(ss, kr, 64);
    return 0;
}

} // namespace KEM
} // namespace PQC
