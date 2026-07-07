#include "test_suite.h"
#include "../include/pqc_config.h"

#ifdef ENABLE_PQC_TESTS
#include "../include/fips202.h"
#include "../include/ntt.h"
#include "../include/poly.h"
#include "../include/encryption.h"
#include <string.h>
#include <stdlib.h>

namespace PQC {
namespace Test {

bool PrimTester::test_keccak() {
    uint8_t out[32];
    uint8_t expected[32] = {
        0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66, 0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
        0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa, 0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a
    };
    sha3_256(out, (const uint8_t*)"", 0);
    return TestSuite::compare_bytes(out, expected, 32);
}

bool PrimTester::test_ntt_symmetry() {
    int16_t r[256], original[256];
    for(int i=0; i<256; i++) {
        r[i] = (i * 13) % 3329;
        original[i] = r[i];
    }
    ntt(r);
    invntt(r);
    // invntt is invntt_tomont: it returns coefficients in Montgomery domain
    // (scaled by 2^16 mod q). Convert back before comparing.
    for(int i=0; i<256; i++) {
        int16_t c = montgomery_reduce(r[i]);
        c = (c % 3329 + 3329) % 3329;
        if (c != original[i]) return false;
    }
    return true;
}

bool PrimTester::test_ntt_edge_cases() {
    int16_t r[256];
    for(int i=0; i<256; i++) r[i] = 3329;
    ntt(r);
    invntt(r);
    for(int i=0; i<256; i++) {
        int16_t c = (r[i] % 3329 + 3329) % 3329;
        if (c != 0) return false;
    }
    return true;
}

bool PrimTester::test_poly_serialization() {
    poly p, p2;
    uint8_t buf[KYBER_POLYBYTES];
    for(int i=0; i<256; i++) p.coeffs[i] = (i * 7) % 3329;
    poly_tobytes(buf, &p);
    poly_frombytes(&p2, buf);
    for(int i=0; i<256; i++) {
        if ((p.coeffs[i] % 3329) != (p2.coeffs[i] % 3329)) return false;
    }
    return true;
}

bool PrimTester::test_poly_compression_noise() {
    poly p, p2;
    uint8_t buf[320];
    for(int i=0; i<256; i++) p.coeffs[i] = (i * 123) % 3329;
    poly_compress(buf, &p, 10);
    poly_decompress(&p2, buf, 10);
    for(int i=0; i<256; i++) {
        int16_t diff = abs(p.coeffs[i] - p2.coeffs[i]);
        if(diff > 3329/2) diff = 3329 - diff;
        if (diff > 2) return false; 
    }
    return true;
}

bool PrimTester::test_chacha20() {
    uint8_t key[32] = {0}, nonce[12] = {0}, out[64], back[64];
    const char* in = "Test Message for ChaCha20";
    size_t len = strlen(in);
    Symmetric::ChaCha20::process(out, (const uint8_t*)in, len, key, nonce);
    Symmetric::ChaCha20::process(back, out, len, key, nonce);
    return TestSuite::compare_bytes((const uint8_t*)in, back, len);
}

} // namespace Test
} // namespace PQC
#endif
