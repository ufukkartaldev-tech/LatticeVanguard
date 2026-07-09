#include "test_suite.h"
#include "../include/pqc_config.h"

#ifdef ENABLE_PQC_TESTS

#include "../include/kyber_modular.h"
#include "../include/dilithium.h"
#include "../include/workspace.h"
#include "../include/csprng.h"
#include "../include/fips202.h"
#include "../include/params.h"
#include "../include/dilithium_params.h"
#include <string.h>

namespace PQC {
namespace Test {

using Memory::ScopedWorkspace;

// ---------------------------------------------------------------------------
// Known-Answer / regression tests.
//
// The existing suite only verified self-consistency (own-encaps -> own-decaps).
// A corrupted NTT zeta table therefore passed every round-trip while silently
// producing non-standard output. These tests pin the *actual bytes* produced
// from a fixed seed via a deterministic RNG, so any change to the underlying
// mathematics (NTT, Montgomery factor, noise sampler, packing) flips a digest
// and fails immediately.
//
// NOTE: these are regression vectors for THIS implementation, not the official
// NIST FIPS-203/204 vectors. The implementation uses a non-standard matrix XOF
// domain separation, so it is not byte-compatible with the NIST .rsp vectors;
// aligning it is tracked separately. The seed and message below are arbitrary
// but fixed. The RNG hook is host-only (see CSPRNG::set_deterministic).
// ---------------------------------------------------------------------------

#ifndef ARDUINO

static const uint8_t KAT_SEED[32] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
};

static bool digest_matches(const uint8_t* data, size_t len, const uint8_t expected[32]) {
    uint8_t actual[32];
    sha3_256(actual, data, len);
    return TestSuite::compare_bytes(actual, expected, 32);
}

// --- Kyber-512 ---
static const uint8_t KAT_K512_PK[32] = {
    0x21,0x86,0xf6,0xcf,0x30,0x8b,0x59,0x24,
    0x88,0x99,0xb5,0x61,0xe3,0x69,0x2a,0x36,
    0x8e,0x31,0x7e,0xe3,0x27,0xa0,0xc1,0xfa,
    0x9e,0x6e,0x0c,0x43,0x07,0x36,0x17,0x3b,
};
static const uint8_t KAT_K512_SK[32] = {
    0xb1,0xd4,0x12,0x31,0xd8,0xf5,0x03,0x1b,
    0x8e,0xdc,0xb7,0xd9,0x3c,0xad,0x86,0x1d,
    0xf1,0x12,0x63,0xda,0x88,0x93,0x16,0x27,
    0x98,0xae,0x30,0x5f,0xdb,0x0e,0xde,0x58,
};
static const uint8_t KAT_K512_CT[32] = {
    0xc9,0x9a,0xbe,0x0a,0x3b,0x8c,0x7e,0x62,
    0x6f,0x7c,0x20,0x1f,0x28,0xdc,0xb1,0x74,
    0x17,0x65,0x94,0xab,0x28,0xa7,0xf5,0x89,
    0x50,0xae,0x12,0x8c,0x13,0xd5,0x73,0xf2,
};
static const uint8_t KAT_K512_SS[32] = {
    0xec,0xd8,0x92,0xc3,0x68,0xae,0xfa,0x9f,
    0x58,0x62,0xf9,0x64,0xca,0x21,0x20,0xf8,
    0xb7,0x63,0x96,0xe7,0x75,0xdc,0x71,0xcc,
    0x26,0xf4,0x57,0x3a,0x67,0xaa,0x44,0x7a,
};

// --- Kyber-768 ---
static const uint8_t KAT_K768_PK[32] = {
    0xa7,0x92,0x39,0x40,0x46,0xcd,0x97,0x76,
    0x7b,0xfb,0x2a,0xf0,0xfa,0x85,0x15,0x79,
    0xef,0x38,0xe8,0x31,0xcd,0x41,0x1b,0xf6,
    0xbc,0x03,0xb7,0xa9,0xa6,0x41,0x67,0x09,
};
static const uint8_t KAT_K768_SK[32] = {
    0xb5,0x00,0xfe,0xb0,0x72,0xc6,0x6f,0xef,
    0x0f,0x29,0xcb,0x1c,0xda,0x8a,0xa8,0x4f,
    0x2a,0x43,0x04,0xb5,0xfe,0x13,0xb9,0x6d,
    0x1a,0xaf,0x6e,0x1b,0x24,0xd6,0x73,0x0a,
};
static const uint8_t KAT_K768_CT[32] = {
    0x62,0x1f,0x22,0x74,0xfb,0xfb,0x85,0x47,
    0x78,0xaf,0xc4,0x60,0xe8,0x4d,0x80,0xfd,
    0xf8,0x9c,0x80,0xcd,0x7e,0xc3,0x53,0x12,
    0xe9,0x23,0x05,0x82,0xf6,0x7d,0xbf,0xdf,
};
static const uint8_t KAT_K768_SS[32] = {
    0xb1,0xac,0xa9,0x8d,0xe3,0x39,0x71,0xfa,
    0x7c,0x41,0x54,0x8c,0x72,0xe8,0x8f,0xa0,
    0x33,0x73,0x35,0x54,0xad,0x92,0x34,0x0f,
    0x30,0x7b,0x8b,0x16,0x18,0xda,0x00,0x62,
};

// --- Dilithium2 (public key only; see test_dilithium2_keygen_kat) ---
// The public key is fully deterministic from the seed. The *secret* key is
// intentionally NOT pinned here: Dilithium2::keypair() reserves
// DILITHIUM2_SECRETKEYBYTES but pack_eta() advances only 96 bytes per vector,
// so the tail of the sk buffer is left uninitialized and its digest varies
// between runs. That (and a non-terminating sign()) are separate correctness
// bugs reported for a dedicated fix; this vector guards the keygen maths that
// feed the public key (matrix expansion, NTT, Montgomery, power2round, t1
// packing).
static const uint8_t KAT_D2_PK[32] = {
    0xf0,0x3a,0xc9,0x02,0x02,0xb5,0x19,0x78,
    0x10,0x62,0xa1,0x7e,0x26,0xa9,0x46,0xe8,
    0xd5,0xb8,0x13,0xff,0xcb,0xcb,0x52,0x0e,
    0xdb,0x33,0xa9,0x8c,0x57,0xa6,0x93,0x7d,
};

#endif // !ARDUINO

bool KatTester::test_kyber512_kat() {
#ifndef ARDUINO
    System::CSPRNG::set_deterministic(KAT_SEED, sizeof(KAT_SEED));
    bool ok = true;
    {
        ScopedWorkspace ws;
        uint8_t pk[KYBER_512_PUBLICKEYBYTES], sk[KYBER_512_SECRETKEYBYTES];
        uint8_t ct[KYBER_512_CIPHERTEXTBYTES], ss1[32], ss2[32];
        KEM::Kyber512::keypair(ws, pk, sk);
        KEM::Kyber512::encaps(ws, ct, ss1, pk);
        KEM::Kyber512::decaps(ws, ss2, ct, sk);

        ok = ok && TestSuite::compare_bytes(ss1, ss2, 32);          // round-trip
        ok = ok && digest_matches(pk, sizeof(pk), KAT_K512_PK);     // pinned vectors
        ok = ok && digest_matches(sk, sizeof(sk), KAT_K512_SK);
        ok = ok && digest_matches(ct, sizeof(ct), KAT_K512_CT);
        ok = ok && digest_matches(ss1, 32, KAT_K512_SS);
    }
    System::CSPRNG::set_deterministic(nullptr, 0);
    return ok;
#else
    return true; // host-only (deterministic RNG hook not compiled on ESP32)
#endif
}

bool KatTester::test_kyber768_kat() {
#ifndef ARDUINO
    System::CSPRNG::set_deterministic(KAT_SEED, sizeof(KAT_SEED));
    bool ok = true;
    {
        ScopedWorkspace ws;
        uint8_t pk[KYBER_768_PUBLICKEYBYTES], sk[KYBER_768_SECRETKEYBYTES];
        uint8_t ct[KYBER_768_CIPHERTEXTBYTES], ss1[32], ss2[32];
        KEM::Kyber768::keypair(ws, pk, sk);
        KEM::Kyber768::encaps(ws, ct, ss1, pk);
        KEM::Kyber768::decaps(ws, ss2, ct, sk);

        ok = ok && TestSuite::compare_bytes(ss1, ss2, 32);
        ok = ok && digest_matches(pk, sizeof(pk), KAT_K768_PK);
        ok = ok && digest_matches(sk, sizeof(sk), KAT_K768_SK);
        ok = ok && digest_matches(ct, sizeof(ct), KAT_K768_CT);
        ok = ok && digest_matches(ss1, 32, KAT_K768_SS);
    }
    System::CSPRNG::set_deterministic(nullptr, 0);
    return ok;
#else
    return true;
#endif
}

bool KatTester::test_dilithium2_keygen_kat() {
#ifndef ARDUINO
    System::CSPRNG::set_deterministic(KAT_SEED, sizeof(KAT_SEED));
    bool ok = true;
    {
        ScopedWorkspace ws;
        uint8_t pk[DILITHIUM2_PUBLICKEYBYTES], sk[DILITHIUM2_SECRETKEYBYTES];
        ok = ok && (DSA::Dilithium2::keypair(ws, pk, sk) == 0);
        ok = ok && digest_matches(pk, sizeof(pk), KAT_D2_PK);
    }
    System::CSPRNG::set_deterministic(nullptr, 0);
    return ok;
#else
    return true;
#endif
}

} // namespace Test
} // namespace PQC

#endif // ENABLE_PQC_TESTS
