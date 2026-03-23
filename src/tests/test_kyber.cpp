#include "test_suite.h"
#include "../include/pqc_config.h"

#ifdef ENABLE_PQC_TESTS
#include "../include/kyber_modular.h"
#include <string.h>

#ifdef ARDUINO
#include <Arduino.h>
#endif

#include "../include/workspace.h"

namespace PQC {
namespace Test {

using Memory::ScopedWorkspace;

bool KyberTester::test_kyber_kem_vectors() {
    uint8_t pk[KYBER_512_PUBLICKEYBYTES], sk[KYBER_512_SECRETKEYBYTES];
    uint8_t ct[KYBER_512_CIPHERTEXTBYTES], ss1[32], ss2[32];
    for(int i=0; i<5; i++) {
        ScopedWorkspace local_ws;
        
        KEM::Kyber512::keypair(local_ws, pk, sk);
        KEM::Kyber512::encaps(local_ws, ct, ss1, pk);
        KEM::Kyber512::decaps(local_ws, ss2, ct, sk);
        if (!TestSuite::compare_bytes(ss1, ss2, 32)) return false;
    }
    return true;
}

bool KyberTester::test_decaps_failure() {
    uint8_t pk[KYBER_512_PUBLICKEYBYTES], sk[KYBER_512_SECRETKEYBYTES];
    uint8_t ct[KYBER_512_CIPHERTEXTBYTES], ss1[32], ss2[32];
    ScopedWorkspace local_ws;
    KEM::Kyber512::keypair(local_ws, pk, sk);
    KEM::Kyber512::encaps(local_ws, ct, ss1, pk);
    ct[10] ^= 0xFF; 
    KEM::Kyber512::decaps(local_ws, ss2, ct, sk);
    return !TestSuite::compare_bytes(ss1, ss2, 32);
}

bool KyberTester::test_memory_leaks() {
#ifdef ARDUINO
    uint8_t pk[KYBER_512_PUBLICKEYBYTES], sk[KYBER_512_SECRETKEYBYTES], ct[KYBER_512_CIPHERTEXTBYTES], ss[32];
    size_t start_heap = ESP.getFreeHeap();
    for(int i=0; i<20; i++) {
        ScopedWorkspace local_ws;
        KEM::Kyber512::keypair(local_ws, pk, sk);
        KEM::Kyber512::encaps(local_ws, ct, ss, pk);
        KEM::Kyber512::decaps(local_ws, ss, ct, sk);
    }
    return (start_heap == ESP.getFreeHeap());
#else
    return true;
#endif
}

bool KyberTester::test_timing_consistency() {
#ifdef ARDUINO
    uint8_t pk[KYBER_512_PUBLICKEYBYTES], sk[KYBER_512_SECRETKEYBYTES], ct[KYBER_512_CIPHERTEXTBYTES], ss[32];
    uint32_t t[10], avg = 0;
    ScopedWorkspace local_ws;
    KEM::Kyber512::keypair(local_ws, pk, sk);
    for(int i=0; i<10; i++) {
        uint32_t t0 = micros();
        KEM::Kyber512::encaps(local_ws, ct, ss, pk);
        t[i] = micros() - t0;
        avg += t[i];
    }
    avg /= 10;
    for(int i=0; i<10; i++) if (abs((long)(t[i] - avg)) > (long)(avg / 5)) return false;
    return true;
#else
    return true;
#endif
}

} // namespace Test
} // namespace PQC
#endif
