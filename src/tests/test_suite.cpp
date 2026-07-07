#include "test_suite.h"
#include "../include/pqc_config.h"

#ifdef ENABLE_PQC_TESTS
#include <string.h>

#ifdef ARDUINO
#include <Arduino.h>
#else
#include "../include/pc_compat.h"
#endif

namespace PQC {
namespace Test {

void TestSuite::log_test(const char* name, bool result) {
#ifdef ARDUINO
    Serial.printf("[TEST] %-35s -> %s\n", name, result ? "OK" : "FAIL !!!");
#else
    printf("[TEST] %-35s -> %s\n", name, result ? "OK" : "FAIL !!!\n");
#endif
}

bool TestSuite::compare_bytes(const uint8_t* a, const uint8_t* b, size_t len) {
    return memcmp(a, b, len) == 0;
}

void TestSuite::run_all_tests() {
    Serial.println("\n--- PQC FORTRESS v5.0 TEST SUITE ---");
    
    // 1. Primitives
    log_test("Keccak KAT", PrimTester::test_keccak());
    log_test("NTT Symmetry", PrimTester::test_ntt_symmetry());
    log_test("Poly Serial", PrimTester::test_poly_serialization());
    log_test("ChaCha20 Logic", PrimTester::test_chacha20());

    // 2. Kyber
    log_test("Kyber stability", KyberTester::test_kyber_kem_vectors());
    log_test("Implicit Rejection", KyberTester::test_decaps_failure());

#ifdef ARDUINO
    // 3. System Audit
    log_test("Entropy Quality", AuditTester::test_randomness_entropy());
    log_test("Multicore Safety", AuditTester::test_multicore_safety());
    
    // 4. Forge (Dilithium)
    log_test("Sign Malleability", ForgeTester::test_dilithium_malleability());

    // 5. Chaos (Adversary)
    Serial.println("\n--- CHAOS (ADVERSARY) ATTACKS ---");
    log_test("Anti-Replay", ChaosTester::test_replay_attack());
    log_test("Buffer Flooding", ChaosTester::test_fragment_flooding());
    log_test("Panic Lock", ChaosTester::test_rng_failure_lock());
    log_test("Flash Integrity", ChaosTester::test_flash_integrity_violation());
    log_test("Power-Cycle Resilience", ChaosTester::test_power_cycle_resilience());
    log_test("Multi-Device Stress", ChaosTester::test_multi_device_stress());
#endif

    Serial.println("--- ALL TESTS COMPLETED ---\n");
}

} // namespace Test
} // namespace PQC
#endif
